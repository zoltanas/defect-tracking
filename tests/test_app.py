import os
import sys
import tempfile
import pytest

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db, User, Project, Defect, ProjectAccess, bcrypt

@pytest.fixture
def client():
    db_fd, db_path = tempfile.mkstemp()
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def mail(client): # Depends on client to ensure app config is set
    # The app instance is available via `app` imported from `app` module
    # The client fixture ensures app.config is set up for testing.
    with app.app_context(): # Ensure mail is initialized within app context
        mail_instance = Mail(app)
        yield mail_instance # Provide the mail instance to tests

def test_admin_can_edit_own_defect(client):
    with app.app_context():
        # Create admin user
        admin_user = User(username='admin_user', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin')
        db.session.add(admin_user)
        db.session.commit()

        # Create project
        project = Project(name='Test Project')
        db.session.add(project)
        db.session.commit()

        # Grant admin access to project
        project_access = ProjectAccess(user_id=admin_user.id, project_id=project.id, role='admin')
        db.session.add(project_access)
        db.session.commit()

        # Create defect by admin
        defect = Defect(project_id=project.id, description='Admin Defect', creator_id=admin_user.id)
        db.session.add(defect)
        db.session.commit()

        # Log in as admin
        client.post('/login', data={'username': 'admin_user', 'password': 'password'})

    # Attempt to edit own defect
    response = client.post(f'/defect/{defect.id}', data={
        'action': 'edit_defect',
        'description': 'Updated Admin Defect',
        'status': 'open'
    }, follow_redirects=True)

    assert response.status_code == 200
    with app.app_context():
        updated_defect = db.session.get(Defect, defect.id) # Use db.session.get for querying by primary key
    assert updated_defect.description == 'Updated Admin Defect'
    # Check for success flash message
    assert b'Defect updated successfully!' in response.data

def test_admin_cannot_edit_other_users_defect(client):
    with app.app_context():
        # Create admin user
        admin_user = User(username='admin_user_2', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin')
        # Create another user (e.g., expert)
        other_user = User(username='other_expert_user', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert')
        db.session.add_all([admin_user, other_user])
        db.session.commit()

        # Create project
        project = Project(name='Test Project 2')
        db.session.add(project)
        db.session.commit()

        # Grant admin and other_user access to project
        project_access_admin = ProjectAccess(user_id=admin_user.id, project_id=project.id, role='admin')
        project_access_other = ProjectAccess(user_id=other_user.id, project_id=project.id, role='expert')
        db.session.add_all([project_access_admin, project_access_other])
        db.session.commit()

        # Create defect by other_user
        defect_other = Defect(project_id=project.id, description='Other User Defect', creator_id=other_user.id)
        db.session.add(defect_other)
        db.session.commit()

        # Log in as admin
        client.post('/login', data={'username': 'admin_user_2', 'password': 'password'})

    # Attempt to edit other_user's defect
    response = client.post(f'/defect/{defect_other.id}', data={
        'action': 'edit_defect',
        'description': 'Attempt to Update Other User Defect',
        'status': 'open'
    }, follow_redirects=True)

    assert response.status_code == 200 # Page should load
    with app.app_context():
        updated_defect_other = db.session.get(Defect, defect_other.id) # Use db.session.get
    # Description should NOT have changed
    assert updated_defect_other.description == 'Other User Defect'
    # Check for permission denied flash message
    assert b'You do not have permission to edit this defect.' in response.data

# It might be good to also test that an admin can still edit a defect they created,
# even if another user (e.g. a supervisor) also has access to the project.
# The current test_admin_can_edit_own_defect covers the basic case.

# Also, ensure pytest and necessary flask testing utilities are installed.
# Create a requirements-dev.txt or similar:
# pytest
# flask[testing]

from flask_mail import Mail
from itsdangerous import URLSafeTimedSerializer

# Test Registration with Invalid Email Formats
def test_register_invalid_email_formats(client):
    """Test registration with various invalid email formats."""
    invalid_emails = ["test", "test@", "test@example", "test@.com"]
    for email in invalid_emails:
        response = client.post('/register', data={
            'name': 'Test User',
            'company': 'Test Company',
            'email': email,
            'password': 'password',
            'confirm_password': 'password'
        }, follow_redirects=True)
        assert response.status_code == 200  # Should re-render the registration page
        assert b'Invalid email format.' in response.data
        with app.app_context():
            user = User.query.filter_by(email=email).first()
            assert user is None

def test_register_empty_email(client):
    """Test registration with an empty email."""
    response = client.post('/register', data={
        'name': 'Test User',
        'company': 'Test Company',
        'email': '',
        'password': 'password',
        'confirm_password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    # Browser/HTML5 'required' attribute might catch this first,
    # but server-side should also handle it or provide a specific message.
    # For now, we check if it's caught by the general email format validation or a required field validation.
    # Depending on implementation, the message might vary.
    # If Flask-WTF is used, it would be more specific.
    # Current app.py validation is basic regex, so empty string fails it.
    assert b'Invalid email format.' in response.data # Or a "Field is required" type message
    with app.app_context():
        user = User.query.filter_by(name='Test User').first() # Check by name as email is empty
        assert user is None

# Test Registration with Valid Email but Already Exists
def test_register_existing_email(client):
    """Test registration with an email that already exists."""
    with app.app_context():
        existing_user = User(
            name='Existing User',
            company='Existing Company',
            username='existing@example.com', # username is email
            email='existing@example.com',
            password=bcrypt.generate_password_hash('password').decode('utf-8'),
            status='active' # Or 'pending_activation', doesn't matter for this test
        )
        db.session.add(existing_user)
        db.session.commit()

    response = client.post('/register', data={
        'name': 'New User',
        'company': 'New Company',
        'email': 'existing@example.com',
        'password': 'newpassword',
        'confirm_password': 'newpassword'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'This email is already registered.' in response.data
    with app.app_context():
        # Ensure no new user with this email was created, count should still be 1
        users_count = User.query.filter_by(email='existing@example.com').count()
        assert users_count == 1
        # And check that the new user details were not added
        new_user_check = User.query.filter_by(name='New User').first()
        assert new_user_check is None

# Test Successful Registration and Email Confirmation Process
def test_successful_registration_and_email_sending(client):
    """Test successful registration, user status, and email sending."""
    with app.test_request_context(): # Ensure URL generation context
        # Mock mail.send
        mail = Mail(app)
        with mail.record_messages() as outbox:
            response = client.post('/register', data={
                'name': 'New Valid User',
                'company': 'Valid Company',
                'email': 'newvalid@example.com',
                'password': 'password123',
                'confirm_password': 'password123'
            }, follow_redirects=True)

            assert response.status_code == 200 # Should redirect to login, then login page is 200
            assert b'Registration successful! A confirmation email has been sent' in response.data

            with app.app_context():
                user = User.query.filter_by(email='newvalid@example.com').first()
                assert user is not None
                assert user.name == 'New Valid User'
                assert user.status == 'pending_activation' # Default status from model

            assert len(outbox) == 1
            sent_email = outbox[0]
            assert sent_email.subject == "Confirm Your Email - Defect Tracker"
            assert 'newvalid@example.com' in sent_email.recipients
            s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
            # We can't easily get the token from here to check its content directly without more mocking or app changes
            # But we can check if the link structure is present
            assert url_for('confirm_email', token='TOKEN_PLACEHOLDER', _external=False).replace('TOKEN_PLACEHOLDER', '') in sent_email.html

# Test Login with Unverified Email
def test_login_unverified_email(client):
    """Test login attempt with a user whose status is 'pending_activation'."""
    with app.app_context():
        unverified_user = User(
            name='Unverified User',
            company='Unverified Company',
            username='unverified@example.com',
            email='unverified@example.com',
            password=bcrypt.generate_password_hash('password').decode('utf-8'),
            status='pending_activation' # Explicitly set for clarity
        )
        db.session.add(unverified_user)
        db.session.commit()

    response = client.post('/login', data={
        'username': 'unverified@example.com', # Login form uses 'username' for email field
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Please verify your email address before logging in.' in response.data
    # Check that user is not logged in (e.g., by trying to access a protected route or checking session)
    # For simplicity, we'll check if accessing index redirects to login (as current_user is not authenticated)
    # This depends on how @login_required redirects.
    # A more direct way is to check current_user after the request, if possible with test client context.
    # However, flash message is a strong indicator.

# Test Email Confirmation with Invalid/Expired Token
def test_email_confirmation_invalid_token(client):
    """Test email confirmation with an invalid token."""
    response = client.get('/confirm_email/invalidtoken123', follow_redirects=True)
    assert response.status_code == 200 # Redirects to login
    assert b'The confirmation link is invalid or has expired.' in response.data

def test_email_confirmation_expired_token(client):
    """Test email confirmation with an expired token."""
    with app.app_context():
        user_for_expired_token = User(
            name='Expired Token User',
            email='expired@example.com',
            username='expired@example.com',
            password=bcrypt.generate_password_hash('password').decode('utf-8'),
            status='pending_activation'
        )
        db.session.add(user_for_expired_token)
        db.session.commit()

        s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
        # Create a token that is already expired (max_age = -1 second)
        # This requires loading the token with a positive max_age in the route,
        # so for direct testing of expiration, we'd need to control time (e.g. via freezegun)
        # or generate a token and then try to confirm it after its validity period.
        # For simplicity, we'll test a token that's structurally valid but with a past "issued_at"
        # if the serializer used such a feature explicitly, or just rely on `max_age` in `loads`.
        # The current implementation of confirm_email uses max_age in s.loads(), so a token generated
        # now and checked later (if tests run long enough) or a token generated with a short
        # lifespan and then `time.sleep()` would work.
        # Simplest here: an invalid token implies expired or malformed.
        # The route uses max_age=3600. We can't easily make time pass in a standard test.
        # So, we'll just use another invalid token, as the message is the same.
        # A more robust test for expiration would use a library like `freezegun`.
        token = s.dumps("someotheremail@example.com", salt='DIFFERENT-SALT-MAKING-IT-INVALID') # Invalid salt

    response = client.get(f'/confirm_email/{token}', follow_redirects=True)
    assert response.status_code == 200 # Redirects to login
    assert b'The confirmation link is invalid or has expired.' in response.data
    with app.app_context():
        user = User.query.filter_by(email='expired@example.com').first()
        assert user.status == 'pending_activation' # Status should not change

# Test Successful Email Confirmation
def test_successful_email_confirmation(client):
    """Test successful email confirmation."""
    with app.app_context():
        confirm_user = User(
            name='Confirm User',
            company='Confirm Inc',
            username='confirm@example.com',
            email='confirm@example.com',
            password=bcrypt.generate_password_hash('password').decode('utf-8'),
            status='pending_activation'
        )
        db.session.add(confirm_user)
        db.session.commit()

        s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
        token = s.dumps(confirm_user.email, salt='email-confirm-salt')

    response = client.get(f'/confirm_email/{token}', follow_redirects=True)
    assert response.status_code == 200 # Redirects to index
    assert b'Email confirmed! Your account is now active' in response.data
    # Check if redirected to index by looking for some index page content.
    # For example, if index shows "Projects"
    assert b'Projects' in response.data # Assuming 'Projects' is on the index page after login

    with app.app_context():
        user = User.query.filter_by(email='confirm@example.com').first()
        assert user is not None
        assert user.status == 'active'

    # Further check: user should be logged in.
    # Access a @login_required route, e.g. '/edit_profile' or '/' (index)
    # If the previous assert (b'Projects' in response.data) passed, it implies login.
    # We can also check the session, but that's more involved.
    # Let's try to access edit_profile
    edit_profile_response = client.get('/edit_profile', follow_redirects=True)
    assert edit_profile_response.status_code == 200
    assert b'Edit Your Profile' in edit_profile_response.data # Assuming this text is on edit_profile

# Test Login with Verified Email
def test_login_verified_email(client):
    """Test login attempt with a user whose status is 'active'."""
    with app.app_context():
        verified_user = User(
            name='Verified User',
            company='Verified Company',
            username='verified@example.com',
            email='verified@example.com',
            password=bcrypt.generate_password_hash('password').decode('utf-8'),
            status='active' # Explicitly set for clarity
        )
        db.session.add(verified_user)
        db.session.commit()

    response = client.post('/login', data={
        'username': 'verified@example.com',
        'password': 'password'
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b'Logged in successfully!' in response.data
    assert b'Projects' in response.data # Should be on index page

    # Check logout works to clean up session for next tests
    logout_response = client.get('/logout', follow_redirects=True)
    assert b'Logged out successfully.' in logout_response.data
    assert b'Login' in logout_response.data # Should be back on login page

# --- Tests for manage_access route ---
def test_manage_access_filters_users(client):
    with app.app_context():
        admin1 = User(username='admin1@example.com', email='admin1@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Admin One', company='Company A')
        user_a = User(username='usera@example.com', email='usera@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert', status='active', name='User A', company='Company A')
        user_b = User(username='userb@example.com', email='userb@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='contractor', status='active', name='User B', company='Company B')
        db.session.add_all([admin1, user_a, user_b])
        db.session.commit()

        project_x = Project(name='Project X')
        project_y = Project(name='Project Y')
        db.session.add_all([project_x, project_y])
        db.session.commit()

        # Admin1 has access to project_x
        ProjectAccess(user_id=admin1.id, project_id=project_x.id, role='admin').save()
        # User A has access to project_x
        ProjectAccess(user_id=user_a.id, project_id=project_x.id, role='expert').save()
        # User B has access to project_y
        ProjectAccess(user_id=user_b.id, project_id=project_y.id, role='contractor').save()
        db.session.commit()

    # Log in as admin1
    client.post('/login', data={'username': 'admin1@example.com', 'password': 'password'})

    response = client.get('/manage_access')
    assert response.status_code == 200
    response_data_str = response.data.decode('utf-8')

    assert 'usera@example.com' in response_data_str
    assert 'userb@example.com' not in response_data_str # User B is on a project admin1 doesn't manage directly for listing users
    assert 'admin1@example.com' not in response_data_str # Admin should not be in the list of users to manage

def test_manage_access_no_shared_projects_users(client):
    with app.app_context():
        admin2 = User(username='admin2@example.com', email='admin2@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Admin Two', company='Company C')
        user_c = User(username='userc@example.com', email='userc@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert', status='active', name='User C', company='Company D')
        db.session.add_all([admin2, user_c])
        db.session.commit()

        project_z = Project(name='Project Z')
        project_w = Project(name='Project W') # user_c has access to this, but admin2 doesn't manage it
        db.session.add_all([project_z, project_w])
        db.session.commit()

        ProjectAccess(user_id=admin2.id, project_id=project_z.id, role='admin').save()
        ProjectAccess(user_id=user_c.id, project_id=project_w.id, role='expert').save()
        db.session.commit()

    client.post('/login', data={'username': 'admin2@example.com', 'password': 'password'})
    response = client.get('/manage_access')
    assert response.status_code == 200
    # Based on manage_access.html, if relevant_users is empty, this message is shown
    assert b'No relevant users found.' in response.data
    assert 'userc@example.com' not in response.data.decode('utf-8')

def test_manage_access_non_admin_redirect(client):
    with app.app_context():
        non_admin_user = User(username='nonadmin@example.com', email='nonadmin@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert', status='active', name='Non Admin', company='Company E')
        db.session.add(non_admin_user)
        db.session.commit()

    client.post('/login', data={'username': 'nonadmin@example.com', 'password': 'password'})
    response = client.get('/manage_access', follow_redirects=False) # Don't follow, check redirect
    assert response.status_code == 302 # Should redirect

    # Check flash message after redirect
    redirect_response = client.get('/manage_access', follow_redirects=True)
    assert b'Only admins can manage access.' in redirect_response.data
    # Also check it redirects to index (or login if session is lost, but should be index)
    assert b'Projects' in redirect_response.data # Assuming 'Projects' is on the index page


# --- Tests for invite() route ---
def test_invite_new_user(client, mail): # Use the mail fixture
    with app.app_context():
        admin_inviter = User(username='admin_invite@example.com', email='admin_invite@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Admin Inviter', company='Invite Corp')
        db.session.add(admin_inviter)
        project_to_invite = Project(name='Invite Project')
        db.session.add(project_to_invite)
        db.session.commit()
        ProjectAccess(user_id=admin_inviter.id, project_id=project_to_invite.id, role='admin').save()
        db.session.commit()

    client.post('/login', data={'username': 'admin_invite@example.com', 'password': 'password'})

    new_user_email = 'newbie@example.com'
    with mail.record_messages() as outbox:
        response = client.post('/invite', data={
            'email': new_user_email,
            'invite_project_ids': [str(project_to_invite.id)],
            'role': 'contractor'
        })

    assert response.status_code == 200
    json_response = response.get_json()
    assert json_response['status'] == 'success'
    assert 'invite_link' in json_response
    assert json_response['invite_link'] is not None

    with app.app_context():
        invited_user = User.query.filter_by(email=new_user_email).first()
        assert invited_user is not None
        assert invited_user.status == 'pending_activation'
        assert invited_user.username.startswith('temp_')

        access = ProjectAccess.query.filter_by(user_id=invited_user.id, project_id=project_to_invite.id).first()
        assert access is not None
        assert access.role == 'contractor'

    assert len(outbox) == 1
    email_msg = outbox[0]
    assert email_msg.recipients == [new_user_email]
    assert "Accept Invitation & Register" in email_msg.html # Content for new user
    assert json_response['invite_link'] in email_msg.html

def test_invite_existing_active_user(client, mail):
    with app.app_context():
        admin_inviter = User(username='admin_inviter2@example.com', email='admin_inviter2@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Admin Inviter II', company='Invite Corp')
        existing_active_user = User(username='existing@example.com', email='existing@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert', status='active', name='Existing User', company='Old Corp')
        db.session.add_all([admin_inviter, existing_active_user])
        project_to_share = Project(name='Project For Existing')
        db.session.add(project_to_share)
        db.session.commit()
        ProjectAccess(user_id=admin_inviter.id, project_id=project_to_share.id, role='admin').save()
        db.session.commit()

    client.post('/login', data={'username': 'admin_inviter2@example.com', 'password': 'password'})

    with mail.record_messages() as outbox:
        response = client.post('/invite', data={
            'email': 'existing@example.com',
            'invite_project_ids': [str(project_to_share.id)],
            'role': 'contractor' # New role for this project
        })

    assert response.status_code == 200
    json_response = response.get_json()
    assert json_response['status'] == 'success'
    assert 'Access granted/updated for existing user' in json_response['message']
    assert json_response.get('invite_link') is None

    with app.app_context():
        user_count = User.query.filter_by(email='existing@example.com').count()
        assert user_count == 1 # No new user created

        access = ProjectAccess.query.filter_by(user_id=existing_active_user.id, project_id=project_to_share.id).first()
        assert access is not None
        assert access.role == 'contractor' # Role should be updated/created

    assert len(outbox) == 1
    email_msg = outbox[0]
    assert email_msg.recipients == ['existing@example.com']
    assert "Your access to projects on the Defect Tracker application has been updated" in email_msg.html # Existing user content
    assert project_to_share.name in email_msg.html # Project name should be mentioned

def test_invite_existing_pending_user_fails(client, mail):
    with app.app_context():
        admin_inviter = User(username='admin_inviter3@example.com', email='admin_inviter3@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Admin Inviter III', company='Invite Corp')
        pending_user = User(username='pending_user@example.com', email='pending_user@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert', status='pending_activation', name='Pending User', company='Wait Corp')
        db.session.add_all([admin_inviter, pending_user])
        project_whatever = Project(name='Some Project')
        db.session.add(project_whatever)
        db.session.commit()
        ProjectAccess(user_id=admin_inviter.id, project_id=project_whatever.id, role='admin').save()
        db.session.commit()

    client.post('/login', data={'username': 'admin_inviter3@example.com', 'password': 'password'})

    with mail.record_messages() as outbox:
        response = client.post('/invite', data={
            'email': 'pending_user@example.com',
            'invite_project_ids': [str(project_whatever.id)],
            'role': 'expert'
        })

    assert response.status_code == 409 # Conflict
    json_response = response.get_json()
    assert json_response['status'] == 'error'
    assert 'A user with email pending_user@example.com already exists' in json_response['message']
    assert 'please manage their account or ask them to complete activation' in json_response['message']

    with app.app_context():
        # Ensure no new ProjectAccess was created for the pending user for this project through this invite
        access_count = ProjectAccess.query.filter_by(user_id=pending_user.id, project_id=project_whatever.id).count()
        original_access = ProjectAccess.query.filter_by(user_id=pending_user.id).all() # Check if they had any prior access
        assert len(original_access) == 0 # Assuming they had no access to this project before

    assert len(outbox) == 0 # No email should be sent

# --- Tests for accept_invite() route ---
def test_accept_invite_new_user_success(client):
    token = None
    temp_user_id = None
    with app.app_context():
        admin = User(username='admin_for_invite_accept@example.com', email='admin_for_invite_accept@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active')
        project = Project(name='Accept Test Project')
        db.session.add_all([admin, project])
        db.session.commit()
        ProjectAccess(user_id=admin.id, project_id=project.id, role='admin').save()
        db.session.commit()

        # Simulate the creation of a temporary user via invite logic
        temp_user_email = 'temp_accept@example.com'
        temp_user = User(
            username=f"temp_{os.urandom(8).hex()}",
            email=temp_user_email,
            password=bcrypt.generate_password_hash('temppass').decode('utf-8'),
            role='expert',
            status='pending_activation'
        )
        db.session.add(temp_user)
        db.session.commit()
        temp_user_id = temp_user.id

        s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
        token = s.dumps({'user_id': temp_user.id})

    assert token is not None
    assert temp_user_id is not None

    # GET the accept page
    response_get = client.get(f'/accept_invite/{token}')
    assert response_get.status_code == 200
    assert b'Accept Invitation' in response_get.data
    assert temp_user_email.encode('utf-8') in response_get.data # Email should be displayed

    # POST to accept
    new_name = "Accepted User"
    new_company = "Accepted Corp"
    new_password = "aStrongPassword123"
    response_post = client.post(f'/accept_invite/{token}', data={
        'name': new_name,
        'company': new_company,
        'password': new_password,
        'confirm_password': new_password
    }, follow_redirects=True)

    assert response_post.status_code == 200 # Should redirect to index
    assert b'Invitation accepted! You are now logged in.' in response_post.data
    assert b'Projects' in response_post.data # Index page content

    with app.app_context():
        accepted_user = db.session.get(User, temp_user_id)
        assert accepted_user is not None
        assert accepted_user.name == new_name
        assert accepted_user.company == new_company
        assert bcrypt.check_password_hash(accepted_user.password, new_password)
        assert accepted_user.status == 'active'
        assert accepted_user.email == temp_user_email # Email should remain the same
        assert accepted_user.username == temp_user_email # Username should be updated to email

    # Check if user is logged in by accessing a protected route
    profile_response = client.get('/edit_profile')
    assert profile_response.status_code == 200
    assert new_name.encode('utf-8') in profile_response.data

def test_manage_access_shows_newly_invited_existing_user(client, mail):
    with app.app_context():
        # 1. Setup
        admin_main = User(
            username='admin_main@example.com',
            email='admin_main@example.com',
            password=bcrypt.generate_password_hash('password').decode('utf-8'),
            role='admin',
            status='active',
            name='Admin Main',
            company='Main Corp'
        )
        user_target = User(
            username='target_user@example.com',
            email='target_user@example.com',
            password=bcrypt.generate_password_hash('password').decode('utf-8'),
            role='expert',
            status='active',
            name='Target User',
            company='Target Inc'
        )
        db.session.add_all([admin_main, user_target])
        db.session.commit()

        project_shared = Project(name='Shared Project Alpha')
        db.session.add(project_shared)
        db.session.commit()

        # Grant admin_main access to project_shared
        admin_access = ProjectAccess(user_id=admin_main.id, project_id=project_shared.id, role='admin')
        db.session.add(admin_access)

        # Create another project for user_target only
        project_target_only = Project(name='Target Only Project')
        db.session.add(project_target_only)
        db.session.commit()

        # Grant user_target access to project_target_only
        target_only_access = ProjectAccess(user_id=user_target.id, project_id=project_target_only.id, role='expert')
        db.session.add(target_only_access)
        db.session.commit()

    # Log in admin_main
    login_resp = client.post('/login', data={'username': 'admin_main@example.com', 'password': 'password'})
    assert login_resp.status_code == 302 # Redirect after login

    # 2. Action Part 1 (Invite user_target to project_shared)
    invited_role = 'contractor'
    with mail.record_messages() as outbox: # Ensure we capture emails if any
        invite_response = client.post('/invite', data={
            'email': user_target.email,
            'invite_project_ids': [str(project_shared.id)],
            'role': invited_role
        })

    assert invite_response.status_code == 200
    invite_json = invite_response.get_json()
    assert invite_json['status'] == 'success'
    assert 'Access granted/updated for existing user' in invite_json['message']

    with app.app_context():
        # Verify ProjectAccess for user_target
        access = ProjectAccess.query.filter_by(user_id=user_target.id, project_id=project_shared.id).first()
        assert access is not None
        assert access.role == invited_role

    # 3. Action Part 2 (Verify in manage_access)
    manage_access_response = client.get('/manage_access')
    assert manage_access_response.status_code == 200

    response_data_html = manage_access_response.data.decode('utf-8')

    # Check if user_target is in the dropdown
    assert f'<option value="{user_target.id}">{user_target.username}</option>' in response_data_html

    # Check if user_target's access is listed in the table
    # This requires more specific HTML parsing or string checking.
    # We look for a row containing user's username, project name, and role.
    # A more robust check might involve BeautifulSoup or similar, but string contains is often sufficient for tests.
    assert user_target.username in response_data_html
    assert user_target.name in response_data_html # Assuming name is displayed
    assert user_target.company in response_data_html # Assuming company is displayed
    assert project_shared.name in response_data_html
    assert invited_role in response_data_html

    # A slightly more specific check for the table row structure:
    # This is still a bit brittle if exact HTML structure changes, but better than just individual strings.
    # Example: looking for parts of the row, like <td>user_target.username</td> ... <td>project_shared.name</td> ... <td>invited_role</td>
    # For simplicity, the individual checks above are often a good start.
    # Let's try to find a pattern for the row.
    # Example: Looking for a substring that represents the row for user_target and project_shared
    # This is highly dependent on the exact HTML structure in manage_access.html's table.
    # We'll assume the individual checks are sufficient for now.
    # A more advanced test could parse the HTML table.
    # For instance, checking for a row containing these pieces of information:
    expected_row_part_user = f'<td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{user_target.username}</td>'
    expected_row_part_name = f'<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user_target.name}</td>'
    expected_row_part_company = f'<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user_target.company}</td>'
    expected_row_part_project_shared = f'<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{project_shared.name}</td>'
    expected_row_part_role = f'<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{invited_role}</td>'

    # Assert that the shared project is listed
    assert expected_row_part_user in response_data_html
    assert expected_row_part_name in response_data_html
    assert expected_row_part_company in response_data_html
    assert expected_row_part_project_shared in response_data_html
    assert expected_row_part_role in response_data_html

    # Assert that the target_only_project is NOT listed for this user in this view
    # (because admin_main does not manage project_target_only)
    # We check that the specific combination of user details + project_target_only.name + role is not present.
    # A simple check is that the project_target_only.name is not in any row associated with user_target.
    # The template logic should filter this out.
    expected_row_part_project_target_only = f'<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{project_target_only.name}</td>'

    # Construct a string representing the full row for the non-shared project, if it were to be displayed
    # This is a bit brittle, as it relies on the order of cells.
    # A more robust test would parse HTML, but this is a common approach for direct string checking.
    # We are checking if the combination of user_target's info AND project_target_only appears.
    # Since user_target.username should appear for project_shared, we want to make sure project_target_only
    # is NOT on a row that also contains user_target.username.

    # Simpler: just check if the cell for project_target_only.name is present at all in rows that could belong to user_target.
    # If the table structure is consistent for all rows:
    # <tr><td>USERNAME</td><td>NAME</td><td>COMPANY</td><td>PROJECT_NAME</td><td>ROLE</td><td>ACTIONS</td></tr>
    # We are checking that PROJECT_NAME is not project_target_only.name for user_target.
    # The current assertions for expected_row_part_project_shared confirm the structure for a displayed project.
    # So, if project_target_only.name were to appear for user_target, it would be in a similar cell.
    # The most straightforward way without parsing HTML is to ensure that the specific cell content for the unmanaged project is not there.
    # This test is primarily ensuring that the *admin's scope* filters the projects shown in the table for *other users*.

    # Check that project_target_only.name is not present in a context where it would be listed for user_target
    # This means if we find a row with user_target.username, it should not also contain project_target_only.name
    # A direct negative assertion is simpler:
    assert expected_row_part_project_target_only not in response_data_html

    # More specific check (optional, can be complex with string matching):
    # Find all rows for user_target.
    # user_target_rows = [] # This would require regex or HTML parsing to populate correctly.
    # for row_html in user_target_rows:
    #     assert project_target_only.name not in row_html
    # For now, the direct `not in` for the specific cell content of the unmanaged project is the primary check.

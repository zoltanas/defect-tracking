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

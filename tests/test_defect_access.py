import os
import tempfile
import pytest
from app import app, db, User, Project, Defect, ProjectAccess, bcrypt, Template, TemplateItem, Checklist, Comment
from flask_login import login_user, logout_user, current_user
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from app import User, Project, Defect, Comment, ProjectAccess, db, bcrypt # Duplicated but ensures it's there
from datetime import datetime # Duplicated but ensures it's there


@pytest.fixture(scope='module')
def test_client():
    # Configure the app for testing
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' # Use in-memory SQLite for tests
    app.config['WTF_CSRF_ENABLED'] = False # Disable CSRF for easier testing of form submissions
    app.config['LOGIN_DISABLED'] = False # Ensure login is enabled

    # Create a test client using the Flask application configured for testing
    with app.test_client() as testing_client:
        with app.app_context():
            db.drop_all() # Ensure a clean slate before creating tables
            db.create_all()
            # Create initial users and data if needed globally for the module
            admin_user = User(username='test_admin', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin')
            expert_user1 = User(username='test_expert1', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert')
            expert_user2 = User(username='test_expert2', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert')
            tech_supervisor_user = User(username='tech_supervisor', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='Technical supervisor')
            another_expert_user = User(username='another_expert', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert')


            db.session.add_all([admin_user, expert_user1, expert_user2, tech_supervisor_user, another_expert_user])
            db.session.commit()

            # Create a project
            project1 = Project(name='Test Project 1')
            db.session.add(project1)
            db.session.commit()

            # Grant access
            access_admin = ProjectAccess(user_id=admin_user.id, project_id=project1.id, role='admin')
            access_expert1 = ProjectAccess(user_id=expert_user1.id, project_id=project1.id, role='expert')
            access_expert2 = ProjectAccess(user_id=expert_user2.id, project_id=project1.id, role='expert')
            access_tech_supervisor = ProjectAccess(user_id=tech_supervisor_user.id, project_id=project1.id, role='Technical supervisor')
            access_another_expert = ProjectAccess(user_id=another_expert_user.id, project_id=project1.id, role='expert')
            db.session.add_all([access_admin, access_expert1, access_expert2, access_tech_supervisor, access_another_expert])
            db.session.commit()

            # Create defects
            defect_by_admin = Defect(project_id=project1.id, description='Defect by Admin', creator_id=admin_user.id, creation_date=datetime.now())
            defect_by_expert1 = Defect(project_id=project1.id, description='Defect by Expert 1', creator_id=expert_user1.id, creation_date=datetime.now())
            defect_by_expert2 = Defect(project_id=project1.id, description='Defect by Expert 2', creator_id=expert_user2.id, creation_date=datetime.now())
            defect_by_tech_supervisor = Defect(project_id=project1.id, description='Defect by Tech Supervisor', creator_id=tech_supervisor_user.id, creation_date=datetime.now())
            defect_by_another_expert = Defect(project_id=project1.id, description='Defect by Another Expert', creator_id=another_expert_user.id, creation_date=datetime.now())
            db.session.add_all([defect_by_admin, defect_by_expert1, defect_by_expert2, defect_by_tech_supervisor, defect_by_another_expert])
            db.session.commit()

            yield testing_client # this is where the testing happens!

            db.session.remove()
            db.drop_all()

def login(client, username, password):
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=True)

def logout(client):
    return client.get('/logout', follow_redirects=True)

# Test Scenario 1: Expert user views a project page. They should only see defects they created.
def test_expert_sees_only_own_defects_on_project_page(test_client):
    admin_user = User.query.filter_by(username='test_admin').first()
    expert1_user = User.query.filter_by(username='test_expert1').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()

    # Defect created by expert1
    defect_by_expert1 = Defect.query.filter_by(creator_id=expert1_user.id, project_id=project1.id).first()
    # Defect created by admin
    defect_by_admin = Defect.query.filter_by(creator_id=admin_user.id, project_id=project1.id).first()

    login(test_client, 'test_expert1', 'password')
    response = test_client.get(f'/project/{project1.id}')
    assert response.status_code == 200
    response_data = response.get_data(as_text=True)

    assert defect_by_expert1.description in response_data
    assert defect_by_admin.description not in response_data
    logout(test_client)

# Test Scenario 2: An expert user attempts to directly access the detail page of a defect created by another user.
def test_expert_cannot_view_others_defect_detail(test_client):
    admin_user = User.query.filter_by(username='test_admin').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()
    defect_by_admin = Defect.query.filter_by(creator_id=admin_user.id, project_id=project1.id).first()

    login(test_client, 'test_expert1', 'password')
    response = test_client.get(f'/defect/{defect_by_admin.id}', follow_redirects=True)
    assert response.status_code == 200 # Should redirect
    response_data = response.get_data(as_text=True)
    assert 'You do not have permission to view this defect' in response_data
    assert defect_by_admin.description not in response_data # Original defect description should not be there
    logout(test_client)

# Test Scenario 3: An expert user attempts to edit a defect created by another user.
def test_expert_cannot_edit_others_defect(test_client):
    admin_user = User.query.filter_by(username='test_admin').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()
    defect_by_admin = Defect.query.filter_by(creator_id=admin_user.id, project_id=project1.id).first()

    login(test_client, 'test_expert1', 'password')
    response = test_client.post(f'/defect/{defect_by_admin.id}', data=dict(
        action='edit_defect',
        description='Attempted edit by expert1',
        status='open'
        # Add other required form fields if any, like drawing_id, marker_x, marker_y if they become mandatory
    ), follow_redirects=True)
    assert response.status_code == 200 # Should redirect
    response_data = response.get_data(as_text=True)
    assert 'You do not have permission to view this defect as it was not created by you.' in response_data

    # Verify the defect description hasn't changed
    db.session.refresh(defect_by_admin) # Refresh from DB
    assert defect_by_admin.description == 'Defect by Admin'
    logout(test_client)

# Test Scenario 4: An expert user successfully views and edits a defect they created.
def test_expert_can_view_and_edit_own_defect(test_client):
    expert1_user = User.query.filter_by(username='test_expert1').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()
    defect_by_expert1 = Defect.query.filter_by(creator_id=expert1_user.id, project_id=project1.id).first()

    login(test_client, 'test_expert1', 'password')

    # Test viewing
    response_view = test_client.get(f'/defect/{defect_by_expert1.id}')
    assert response_view.status_code == 200
    assert defect_by_expert1.description in response_view.get_data(as_text=True)

    # Test editing
    new_description = 'Updated by expert1 successfully'
    response_edit = test_client.post(f'/defect/{defect_by_expert1.id}', data=dict(
        action='edit_defect',
        description=new_description,
        status='open'
        # Add other required form fields if any
    ), follow_redirects=True)
    assert response_edit.status_code == 200
    assert 'Defect updated successfully!' in response_edit.get_data(as_text=True)

    db.session.refresh(defect_by_expert1)
    assert defect_by_expert1.description == new_description
    logout(test_client)

# Test Scenario 5: An admin user logs in. They should be able to see all defects and edit any defect.
def test_admin_can_view_and_edit_all_defects(test_client):
    admin_user = User.query.filter_by(username='test_admin').first()
    expert1_user = User.query.filter_by(username='test_expert1').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()

    defect_by_admin = Defect.query.filter_by(creator_id=admin_user.id, project_id=project1.id).first()
    defect_by_expert1 = Defect.query.filter_by(creator_id=expert1_user.id, project_id=project1.id).first()

    login(test_client, 'test_admin', 'password')

    # Admin views project page - should see all defects
    response_project = test_client.get(f'/project/{project1.id}')
    assert response_project.status_code == 200
    project_data = response_project.get_data(as_text=True)
    assert defect_by_admin.description in project_data
    assert defect_by_expert1.description in project_data

    # Admin views expert1's defect detail page
    response_view_expert_defect = test_client.get(f'/defect/{defect_by_expert1.id}')
    assert response_view_expert_defect.status_code == 200
    assert defect_by_expert1.description in response_view_expert_defect.get_data(as_text=True)

    # Admin edits expert1's defect
    admin_edit_description = 'Admin edit on expert defect'
    response_edit_expert_defect = test_client.post(f'/defect/{defect_by_expert1.id}', data=dict(
        action='edit_defect',
        description=admin_edit_description,
        status='closed' # Admin changes status
        # Add other required form fields if any
    ), follow_redirects=True)
    assert response_edit_expert_defect.status_code == 200
    assert 'Defect updated successfully!' in response_edit_expert_defect.get_data(as_text=True)

    db.session.refresh(defect_by_expert1)
    assert defect_by_expert1.description == admin_edit_description
    assert defect_by_expert1.status == 'closed'

    logout(test_client)

# It might be good to add a test for a contractor user to ensure they are not affected by these changes
# (i.e., their access remains unchanged, assuming they have different rules or no defect creation/editing rights).
# For now, focusing on admin/expert roles as per the issue.

# Test Scenario: Expert user generates a report, should only contain their defects.
@patch('app.render_template') # Mock render_template
def test_expert_report_contains_only_own_defects(mock_render_template, test_client):
    expert1_user = User.query.filter_by(username='test_expert1').first()
    admin_user = User.query.filter_by(username='test_admin').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()

    defect_by_expert1 = Defect.query.filter_by(creator_id=expert1_user.id, project_id=project1.id).first()
    defect_by_admin = Defect.query.filter_by(creator_id=admin_user.id, project_id=project1.id).first()

    # Mock the return value of render_template to prevent actual PDF generation
    # and to allow inspection of arguments passed to it.
    mock_render_template.return_value = "mocked PDF content"

    login(test_client, 'test_expert1', 'password')
    response = test_client.get(f'/project/{project1.id}/new_report')

    assert response.status_code == 200 # Report generation should be successful

    # Check the arguments passed to render_template
    assert mock_render_template.called
    args, kwargs = mock_render_template.call_args
    assert kwargs['project'].id == project1.id

    reported_defects = kwargs['defects']
    reported_defect_ids = [d.id for d in reported_defects]

    assert defect_by_expert1.id in reported_defect_ids
    assert defect_by_admin.id not in reported_defect_ids

    logout(test_client)

# Test Scenario: Admin user generates a report, should contain all defects.
@patch('app.render_template') # Mock render_template
def test_admin_report_contains_all_defects(mock_render_template, test_client):
    expert1_user = User.query.filter_by(username='test_expert1').first()
    admin_user = User.query.filter_by(username='test_admin').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()

    defect_by_expert1 = Defect.query.filter_by(creator_id=expert1_user.id, project_id=project1.id).first()
    defect_by_admin = Defect.query.filter_by(creator_id=admin_user.id, project_id=project1.id).first()

    mock_render_template.return_value = "mocked PDF content"

    login(test_client, 'test_admin', 'password')
    response = test_client.get(f'/project/{project1.id}/new_report')

    assert response.status_code == 200

    assert mock_render_template.called
    args, kwargs = mock_render_template.call_args
    assert kwargs['project'].id == project1.id

    reported_defects = kwargs['defects']
    reported_defect_ids = [d.id for d in reported_defects]

    assert defect_by_expert1.id in reported_defect_ids
    assert defect_by_admin.id in reported_defect_ids

    logout(test_client)


# --- Tests for Technical Supervisor Role ---

def test_admin_can_invite_technical_supervisor(test_client):
    admin_user = User.query.filter_by(username='test_admin').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()

    login(test_client, 'test_admin', 'password')

    # Invite a new user as Technical Supervisor
    invite_response = test_client.post('/invite', data=dict(
        project_id=project1.id,
        role='Technical supervisor'
    ), follow_redirects=True)
    assert invite_response.status_code == 200
    invite_json = invite_response.get_json()
    assert invite_json['status'] == 'success'
    assert 'invite_link' in invite_json

    invite_token = invite_json['invite_link'].split('/')[-1]

    # New user accepts invitation
    logout(test_client) # Log out admin before new user accepts

    accept_response_get = test_client.get(f'/accept_invite/{invite_token}')
    assert accept_response_get.status_code == 200

    # Simulate form submission for accepting invite
    # Find the temporary user created by the invite
    temp_user = User.query.filter(User.username.like('temp_%')).first()
    assert temp_user is not None

    new_username = 'new_tech_supervisor'
    new_password = 'new_password'

    accept_response_post = test_client.post(f'/accept_invite/{invite_token}', data=dict(
        username=new_username,
        password=new_password,
        confirm_password=new_password
    ), follow_redirects=True)

    assert accept_response_post.status_code == 200
    assert 'Invitation accepted! You are now logged in.' in accept_response_post.get_data(as_text=True)

    # Verify user role and project access
    newly_registered_user = User.query.filter_by(username=new_username).first()
    assert newly_registered_user is not None
    assert newly_registered_user.role == 'Technical supervisor'

    project_access = ProjectAccess.query.filter_by(user_id=newly_registered_user.id, project_id=project1.id).first()
    assert project_access is not None
    assert project_access.role == 'Technical supervisor'

    # Clean up: It might be good to delete this user or use transactions if tests interfere
    logout(test_client)


def test_tech_supervisor_sees_all_defects_on_project_page(test_client):
    project1 = Project.query.filter_by(name='Test Project 1').first()
    admin_user = User.query.filter_by(username='test_admin').first()
    expert1_user = User.query.filter_by(username='test_expert1').first()
    tech_supervisor_user = User.query.filter_by(username='tech_supervisor').first()

    defect_by_admin = Defect.query.filter_by(creator_id=admin_user.id, project_id=project1.id).first()
    defect_by_expert1 = Defect.query.filter_by(creator_id=expert1_user.id, project_id=project1.id).first()
    defect_by_tech_supervisor = Defect.query.filter_by(creator_id=tech_supervisor_user.id, project_id=project1.id).first()

    login(test_client, 'tech_supervisor', 'password')
    response = test_client.get(f'/project/{project1.id}')
    assert response.status_code == 200
    response_data = response.get_data(as_text=True)

    assert defect_by_admin.description in response_data
    assert defect_by_expert1.description in response_data
    assert defect_by_tech_supervisor.description in response_data
    logout(test_client)

def test_tech_supervisor_can_add_defect(test_client):
    project1 = Project.query.filter_by(name='Test Project 1').first()
    tech_supervisor_user = User.query.filter_by(username='tech_supervisor').first()

    login(test_client, 'tech_supervisor', 'password')

    defect_description = "New defect by Tech Supervisor"
    response = test_client.post(f'/project/{project1.id}/add_defect', data=dict(
        description=defect_description
        # Assuming no drawing/marker data is mandatory for this test
    ), follow_redirects=True)

    assert response.status_code == 200 # Should redirect to defect detail page
    assert 'Defect created successfully!' in response.get_data(as_text=True)

    new_defect = Defect.query.filter_by(description=defect_description, creator_id=tech_supervisor_user.id).first()
    assert new_defect is not None
    assert new_defect.project_id == project1.id
    logout(test_client)

def test_tech_supervisor_can_edit_own_defect(test_client):
    tech_supervisor_user = User.query.filter_by(username='tech_supervisor').first()
    defect_by_tech_supervisor = Defect.query.filter_by(creator_id=tech_supervisor_user.id).first()

    login(test_client, 'tech_supervisor', 'password')

    new_description = "Tech Supervisor edited own defect"
    response = test_client.post(f'/defect/{defect_by_tech_supervisor.id}', data=dict(
        action='edit_defect',
        description=new_description,
        status=defect_by_tech_supervisor.status
    ), follow_redirects=True)

    assert response.status_code == 200
    assert 'Defect updated successfully!' in response.get_data(as_text=True)
    db.session.refresh(defect_by_tech_supervisor)
    assert defect_by_tech_supervisor.description == new_description
    logout(test_client)

def test_tech_supervisor_cannot_edit_others_defect(test_client):
    expert1_user = User.query.filter_by(username='test_expert1').first()
    defect_by_expert1 = Defect.query.filter_by(creator_id=expert1_user.id).first()

    login(test_client, 'tech_supervisor', 'password')

    original_description = defect_by_expert1.description
    response = test_client.post(f'/defect/{defect_by_expert1.id}', data=dict(
        action='edit_defect',
        description="Attempted edit by Tech Supervisor",
        status=defect_by_expert1.status
    ), follow_redirects=True)

    assert response.status_code == 200
    assert 'You do not have permission to edit this defect.' in response.get_data(as_text=True)
    db.session.refresh(defect_by_expert1)
    assert defect_by_expert1.description == original_description # Description should not change
    logout(test_client)

def test_tech_supervisor_can_close_own_defect(test_client):
    tech_supervisor_user = User.query.filter_by(username='tech_supervisor').first()
    # Ensure there's an open defect by the tech supervisor
    defect_to_close = Defect.query.filter_by(creator_id=tech_supervisor_user.id, status='open').first()
    if not defect_to_close: # Create one if not exists from fixture
        project1 = Project.query.filter_by(name='Test Project 1').first()
        defect_to_close = Defect(project_id=project1.id, description='Open defect for TS to close', creator_id=tech_supervisor_user.id, status='open', creation_date=datetime.now())
        db.session.add(defect_to_close)
        db.session.commit()

    login(test_client, 'tech_supervisor', 'password')

    response = test_client.post(f'/defect/{defect_to_close.id}', data=dict(
        action='edit_defect',
        description=defect_to_close.description, # Keep description same
        status='closed'
    ), follow_redirects=True)

    assert response.status_code == 200
    assert 'Defect updated successfully!' in response.get_data(as_text=True)
    db.session.refresh(defect_to_close)
    assert defect_to_close.status == 'closed'
    logout(test_client)

def test_tech_supervisor_cannot_close_others_defect(test_client):
    expert1_user = User.query.filter_by(username='test_expert1').first()
    # Ensure there's an open defect by expert1
    defect_by_expert1 = Defect.query.filter_by(creator_id=expert1_user.id, status='open').first()
    if not defect_by_expert1: # Create one if not exists
        project1 = Project.query.filter_by(name='Test Project 1').first()
        defect_by_expert1 = Defect(project_id=project1.id, description='Open defect by Expert 1 for TS test', creator_id=expert1_user.id, status='open', creation_date=datetime.now())
        db.session.add(defect_by_expert1)
        db.session.commit()

    login(test_client, 'tech_supervisor', 'password')

    response = test_client.post(f'/defect/{defect_by_expert1.id}', data=dict(
        action='edit_defect',
        description=defect_by_expert1.description,
        status='closed' # Attempt to close
    ), follow_redirects=True)

    assert response.status_code == 200
    assert 'You do not have permission to edit this defect.' in response.get_data(as_text=True)
    db.session.refresh(defect_by_expert1)
    assert defect_by_expert1.status == 'open' # Status should not change
    logout(test_client)


def test_tech_supervisor_can_comment_on_others_defect(test_client):
    # Get users and project from the fixture setup
    admin_user = User.query.filter_by(username='test_admin').first()
    tech_supervisor_user = User.query.filter_by(username='tech_supervisor').first()
    project1 = Project.query.filter_by(name='Test Project 1').first()

    # Ensure a defect exists that was NOT created by the tech_supervisor
    # For example, use the defect created by the admin_user
    defect_by_admin = Defect.query.filter_by(creator_id=admin_user.id, project_id=project1.id).first()
    assert defect_by_admin is not None, "Defect by admin not found for test setup."
    assert defect_by_admin.creator_id != tech_supervisor_user.id

    # Log in as Technical Supervisor
    login(test_client, 'tech_supervisor', 'password')

    # Navigate to the defect detail page (GET request to ensure page loads)
    response_get = test_client.get(f'/defect/{defect_by_admin.id}')
    assert response_get.status_code == 200

    # Tech Supervisor adds a comment
    comment_content = "Comment from Technical Supervisor on admin's defect."
    # Make sure to include csrf_token if it's enabled for tests,
    # or ensure it's handled by the test client setup.
    # The current test_client fixture disables WTF_CSRF_ENABLED, so it should be fine.
    response_post = test_client.post(f'/defect/{defect_by_admin.id}', data=dict(
        action='add_comment',
        comment_content=comment_content
    ), follow_redirects=True)

    assert response_post.status_code == 200
    assert 'Comment added successfully!' in response_post.get_data(as_text=True)

    # Verify the comment was added to the database
    new_comment = Comment.query.filter_by(
        defect_id=defect_by_admin.id,
        user_id=tech_supervisor_user.id,
        content=comment_content
    ).first()
    assert new_comment is not None
    assert new_comment.user_id == tech_supervisor_user.id
    assert new_comment.content == comment_content

    # Also, check if the comment appears on the defect detail page after adding
    response_after_comment = test_client.get(f'/defect/{defect_by_admin.id}')
    assert response_after_comment.status_code == 200

    html_content = response_after_comment.get_data(as_text=True)
    # print(f"DEBUG HTML for defect {defect_by_admin.id}:\n{html_content}\n") # Debugging line

    # Check if the comment author's username appears
    assert tech_supervisor_user.username in html_content, f"Tech supervisor username '{tech_supervisor_user.username}' not found in HTML."

    # Check if the specific comment content appears, accounting for potential HTML escaping of apostrophe
    expected_comment_text_original = "Supervisor on admin's defect"
    expected_comment_text_escaped = "Supervisor on admin&#39;s defect"
    assert expected_comment_text_original in html_content or \
           expected_comment_text_escaped in html_content, \
           f"Comment content '{expected_comment_text_original}' (or escaped form) not found in HTML."

    logout(test_client)


def test_invite_page_renders_technical_supervisor_option(test_client):
    # Ensure an admin is logged in to access /invite
    login(test_client, 'test_admin', 'password')

    response = test_client.get('/invite')
    assert response.status_code == 200
    response_data = response.get_data(as_text=True)

    # Check for the option value and text
    expected_option_html = '<option value="Technical supervisor">Technical supervisor</option>'
    assert expected_option_html in response_data

    # It's good practice to also check that the other options are still there,
    # though for this specific subtask, ensuring the new one is present is key.
    assert '<option value="admin">Admin</option>' in response_data
    assert '<option value="expert">Expert</option>' in response_data
    assert '<option value="contractor">Contractor</option>' in response_data

    logout(test_client)


# --- Technical Supervisor: Defect Button Visibility ---
def test_tech_supervisor_sees_add_defect_button_on_project_page(test_client):
    project1 = Project.query.filter_by(name='Test Project 1').first()
    login(test_client, 'tech_supervisor', 'password')
    response = test_client.get(f'/project/{project1.id}')
    assert response.status_code == 200
    response_data = response.get_data(as_text=True)
    assert f'href="/project/{project1.id}/add_defect"' in response_data
    assert "Add Defect" in response_data
    logout(test_client)

# --- Technical Supervisor: Checklist Management ---
def test_tech_supervisor_sees_add_checklist_button_on_project_page(test_client):
    project1 = Project.query.filter_by(name='Test Project 1').first()
    login(test_client, 'tech_supervisor', 'password')
    response = test_client.get(f'/project/{project1.id}') # Ensure this page now shows the button for tech_supervisor
    assert response.status_code == 200
    response_data = response.get_data(as_text=True)
    # The button might be hidden/shown by JS based on tab, so ensure the HTML for it exists
    assert f'href="{{ url_for(\'add_checklist\', project_id={project1.id}) }}"' in response_data or \
           f'href="/project/{project1.id}/add_checklist"' in response_data
    assert "Add Checklist" in response_data # Check for button text
    logout(test_client)

def test_tech_supervisor_can_access_add_checklist_page(test_client):
    project1 = Project.query.filter_by(name='Test Project 1').first()
    login(test_client, 'tech_supervisor', 'password')
    response = test_client.get(f'/project/{project1.id}/add_checklist')
    assert response.status_code == 200
    # Check for the text content, respecting the HTML structure
    expected_html_snippet = b"Add Checklist to <span class=\"text-primary\">" + project1.name.encode() + b"</span>"
    assert expected_html_snippet in response.data
    logout(test_client)

def test_tech_supervisor_can_add_checklist(test_client):
    project1 = Project.query.filter_by(name='Test Project 1').first()
    # Ensure a template exists
    template = Template.query.first()
    if not template:
        template = Template(name="Test Template for Checklist")
        db.session.add(template)
        db.session.commit()

    login(test_client, 'tech_supervisor', 'password')
    checklist_name = "Tech Supervisor Checklist"
    response = test_client.post(f'/project/{project1.id}/add_checklist', data=dict(
        name=checklist_name,
        template_id=template.id
    ), follow_redirects=True)
    assert response.status_code == 200
    assert "Checklist added successfully!" in response.get_data(as_text=True)

    new_checklist = Checklist.query.filter_by(name=checklist_name, project_id=project1.id).first()
    assert new_checklist is not None
    logout(test_client)

def test_tech_supervisor_can_delete_checklist(test_client):
    project1 = Project.query.filter_by(name='Test Project 1').first()
    tech_supervisor_user = User.query.filter_by(username='tech_supervisor').first()
    template = Template.query.first() # Assume one exists from previous test or fixture
    if not template:
        template = Template(name="Default Template for Deletion Test")
        db.session.add(template)
        db.session.commit()

    checklist_to_delete = Checklist(name="Checklist to be deleted by TS", project_id=project1.id, template_id=template.id)
    db.session.add(checklist_to_delete)
    db.session.commit()
    checklist_id = checklist_to_delete.id

    login(test_client, 'tech_supervisor', 'password')
    response = test_client.post(f'/checklist/{checklist_id}/delete', follow_redirects=True)
    assert response.status_code == 200
    assert "Checklist and all associated data deleted successfully!" in response.get_data(as_text=True)

    deleted_checklist = Checklist.query.get(checklist_id)
    assert deleted_checklist is None
    logout(test_client)

# --- Technical Supervisor: Template Management ---
def test_tech_supervisor_sees_manage_templates_button_on_project_page(test_client):
    project1 = Project.query.filter_by(name='Test Project 1').first()
    login(test_client, 'tech_supervisor', 'password')
    response = test_client.get(f'/project/{project1.id}')
    assert response.status_code == 200
    response_data = response.get_data(as_text=True)
    assert 'href="/templates"' in response_data or "href=\"{{ url_for('template_list') }}\"" in response_data
    assert "Manage Templates" in response_data
    logout(test_client)


class TestDefectFilters: # Renamed class
    def setup_method(self, method):
        # Common setup for these tests: create users, project
        with app.app_context():
            creator_user = User.query.filter_by(username='test_expert1').first()
            # Ensure users exist, create if not (though module fixture should handle this)
            if not creator_user:
                creator_user = User(username='test_expert1', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert')
                db.session.add(creator_user)

            other_user = User.query.filter_by(username='test_expert2').first()
            if not other_user:
                other_user = User(username='test_expert2', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert')
                db.session.add(other_user)

            admin_user = User.query.filter_by(username='test_admin').first()
            if not admin_user:
                admin_user = User(username='test_admin', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin')
                db.session.add(admin_user)

            db.session.commit() # Commit users if any were added

            self.creator_user_id = creator_user.id
            self.other_user_id = other_user.id
            self.admin_user_id = admin_user.id
            self.creator_username = creator_user.username
            self.other_username = other_user.username
            self.admin_username = admin_user.username


            self.project = Project.query.filter_by(name='Filter Test Project').first()
            if not self.project:
                self.project = Project(name='Filter Test Project')
                db.session.add(self.project)
                db.session.commit()

            self.project_id = self.project.id # Store project_id

            # Grant access for users to the project
            # Ensure users are re-fetched for the current session if their IDs are used for new ProjectAccess instances
            current_session_creator_user = db.session.get(User, self.creator_user_id)
            current_session_other_user = db.session.get(User, self.other_user_id)
            current_session_admin_user = db.session.get(User, self.admin_user_id)

            for user in [current_session_creator_user, current_session_other_user, current_session_admin_user]:
                if user: # Check if user was found
                    access = ProjectAccess.query.filter_by(user_id=user.id, project_id=self.project.id).first()
                    if not access:
                        # Determine role based on user object if complex, or assign default for test
                        role_to_assign = user.role if hasattr(user, 'role') else 'expert'
                        access = ProjectAccess(user_id=user.id, project_id=self.project.id, role=role_to_assign)
                        db.session.add(access)
            db.session.commit()

    def teardown_method(self, method):
        with app.app_context():
            # More robust cleanup: query defects by project_id and then their comments
            defects_to_delete = Defect.query.filter_by(project_id=self.project_id).all()
            for defect in defects_to_delete:
                Comment.query.filter_by(defect_id=defect.id).delete()
                db.session.delete(defect)
            db.session.commit()

            # Optionally, delete the project if it was uniquely created for this test class
            # project_to_delete = Project.query.get(self.project_id)
            # if project_to_delete:
            # ProjectAccess.query.filter_by(project_id=project_to_delete.id).delete()
            # db.session.delete(project_to_delete)
            # db.session.commit()


    def test_filter_open_with_reply_defect_visible_last_comment_by_other(self, test_client):
        # Scenario 1: Defect is 'open', last comment by other user -> VISIBLE
        login(test_client, self.admin_username, 'password')

        defect1 = Defect(description="S1 Open Defect Reply by Other", project_id=self.project_id, creator_id=self.creator_user_id, status='open', creation_date=datetime.utcnow())
        db.session.add(defect1)
        db.session.commit()

        comment1_defect1 = Comment(defect_id=defect1.id, user_id=self.creator_user_id, content="Creator's first comment", created_at=datetime.utcnow() - timedelta(hours=2))
        comment2_defect1 = Comment(defect_id=defect1.id, user_id=self.other_user_id, content="Other user's reply", created_at=datetime.utcnow() - timedelta(hours=1))
        db.session.add_all([comment1_defect1, comment2_defect1])
        db.session.commit()

        response = test_client.get(f'/project/{self.project_id}?filter=OpenWithReply')
        assert response.status_code == 200
        assert defect1.description in response.data.decode()
        logout(test_client)

    def test_filter_open_with_reply_defect_hidden_last_comment_by_creator(self, test_client):
        # Scenario 2: Defect is 'open', last comment by creator -> HIDDEN
        login(test_client, self.admin_username, 'password')

        defect2 = Defect(description="S2 Open Defect Last Reply by Creator", project_id=self.project_id, creator_id=self.creator_user_id, status='open', creation_date=datetime.utcnow())
        db.session.add(defect2)
        db.session.commit()

        comment1_defect2 = Comment(defect_id=defect2.id, user_id=self.other_user_id, content="Other user's first comment", created_at=datetime.utcnow() - timedelta(hours=2))
        comment2_defect2 = Comment(defect_id=defect2.id, user_id=self.creator_user_id, content="Creator's reply", created_at=datetime.utcnow() - timedelta(hours=1))
        db.session.add_all([comment1_defect2, comment2_defect2])
        db.session.commit()

        response = test_client.get(f'/project/{self.project_id}?filter=OpenWithReply')
        assert response.status_code == 200
        assert defect2.description not in response.data.decode()
        logout(test_client)

    def test_filter_open_with_reply_defect_hidden_no_comments(self, test_client):
        # Scenario 3: Defect is 'open', no comments -> HIDDEN
        login(test_client, self.admin_username, 'password')

        defect3 = Defect(description="S3 Open Defect No Comments", project_id=self.project_id, creator_id=self.creator_user_id, status='open', creation_date=datetime.utcnow())
        db.session.add(defect3)
        db.session.commit()

        response = test_client.get(f'/project/{self.project_id}?filter=OpenWithReply')
        assert response.status_code == 200
        assert defect3.description not in response.data.decode()
        logout(test_client)

    def test_filter_open_with_reply_defect_hidden_closed_status(self, test_client):
        # Scenario 4: Defect is 'closed', even if last comment by other -> HIDDEN
        login(test_client, self.admin_username, 'password')

        defect4 = Defect(description="S4 Closed Defect Reply by Other", project_id=self.project_id, creator_id=self.creator_user_id, status='closed', creation_date=datetime.utcnow(), close_date=datetime.utcnow())
        db.session.add(defect4)
        db.session.commit()

        comment1_defect4 = Comment(defect_id=defect4.id, user_id=self.other_user_id, content="Other user's reply", created_at=datetime.utcnow() - timedelta(hours=1))
        db.session.add(comment1_defect4)
        db.session.commit()

        response = test_client.get(f'/project/{self.project_id}?filter=OpenWithReply')
        assert response.status_code == 200
        assert defect4.description not in response.data.decode()
        logout(test_client)

    def test_filter_open_with_reply_defect_visible_multiple_comments_last_by_other(self, test_client):
        # Scenario 5: Defect is 'open', multiple comments, very last by other -> VISIBLE
        login(test_client, self.admin_username, 'password')

        defect5 = Defect(description="S5 Open Defect Multi Comments Last by Other", project_id=self.project_id, creator_id=self.creator_user_id, status='open', creation_date=datetime.utcnow())
        db.session.add(defect5)
        db.session.commit()

        comments = [
            Comment(defect_id=defect5.id, user_id=self.creator_user_id, content="C1", created_at=datetime.utcnow() - timedelta(minutes=50)),
            Comment(defect_id=defect5.id, user_id=self.other_user_id, content="O1", created_at=datetime.utcnow() - timedelta(minutes=40)),
            Comment(defect_id=defect5.id, user_id=self.creator_user_id, content="C2", created_at=datetime.utcnow() - timedelta(minutes=30)),
            Comment(defect_id=defect5.id, user_id=self.other_user_id, content="O2 - Last one", created_at=datetime.utcnow() - timedelta(minutes=20))
        ]
        db.session.add_all(comments)
        db.session.commit()

        response = test_client.get(f'/project/{self.project_id}?filter=OpenWithReply')
        assert response.status_code == 200
        assert defect5.description in response.data.decode()
        logout(test_client)

    def test_filter_open_with_reply_defect_hidden_only_comment_by_creator(self, test_client):
        # Additional Scenario: Open defect, only one comment, and it's by the creator -> HIDDEN
        login(test_client, self.admin_username, 'password')

        defect6 = Defect(description="S6 Open Defect Only Comment by Creator", project_id=self.project_id, creator_id=self.creator_user_id, status='open', creation_date=datetime.utcnow())
        db.session.add(defect6)
        db.session.commit()

        comment1_defect6 = Comment(defect_id=defect6.id, user_id=self.creator_user_id, content="Creator's only comment", created_at=datetime.utcnow() - timedelta(hours=1))
        db.session.add(comment1_defect6)
        db.session.commit()

        response = test_client.get(f'/project/{self.project_id}?filter=OpenWithReply')
        assert response.status_code == 200
        assert defect6.description not in response.data.decode()
        logout(test_client)

    def test_open_with_reply_filter_technical_supervisor(self, test_client): # Removed app from signature
        # Removed with app.app_context(): block to use test_client's context
        # Setup: Create users (Admin, Technical Supervisor, Other User)
        admin_user = User.query.filter_by(username='testadmin').first()
        if not admin_user:
            admin_user = User(username='testadmin', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin')
            db.session.add(admin_user)

        ts_user = User.query.filter_by(username='techsupervisor').first()
        if not ts_user:
            ts_user = User(username='techsupervisor', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='Technical supervisor')
            db.session.add(ts_user)

        other_user = User.query.filter_by(username='otheruser').first()
        if not other_user:
            other_user = User(username='otheruser', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='contractor') # Role doesn't strictly matter here
            db.session.add(other_user)

        # Removed one db.session.commit() here, will commit after all user creations if needed,
        # but the main commit is after all setup.

        # Create a project
        project = Project(name='Filter Test Project TS') # Renamed to avoid collision
        db.session.add(project)
        # Removed db.session.commit() here

        # Grant access to project
        ProjectAccess.query.filter_by(project_id=project.id).delete()
        db.session.add(ProjectAccess(user_id=admin_user.id, project_id=project.id, role='admin'))
        db.session.add(ProjectAccess(user_id=ts_user.id, project_id=project.id, role='Technical supervisor'))
        db.session.add(ProjectAccess(user_id=other_user.id, project_id=project.id, role='contractor'))
        # Removed db.session.commit() here

        # Defect A: Created by TS_User, Last comment by TS_User
        defect_a = Defect(project_id=project.id, description='Defect A by TS', status='open', creator_id=ts_user.id, creation_date=datetime.utcnow())
        db.session.add(defect_a)
        db.session.flush() # Ensure defect_a.id is populated
        comment_a = Comment(defect_id=defect_a.id, user_id=ts_user.id, content='TS comment on Defect A', created_at=datetime.utcnow())
        db.session.add(comment_a)

        # Defect B: Created by Other_User, Last comment by TS_User
        defect_b = Defect(project_id=project.id, description='Defect B by Other', status='open', creator_id=other_user.id, creation_date=datetime.utcnow())
        db.session.add(defect_b)
        db.session.flush() # Ensure defect_b.id is populated
        comment_b = Comment(defect_id=defect_b.id, user_id=ts_user.id, content='TS comment on Defect B', created_at=datetime.utcnow())
        db.session.add(comment_b)

        # Defect C: Created by TS_User, Last comment by Other_User
        defect_c = Defect(project_id=project.id, description='Defect C by TS', status='open', creator_id=ts_user.id, creation_date=datetime.utcnow())
        db.session.add(defect_c)
        db.session.flush() # Ensure defect_c.id is populated
        comment_c = Comment(defect_id=defect_c.id, user_id=other_user.id, content='Other comment on Defect C', created_at=datetime.utcnow())
        db.session.add(comment_c)

        # Defect D: Created by TS_User, no comments (should not appear in "OpenWithReply")
        defect_d_no_reply = Defect(project_id=project.id, description='Defect D by TS no reply', status='open', creator_id=ts_user.id, creation_date=datetime.utcnow())
        db.session.add(defect_d_no_reply)

        # Defect E: Created by Other_User, last comment by Other_User (should not appear)
        defect_e = Defect(project_id=project.id, description='Defect E by Other', status='open', creator_id=other_user.id, creation_date=datetime.utcnow())
        db.session.add(defect_e)
        db.session.flush() # Ensure defect_e.id is populated
        comment_e = Comment(defect_id=defect_e.id, user_id=other_user.id, content='Other comment on Defect E', created_at=datetime.utcnow())
        db.session.add(comment_e)

        db.session.commit() # Commit all DB setup once at the end of this block

        # Log in as TS_User (or any user, filter logic is independent of viewing user for this rule)
        # Assuming 'auth' fixture has a login method similar to the 'login' utility function used elsewhere
        # If 'auth' is from Flask-Login or similar, it might be auth.login_user(ts_user)
        # For consistency with other tests, using the login utility if test_client is available or adapting auth.
        # The provided snippet used `auth.login(username='techsupervisor', password='password')`
        # This implies 'auth' is a fixture that provides this method.
        # 'client' fixture is also passed, which is standard for Flask tests.

        # The test signature includes 'client', 'auth', 'app'.
        # The existing tests use `login(test_client, username, password)`.
        # I will assume `auth` has a similar `login` method or adapt if `client` is the test_client.
        # For now, I'll use the provided `auth.login` call.

        login(test_client, 'techsupervisor', 'password') # Use the existing login helper

        response = test_client.get(f'/project/{project.id}?filter=OpenWithReply') # Changed client to test_client
        assert response.status_code == 200

        response_data = response.get_data(as_text=True)

        # Expected: Defect A (creator=TS, last_reply=TS) should NOT be visible.
        assert defect_a.description not in response_data, "Defect A (creator=TS, last_reply=TS) should NOT be visible"

        # Expected: Defect B (creator=Other, last_reply=TS) SHOULD be visible.
        assert defect_b.description in response_data, "Defect B (creator=Other, last_reply=TS) SHOULD be visible"

        # Expected: Defect C (creator=TS, last_reply=Other) SHOULD be visible.
        assert defect_c.description in response_data, "Defect C (creator=TS, last_reply=Other) SHOULD be visible"

        # Expected: Defect D (no reply) should NOT be visible
        assert defect_d_no_reply.description not in response_data, "Defect D (no reply) should NOT be visible"

        # Expected: Defect E (creator=Other, last_reply=Other) should NOT be visible
        assert defect_e.description not in response_data, "Defect E (creator=Other, last_reply=Other) should NOT be visible"
        logout(test_client) # Added logout


def test_tech_supervisor_can_access_template_pages(test_client):
    login(test_client, 'tech_supervisor', 'password')

    response_list = test_client.get('/templates')
    assert response_list.status_code == 200
    assert b"Checklist Templates" in response_list.data

    response_add_get = test_client.get('/add_template')
    assert response_add_get.status_code == 200
    assert b"Add New Checklist Template" in response_add_get.data

    # Create a dummy template for editing
    template = Template(name="TS Dummy Template for Edit Page Access")
    db.session.add(template)
    db.session.commit()
    response_edit_get = test_client.get(f'/template/{template.id}/edit')
    assert response_edit_get.status_code == 200
    assert b"Edit Checklist Template" in response_edit_get.data
    assert template.name.encode() in response_edit_get.data

    db.session.delete(template) # Clean up
    db.session.commit()
    logout(test_client)

def test_tech_supervisor_can_add_template(test_client):
    login(test_client, 'tech_supervisor', 'password')
    template_name = "TS Added Template"
    template_items = "Item 1,Item 2, Item 3"
    response = test_client.post('/add_template', data=dict(
        name=template_name,
        items=template_items
    ), follow_redirects=True)
    assert response.status_code == 200
    assert "Template added successfully!" in response.get_data(as_text=True)

    new_template = Template.query.filter_by(name=template_name).first()
    assert new_template is not None
    assert len(new_template.items) == 3
    assert new_template.items[0].item_text == "Item 1"
    logout(test_client)

def test_tech_supervisor_can_edit_template(test_client):
    # Create a template first
    template_to_edit = Template(name="TS Original Template Name", items=[
        TemplateItem(item_text="Original Item 1"),
        TemplateItem(item_text="Original Item 2")
    ])
    db.session.add(template_to_edit)
    db.session.commit()
    template_id = template_to_edit.id

    login(test_client, 'tech_supervisor', 'password')

    edited_name = "TS Edited Template Name"
    edited_items = "Edited Item A,Edited Item B"
    response = test_client.post(f'/template/{template_id}/edit', data=dict(
        name=edited_name,
        items=edited_items
    ), follow_redirects=True)
    assert response.status_code == 200
    assert "Template updated successfully!" in response.get_data(as_text=True)

    edited_template = Template.query.get(template_id)
    assert edited_template is not None
    assert edited_template.name == edited_name
    assert len(edited_template.items) == 2
    assert edited_template.items[0].item_text == "Edited Item A"
    logout(test_client)

def test_tech_supervisor_can_delete_template(test_client):
    # Create a template to delete
    template_to_delete = Template(name="TS Template To Delete")
    db.session.add(template_to_delete)
    db.session.commit()
    template_id = template_to_delete.id

    login(test_client, 'tech_supervisor', 'password')
    response = test_client.post(f'/template/{template_id}/delete', follow_redirects=True)
    assert response.status_code == 200
    assert "Template deleted successfully!" in response.get_data(as_text=True)

    deleted_template = Template.query.get(template_id)
    assert deleted_template is None
    logout(test_client)

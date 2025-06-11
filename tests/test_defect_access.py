import os
import tempfile
import pytest
from app import app, db, User, Project, Defect, ProjectAccess, bcrypt, Template, TemplateItem, Checklist
from flask_login import login_user, logout_user, current_user
from datetime import datetime
from unittest.mock import patch, MagicMock


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
    defect_by_admin = Defect.query.filter_by(description='Defect by Admin').first()
    defect_by_expert1 = Defect.query.filter_by(description='Defect by Expert 1').first()
    defect_by_tech_supervisor = Defect.query.filter_by(description='Defect by Tech Supervisor').first()

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
    assert b"Add Checklist to " + project1.name.encode() in response.data # Check for page title or header
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

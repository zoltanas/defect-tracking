import os
import tempfile
import pytest
from app import app, db, User, Project, Defect, ProjectAccess, bcrypt
from flask_login import login_user, logout_user, current_user
from datetime import datetime

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

            db.session.add_all([admin_user, expert_user1, expert_user2])
            db.session.commit()

            # Create a project
            project1 = Project(name='Test Project 1')
            db.session.add(project1)
            db.session.commit()

            # Grant access
            access_admin = ProjectAccess(user_id=admin_user.id, project_id=project1.id, role='admin')
            access_expert1 = ProjectAccess(user_id=expert_user1.id, project_id=project1.id, role='expert')
            access_expert2 = ProjectAccess(user_id=expert_user2.id, project_id=project1.id, role='expert')
            db.session.add_all([access_admin, access_expert1, access_expert2])
            db.session.commit()

            # Create defects
            defect_by_admin = Defect(project_id=project1.id, description='Defect by Admin', creator_id=admin_user.id, creation_date=datetime.now())
            defect_by_expert1 = Defect(project_id=project1.id, description='Defect by Expert 1', creator_id=expert_user1.id, creation_date=datetime.now())
            defect_by_expert2 = Defect(project_id=project1.id, description='Defect by Expert 2', creator_id=expert_user2.id, creation_date=datetime.now())
            db.session.add_all([defect_by_admin, defect_by_expert1, defect_by_expert2])
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

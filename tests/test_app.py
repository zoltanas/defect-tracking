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

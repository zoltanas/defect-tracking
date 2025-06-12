import pytest
from app import app, db, User, Project, ProjectAccess, Defect, Comment, Checklist, ChecklistItem, bcrypt
from flask import url_for, session
from datetime import datetime

@pytest.fixture(scope='module')
def test_client_module():
    app.config['TESTING'] = True
    # Use a unique name for the test database file if not using in-memory
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_project_features.db'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key-features'
    app.config['LOGIN_DISABLED'] = False # Ensure login is enabled
    app.config['SERVER_NAME'] = 'localhost.test' # Added to allow url_for outside request context
    app.config['APPLICATION_ROOT'] = '/'
    app.config['PREFERRED_URL_SCHEME'] = 'http'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Create a default admin user for login
            admin_user = User.query.filter_by(username='testadmin_features').first()
            if not admin_user:
                hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
                admin_user = User(username='testadmin_features', password=hashed_password, role='admin')
                db.session.add(admin_user)
                db.session.commit()
        yield client
        with app.app_context():
            db.session.remove() # Close session
            db.drop_all() # Drop all tables
    # import os # Uncomment if using file-based SQLite and want to delete it
    # os.unlink('test_project_features.db') # Uncomment to delete db file

@pytest.fixture(scope='function')
def test_client(test_client_module):
    # This fixture will run for each test function, ensuring a clean state for web requests
    # but using the module-level DB setup.
    # If tests modify DB and need isolation, they should handle cleanup.

    # This fixture now just yields the client from the module-level fixture.
    # Login will be handled by individual tests or a separate login fixture if needed.
    yield test_client_module

    # Optional: Logout after each test if needed, or rely on next test's login
    # test_client_module.get(url_for('logout'), follow_redirects=True)


@pytest.fixture(scope='function')
def current_test_user(test_client): # Depends on test_client to ensure app context
    with app.app_context(): # Ensure we are in an app context for DB queries
        user = User.query.filter_by(username='testadmin_features').first()
        if not user: # Should have been created by test_client_module
            raise RuntimeError("Default test user 'testadmin_features' not found.")
    return user


def clear_test_data(user_to_keep=None):
    """Clears all data from tables, optionally keeping one user."""
    with app.app_context():
        # Delete in order to respect foreign keys
        ProjectAccess.query.delete()
        Comment.query.delete()
        ChecklistItem.query.delete()
        # Assuming DefectMarker is not explicitly tested here but might be linked
        # from Defect model, and Attachment from Defect/Comment/ChecklistItem
        if 'DefectMarker' in db.metadata.tables: # Check if model exists
            # Correct way to access table for deletion if using SQLAlchemy core table object
            # For ORM objects, it's simpler: DefectMarker.query.delete() if DefectMarker model is imported
            # Assuming DefectMarker model might not be imported directly in this test file for now.
             defect_marker_table = db.metadata.tables.get('defect_markers')
             if defect_marker_table is not None:
                db.session.execute(defect_marker_table.delete())
        if 'Attachment' in db.metadata.tables:
            attachment_table = db.metadata.tables.get('attachments')
            if attachment_table is not None:
                db.session.execute(attachment_table.delete())


        Defect.query.delete()
        Checklist.query.delete()
        Project.query.delete()

        # Handle Users
        user_query = User.query
        if user_to_keep:
            user_query = user_query.filter(User.id != user_to_keep.id)
        user_query.delete()

        db.session.commit()

@pytest.fixture(autouse=True) # Automatically use this fixture for every test in this file
def auto_clear_data_and_recreate_admin(test_client, current_test_user): # Depends on test_client for app_context
    # This will run before each test
    clear_test_data(user_to_keep=current_test_user) # Keep the logged-in user

    # Ensure the default user for login still exists or is recreated if somehow deleted
    # This is a safeguard; clear_test_data should already preserve it.
    with app.app_context():
        user = User.query.filter_by(username=current_test_user.username).first()
        if not user:
            hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
            new_user = User(username=current_test_user.username, password=hashed_password, role='admin')
            db.session.add(new_user)
            db.session.commit()
            # Update current_test_user to be this new instance if it was recreated
            # This is tricky; better to ensure clear_test_data handles preservation correctly.

    yield # Test runs here

    # Teardown after test (already handled by clearing before next test)


def test_project_list_no_projects(test_client, current_test_user):
    """Test the project list page when there are no projects for the user."""
    with app.app_context(): # Needed for url_for
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    with app.app_context(): # Needed for url_for
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    assert b"No projects" in response.data
    assert b"Get started by creating a new project." in response.data


def test_project_list_with_all_stats_positive(test_client, current_test_user):
    """Test project list with a project having open defects, replies, and open checklists."""
    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    # 1. Create Project and Access
    project1 = Project(name="Project Alpha")
    db.session.add(project1)
    db.session.commit()
    access1 = ProjectAccess(user_id=current_test_user.id, project_id=project1.id, role='admin')
    db.session.add(access1)
    db.session.commit()

    # 2. Defects for Project Alpha
    defect1_p1 = Defect(project_id=project1.id, description="Open Defect 1 P1", status='open', creator_id=current_test_user.id, creation_date=datetime.utcnow())
    db.session.add(defect1_p1)
    db.session.commit() # Commit to get defect1_p1.id
    comment1_d1_p1 = Comment(defect_id=defect1_p1.id, user_id=current_test_user.id, content="A reply")
    db.session.add(comment1_d1_p1)

    defect2_p1 = Defect(project_id=project1.id, description="Open Defect 2 P1", status='open', creator_id=current_test_user.id, creation_date=datetime.utcnow())
    db.session.add(defect2_p1)

    defect3_p1 = Defect(project_id=project1.id, description="Closed Defect 3 P1", status='closed', creator_id=current_test_user.id, creation_date=datetime.utcnow())
    db.session.add(defect3_p1)
    db.session.commit()

    # 3. Checklists for Project Alpha
    checklist1_p1 = Checklist(project_id=project1.id, name="Checklist 1 P1", creation_date=datetime.utcnow())
    db.session.add(checklist1_p1)
    db.session.commit() # Commit to get checklist1_p1.id
    cl_item1_c1_p1 = ChecklistItem(checklist_id=checklist1_p1.id, item_text="Item 1", is_checked=False)
    cl_item2_c1_p1 = ChecklistItem(checklist_id=checklist1_p1.id, item_text="Item 2", is_checked=True)
    db.session.add_all([cl_item1_c1_p1, cl_item2_c1_p1])

    checklist2_p1 = Checklist(project_id=project1.id, name="Checklist 2 P1", creation_date=datetime.utcnow())
    db.session.add(checklist2_p1)
    db.session.commit() # Commit to get checklist2_p1.id
    cl_item1_c2_p1 = ChecklistItem(checklist_id=checklist2_p1.id, item_text="Item A", is_checked=True)
    cl_item2_c2_p1 = ChecklistItem(checklist_id=checklist2_p1.id, item_text="Item B", is_checked=True)
    db.session.add_all([cl_item1_c2_p1, cl_item2_c2_p1])
    db.session.commit()

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    response_data = response.data.decode('utf-8')

    assert "Project Alpha" in response_data
    assert "Open Defects: <span class=\"font-semibold\">2</span>" in response_data
    assert "Open Defects with Replies: <span class=\"font-semibold\">1</span>" in response_data
    assert "Open Checklists: <span class=\"font-semibold\">1</span>" in response_data


def test_project_list_no_open_defects(test_client, current_test_user):
    project = Project(name="Project No Open Defects")
    db.session.add(project)
    db.session.commit()
    access = ProjectAccess(user_id=current_test_user.id, project_id=project.id, role='admin')
    db.session.add(access)
    defect_closed = Defect(project_id=project.id, description="Closed one", status='closed', creator_id=current_test_user.id)
    db.session.add(defect_closed)
    db.session.commit()

    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    response_data = response.data.decode('utf-8')
    assert "Project No Open Defects" in response_data
    assert "Open Defects: <span class=\"font-semibold\">0</span>" in response_data
    assert "Open Defects with Replies: <span class=\"font-semibold\">0</span>" in response_data

def test_project_list_open_defects_no_replies(test_client, current_test_user):
    project = Project(name="Project Open No Reply")
    db.session.add(project)
    db.session.commit()
    access = ProjectAccess(user_id=current_test_user.id, project_id=project.id, role='admin')
    db.session.add(access)
    defect_open1 = Defect(project_id=project.id, description="Open no reply 1", status='open', creator_id=current_test_user.id)
    defect_open2 = Defect(project_id=project.id, description="Open no reply 2", status='open', creator_id=current_test_user.id)
    db.session.add_all([defect_open1, defect_open2])
    db.session.commit()

    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    response_data = response.data.decode('utf-8')
    assert "Project Open No Reply" in response_data
    assert "Open Defects: <span class=\"font-semibold\">2</span>" in response_data
    assert "Open Defects with Replies: <span class=\"font-semibold\">0</span>" in response_data

def test_project_list_all_checklists_completed(test_client, current_test_user):
    project = Project(name="Project All Checklists Done")
    db.session.add(project)
    db.session.commit()
    access = ProjectAccess(user_id=current_test_user.id, project_id=project.id, role='admin')
    db.session.add(access)
    checklist_done = Checklist(project_id=project.id, name="Done Checklist")
    db.session.add(checklist_done)
    db.session.commit()
    item_done1 = ChecklistItem(checklist_id=checklist_done.id, item_text="All done 1", is_checked=True)
    item_done2 = ChecklistItem(checklist_id=checklist_done.id, item_text="All done 2", is_checked=True)
    db.session.add_all([item_done1, item_done2])
    db.session.commit()

    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    response_data = response.data.decode('utf-8')
    assert "Project All Checklists Done" in response_data
    assert "Open Checklists: <span class=\"font-semibold\">0</span>" in response_data

def test_project_list_no_defects_or_checklists(test_client, current_test_user):
    project = Project(name="Project Completely Empty")
    db.session.add(project)
    db.session.commit()
    access = ProjectAccess(user_id=current_test_user.id, project_id=project.id, role='admin')
    db.session.add(access)
    db.session.commit()

    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    response_data = response.data.decode('utf-8')
    assert "Project Completely Empty" in response_data
    assert "Open Defects: <span class=\"font-semibold\">0</span>" in response_data
    assert "Open Defects with Replies: <span class=\"font-semibold\">0</span>" in response_data
    assert "Open Checklists: <span class=\"font-semibold\">0</span>" in response_data

def test_project_list_multiple_projects_varied_stats(test_client, current_test_user):
    # Project 1: Some stats
    project1 = Project(name="Multi Project One")
    db.session.add(project1)
    db.session.commit()
    access1 = ProjectAccess(user_id=current_test_user.id, project_id=project1.id, role='admin')
    db.session.add(access1)
    d1_p1 = Defect(project_id=project1.id, description="D1P1 Open", status='open', creator_id=current_test_user.id)
    db.session.add(d1_p1)
    db.session.commit()
    c1_d1_p1 = Comment(defect_id=d1_p1.id, user_id=current_test_user.id, content="Reply D1P1")
    db.session.add(c1_d1_p1)
    # Expected for P1: Open Defects: 1, Open Defects w/ Replies: 1, Open Checklists: 0

    # Project 2: Different stats
    project2 = Project(name="Multi Project Two")
    db.session.add(project2)
    db.session.commit()
    access2 = ProjectAccess(user_id=current_test_user.id, project_id=project2.id, role='admin')
    db.session.add(access2)
    d1_p2 = Defect(project_id=project2.id, description="D1P2 Open", status='open', creator_id=current_test_user.id)
    d2_p2 = Defect(project_id=project2.id, description="D2P2 Open", status='open', creator_id=current_test_user.id)
    db.session.add_all([d1_p2, d2_p2])
    cl1_p2 = Checklist(project_id=project2.id, name="CL1P2")
    db.session.add(cl1_p2)
    db.session.commit()
    cli1_cl1_p2 = ChecklistItem(checklist_id=cl1_p2.id, item_text="Item 1 CL1P2", is_checked=False)
    cli2_cl1_p2 = ChecklistItem(checklist_id=cl1_p2.id, item_text="Item 2 CL1P2", is_checked=True)
    db.session.add_all([cli1_cl1_p2, cli2_cl1_p2])
    # Expected for P2: Open Defects: 2, Open Defects w/ Replies: 0, Open Checklists: 1
    db.session.commit()

    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    response_data = response.data.decode('utf-8')

    # Check Project 1 stats
    assert "Multi Project One" in response_data

    project1_html_segment_index = response_data.find("Multi Project One")
    project2_html_segment_index = response_data.find("Multi Project Two")

    # Determine the segment for Project 1 based on whether Project 2 exists and its position
    p1_segment_end = project2_html_segment_index if project2_html_segment_index > project1_html_segment_index and project1_html_segment_index != -1 else len(response_data)
    p1_segment = response_data[project1_html_segment_index:p1_segment_end] if project1_html_segment_index != -1 else ""


    assert "Open Defects: <span class=\"font-semibold\">1</span>" in p1_segment
    assert "Open Defects with Replies: <span class=\"font-semibold\">1</span>" in p1_segment
    assert "Open Checklists: <span class=\"font-semibold\">0</span>" in p1_segment

    # Check Project 2 stats
    assert "Multi Project Two" in response_data
    if project2_html_segment_index != -1:
        # Determine the segment for Project 2.
        p2_segment_start = project2_html_segment_index
        # This simple slicing might be too greedy if other projects follow P2.
        # A more robust approach would be to find the end of P2's card.
        # For now, we assume P2 is the last relevant card or its stats are unique enough.
        p2_segment = response_data[p2_segment_start:]

        assert "Open Defects: <span class=\"font-semibold\">2</span>" in p2_segment
        assert "Open Defects with Replies: <span class=\"font-semibold\">0</span>" in p2_segment
        assert "Open Checklists: <span class=\"font-semibold\">1</span>" in p2_segment

# Note: The string searching for multiple projects is fragile.
# Using an HTML parsing library like BeautifulSoup in tests would make these assertions more robust.
# For example, find a div for "Multi Project One", then search within that div for the stats.
# This is a common improvement for more complex view testing.

import pytest
from app import app, db, User, Project, ProjectAccess, Defect, Comment, Checklist, ChecklistItem, bcrypt
from flask import url_for, session
from datetime import datetime

@pytest.fixture(scope='module')
def test_client_module():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test_project_features.db'
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'test-secret-key-features'
    app.config['LOGIN_DISABLED'] = False
    app.config['SERVER_NAME'] = 'localhost.test'
    app.config['APPLICATION_ROOT'] = '/'
    app.config['PREFERRED_URL_SCHEME'] = 'http'

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            admin_user = User.query.filter_by(username='testadmin_features').first()
            if not admin_user:
                hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
                admin_user = User(username='testadmin_features', password=hashed_password, role='admin')
                db.session.add(admin_user)
                db.session.commit()
        yield client
        with app.app_context():
            db.session.remove()
            db.drop_all()

@pytest.fixture(scope='function')
def test_client(test_client_module):
    yield test_client_module

@pytest.fixture(scope='function')
def current_test_user():
    with app.app_context():
        user = User.query.filter_by(username='testadmin_features').first()
        if not user: # Should be created by test_client_module or auto_clear_data
            hashed_password = bcrypt.generate_password_hash('password').decode('utf-8')
            user = User(username='testadmin_features', password=hashed_password, role='admin')
            db.session.add(user)
            db.session.commit()
    return user

@pytest.fixture(scope='function')
def other_user():
    with app.app_context():
        user = User.query.filter_by(username='other_user_features').first()
        if not user:
            hashed_password = bcrypt.generate_password_hash('password_other').decode('utf-8')
            user = User(username='other_user_features', password=hashed_password, role='contractor')
            db.session.add(user)
            db.session.commit()
    return user

def clear_test_data(usernames_to_keep=None):
    """Clears all data from tables, optionally keeping users with specified usernames."""
    with app.app_context():
        ProjectAccess.query.delete()
        Comment.query.delete()
        ChecklistItem.query.delete()

        defect_marker_table = db.metadata.tables.get('defect_markers')
        if defect_marker_table is not None:
            db.session.execute(defect_marker_table.delete())

        attachment_table = db.metadata.tables.get('attachments')
        if attachment_table is not None:
            db.session.execute(attachment_table.delete())

        Defect.query.delete()
        Checklist.query.delete()
        Project.query.delete()

        user_query = User.query
        if usernames_to_keep:
            user_query = user_query.filter(User.username.notin_(usernames_to_keep))
        user_query.delete()

        db.session.commit()

@pytest.fixture(autouse=True)
def auto_ensure_users_and_clear_data(test_client): # Depends on test_client for app_context
    with app.app_context():
        preserved_usernames = ['testadmin_features', 'other_user_features']
        clear_test_data(usernames_to_keep=preserved_usernames) # Clear first

        # Ensure preserved users exist
        user_configs = [
            {'username': 'testadmin_features', 'password': 'password', 'role': 'admin'},
            {'username': 'other_user_features', 'password': 'password_other', 'role': 'contractor'}
        ]
        for config in user_configs:
            user_instance = User.query.filter_by(username=config['username']).first()
            if not user_instance:
                hashed_password = bcrypt.generate_password_hash(config['password']).decode('utf-8')
                new_user_instance = User(username=config['username'], password=hashed_password, role=config['role'])
                db.session.add(new_user_instance)
        db.session.commit()
    yield


def test_project_list_no_projects(test_client, current_test_user):
    """Test the project list page when there are no projects for the user."""
    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    assert b"No projects" in response.data
    assert b"Get started by creating a new project." in response.data


def test_project_list_with_all_stats_positive(test_client, current_test_user, other_user):
    """Test project list with a project having open defects, replies (from other user), and open checklists."""
    current_user_id = current_test_user.id
    other_user_id = other_user.id

    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    project1 = Project(name="Project Alpha")
    db.session.add(project1)
    db.session.commit()
    access1 = ProjectAccess(user_id=current_user_id, project_id=project1.id, role='admin')
    db.session.add(access1)

    d1 = Defect(project_id=project1.id, description="D1 Open, reply by other", status='open', creator_id=current_user_id)
    db.session.add(d1)
    db.session.commit()
    c1_d1 = Comment(defect_id=d1.id, user_id=current_user_id, content="My initial comment", created_at=datetime(2023,1,1,10,0,0))
    c2_d1 = Comment(defect_id=d1.id, user_id=other_user_id, content="Reply from other user", created_at=datetime(2023,1,1,11,0,0))
    db.session.add_all([c1_d1, c2_d1])

    d2 = Defect(project_id=project1.id, description="D2 Open, reply by self", status='open', creator_id=current_user_id)
    db.session.add(d2)
    db.session.commit()
    c1_d2 = Comment(defect_id=d2.id, user_id=other_user_id, content="Initial comment by other", created_at=datetime(2023,1,2,10,0,0))
    c2_d2 = Comment(defect_id=d2.id, user_id=current_user_id, content="My reply to other", created_at=datetime(2023,1,2,11,0,0))
    db.session.add_all([c1_d2, c2_d2])

    d3 = Defect(project_id=project1.id, description="D3 Open, no reply", status='open', creator_id=current_user_id)
    db.session.add(d3)

    d4 = Defect(project_id=project1.id, description="D4 Closed, with reply", status='closed', creator_id=current_user_id)
    db.session.add(d4)
    db.session.commit()
    c_d4 = Comment(defect_id=d4.id, user_id=other_user_id, content="Comment on closed defect")
    db.session.add(c_d4)

    db.session.commit()

    checklist1_p1 = Checklist(project_id=project1.id, name="Checklist 1 P1", creation_date=datetime.utcnow())
    db.session.add(checklist1_p1)
    db.session.commit()
    cl_item1_c1_p1 = ChecklistItem(checklist_id=checklist1_p1.id, item_text="Item 1", is_checked=False)
    cl_item2_c1_p1 = ChecklistItem(checklist_id=checklist1_p1.id, item_text="Item 2", is_checked=True)
    db.session.add_all([cl_item1_c1_p1, cl_item2_c1_p1])

    checklist2_p1 = Checklist(project_id=project1.id, name="Checklist 2 P1", creation_date=datetime.utcnow())
    db.session.add(checklist2_p1)
    db.session.commit()
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
    assert "Open Defects: <span class=\"font-semibold\">3</span>" in response_data
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

def test_project_list_multiple_projects_varied_stats(test_client, current_test_user, other_user):
    current_user_id = current_test_user.id
    other_user_id = other_user.id

    project1 = Project(name="Multi Project One")
    db.session.add(project1)
    db.session.commit()
    access1 = ProjectAccess(user_id=current_user_id, project_id=project1.id, role='admin')
    db.session.add(access1)
    d1_p1 = Defect(project_id=project1.id, description="D1P1 Open", status='open', creator_id=current_user_id)
    db.session.add(d1_p1)
    db.session.commit()
    c1_d1_p1 = Comment(defect_id=d1_p1.id, user_id=current_user_id, content="Reply D1P1")
    db.session.add(c1_d1_p1) # Explicitly add comment

    project2 = Project(name="Multi Project Two")
    db.session.add(project2)
    db.session.commit()
    access2 = ProjectAccess(user_id=current_user_id, project_id=project2.id, role='admin')
    db.session.add(access2)
    d1_p2 = Defect(project_id=project2.id, description="D1P2 Open", status='open', creator_id=current_user_id)
    d2_p2 = Defect(project_id=project2.id, description="D2P2 Open", status='open', creator_id=current_user_id)
    db.session.add_all([d1_p2, d2_p2])
    db.session.commit()
    c1_d1_p2 = Comment(defect_id=d1_p2.id, user_id=other_user_id, content="Reply from other on D1P2")
    db.session.add(c1_d1_p2)

    cl1_p2 = Checklist(project_id=project2.id, name="CL1P2")
    db.session.add(cl1_p2)
    db.session.commit()
    cli1_cl1_p2 = ChecklistItem(checklist_id=cl1_p2.id, item_text="Item 1 CL1P2", is_checked=False)
    cli2_cl1_p2 = ChecklistItem(checklist_id=cl1_p2.id, item_text="Item 2 CL1P2", is_checked=True)
    db.session.add_all([cli1_cl1_p2, cli2_cl1_p2])
    db.session.commit()

    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    response_data = response.data.decode('utf-8')

    project1_html_segment_index = response_data.find("Multi Project One")
    project2_html_segment_index = response_data.find("Multi Project Two")

    p1_segment_end = project2_html_segment_index if project2_html_segment_index > project1_html_segment_index and project1_html_segment_index != -1 else len(response_data)
    p1_segment = response_data[project1_html_segment_index:p1_segment_end] if project1_html_segment_index != -1 else ""

    assert "Open Defects: <span class=\"font-semibold\">1</span>" in p1_segment
    assert "Open Defects with Replies: <span class=\"font-semibold\">0</span>" in p1_segment
    assert "Open Checklists: <span class=\"font-semibold\">0</span>" in p1_segment

    if project2_html_segment_index != -1:
        p2_segment_start = project2_html_segment_index
        p2_segment = response_data[p2_segment_start:]

        assert "Open Defects: <span class=\"font-semibold\">2</span>" in p2_segment
        assert "Open Defects with Replies: <span class=\"font-semibold\">1</span>" in p2_segment
        assert "Open Checklists: <span class=\"font-semibold\">1</span>" in p2_segment

def test_open_defects_with_reply_count_scenarios(test_client, current_test_user, other_user):
    current_user_id = current_test_user.id
    other_user_id = other_user.id

    with app.app_context():
        login_url = url_for('login')
    test_client.post(login_url, data={'username': current_test_user.username, 'password': 'password'}, follow_redirects=True)

    project = Project(name="Reply Scenarios Project")
    db.session.add(project)
    db.session.commit()
    access = ProjectAccess(user_id=current_user_id, project_id=project.id, role='admin')
    db.session.add(access)
    db.session.commit()

    d1 = Defect(project_id=project.id, description="D1 no comments", status='open', creator_id=current_user_id)
    db.session.add(d1)

    d2 = Defect(project_id=project.id, description="D2 last comment by self", status='open', creator_id=current_user_id)
    db.session.add(d2)
    db.session.commit()
    c_d2 = Comment(defect_id=d2.id, user_id=current_user_id, content="Self comment", created_at=datetime(2023,1,1,10,0,0))
    db.session.add(c_d2)

    d3 = Defect(project_id=project.id, description="D3 last comment by other", status='open', creator_id=current_user_id)
    db.session.add(d3)
    db.session.commit()
    c_d3 = Comment(defect_id=d3.id, user_id=other_user_id, content="Other comment", created_at=datetime(2023,1,2,10,0,0))
    db.session.add(c_d3)

    d4 = Defect(project_id=project.id, description="D4 multi comments, last by self", status='open', creator_id=current_user_id)
    db.session.add(d4)
    db.session.commit()
    c1_d4 = Comment(defect_id=d4.id, user_id=other_user_id, content="Other first", created_at=datetime(2023,1,3,10,0,0))
    c2_d4 = Comment(defect_id=d4.id, user_id=current_user_id, content="Self last", created_at=datetime(2023,1,3,11,0,0))
    db.session.add_all([c1_d4, c2_d4])

    d5 = Defect(project_id=project.id, description="D5 multi comments, last by other", status='open', creator_id=current_user_id)
    db.session.add(d5)
    db.session.commit()
    c1_d5 = Comment(defect_id=d5.id, user_id=current_user_id, content="Self first", created_at=datetime(2023,1,4,10,0,0))
    c2_d5 = Comment(defect_id=d5.id, user_id=other_user_id, content="Other last", created_at=datetime(2023,1,4,11,0,0))
    db.session.add_all([c1_d5, c2_d5])

    db.session.commit()

    with app.app_context():
        index_url = url_for('index')
    response = test_client.get(index_url)
    assert response.status_code == 200
    response_data = response.data.decode('utf-8')

    assert "Reply Scenarios Project" in response_data
    assert "Open Defects: <span class=\"font-semibold\">5</span>" in response_data
    assert "Open Defects with Replies: <span class=\"font-semibold\">2</span>" in response_data

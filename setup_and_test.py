import requests
import sqlite3
import os
from app import app, db, User, Project, ProjectAccess, bcrypt

# --- Configuration ---
BASE_URL = "http://127.0.0.1:5000" # Assuming Flask runs on port 5000
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'myapp.db')
# Ensure instance folder exists
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

PROJECT_NAME = "Comprehensive Test Project"

PA_ID_ADMIN2 = None
PA_ID_EXPERT = None

def run_sql(query, params=(), fetch_one=False, fetch_all=False):
    print(f"Executing SQL: {query} with params {params}")
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        result = None
        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
        conn.close()
        print(f"SQL Result: {result}")
        return result
    except Exception as e:
        print(f"SQL Error: {e}")
        return None

def setup_environment():
    global PA_ID_ADMIN2, PA_ID_EXPERT
    print("\n--- 1. Setting up Environment ---")

    # Call /setup_test_data
    try:
        print("Calling /setup_test_data...")
        response = requests.get(f"{BASE_URL}/setup_test_data", timeout=20) # Increased timeout
        response.raise_for_status() # Raise an exception for bad status codes
        print(f"/setup_test_data response: {response.status_code} - {response.text[:200]}")
    except requests.exceptions.RequestException as e:
        print(f"Error calling /setup_test_data: {e}")
        # Attempt to continue, as the DB might be in a usable state or init_db might fix it.
        # Fallback to ensure db is initialized if setup_test_data fails badly
        with app.app_context():
            try:
                db.create_all()
                print("Fallback: db.create_all() executed.")
            except Exception as db_e:
                print(f"Fallback db.create_all() also failed: {db_e}")
                raise # Cannot proceed if DB is not set up

    with app.app_context():
        print("Creating additional users and granting access...")
        # Create testadmin2
        admin2 = User.query.filter_by(username='testadmin2').first()
        if not admin2:
            admin2 = User(username='testadmin2', email='admin2@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Test Admin Two', company='Test Co')
            db.session.add(admin2)
            print("Created user: testadmin2")
        else:
            print("User testadmin2 already exists.")
            if admin2.status != 'active': # Ensure active for tests
                admin2.status = 'active'
                print("Set testadmin2 status to active.")


        # Create testexpert
        expert_user = User.query.filter_by(username='testexpert').first()
        if not expert_user:
            expert_user = User(username='testexpert', email='expert@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert', status='active', name='Test Expert', company='Test Co')
            db.session.add(expert_user)
            print("Created user: testexpert")
        else:
            print("User testexpert already exists.")
            if expert_user.status != 'active': # Ensure active for tests
                expert_user.status = 'active'
                print("Set testexpert status to active.")

        db.session.commit()
        print("Committed new users.")

        admin2_id = User.query.filter_by(username='testadmin2').first().id
        expert_user_id = User.query.filter_by(username='testexpert').first().id

        project = Project.query.filter_by(name=PROJECT_NAME).first()
        if not project:
            print(f"CRITICAL: Project '{PROJECT_NAME}' not found after setup_test_data. Attempting to create.")
            # This indicates an issue with /setup_test_data not creating the project as expected
            project = Project(name=PROJECT_NAME)
            db.session.add(project)
            db.session.commit()
            # Also need to grant testadmin access to it if /setup_test_data failed to do so
            admin1 = User.query.filter_by(username='testadmin').first()
            if admin1 and not ProjectAccess.query.filter_by(user_id=admin1.id, project_id=project.id).first():
                db.session.add(ProjectAccess(user_id=admin1.id, project_id=project.id, role='admin'))
                db.session.commit()
                print(f"Fallback: Created '{PROJECT_NAME}' and granted testadmin access.")


        if project:
            print(f"Identified Project: '{project.name}' (ID: {project.id})")

            # Grant testadmin2 admin access
            pa_admin2_obj = ProjectAccess.query.filter_by(user_id=admin2_id, project_id=project.id).first()
            if not pa_admin2_obj:
                pa_admin2_obj = ProjectAccess(user_id=admin2_id, project_id=project.id, role='admin')
                db.session.add(pa_admin2_obj)
                print(f"Granted admin access to project '{project.name}' for user 'testadmin2'")
            else:
                print(f"User 'testadmin2' already has access to project '{project.name}'. Ensuring role is 'admin'.")
                pa_admin2_obj.role = 'admin' # Ensure role is correct for test

            # Grant testexpert expert access
            pa_expert_obj = ProjectAccess.query.filter_by(user_id=expert_user_id, project_id=project.id).first()
            if not pa_expert_obj:
                pa_expert_obj = ProjectAccess(user_id=expert_user_id, project_id=project.id, role='expert')
                db.session.add(pa_expert_obj)
                print(f"Granted expert access to project '{project.name}' for user 'testexpert'")
            else:
                print(f"User 'testexpert' already has access to project '{project.name}'. Ensuring role is 'expert'.")
                pa_expert_obj.role = 'expert' # Ensure role is correct for test

            db.session.commit()
            print("Committed project access grants.")

            PA_ID_ADMIN2 = ProjectAccess.query.filter_by(user_id=admin2_id, project_id=project.id).first().id
            PA_ID_EXPERT = ProjectAccess.query.filter_by(user_id=expert_user_id, project_id=project.id).first().id

            print(f"PA_ID_ADMIN2: {PA_ID_ADMIN2}")
            print(f"PA_ID_EXPERT: {PA_ID_EXPERT}")
        else:
            print(f"ERROR: Project '{PROJECT_NAME}' could not be found or created. Tests cannot proceed.")
            exit(1)

if __name__ == "__main__":
    setup_environment()

    # Test cases would be run here using curl commands via os.system or subprocess
    # For now, this script only performs the setup.
    # The actual test execution will be done via bash commands.
    print("\nEnvironment setup script finished.")
    print(f"To be used in tests: PA_ID_ADMIN2={PA_ID_ADMIN2}, PA_ID_EXPERT={PA_ID_EXPERT}")

import os
from app import app, db, User, Project, ProjectAccess, bcrypt

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'myapp.db')
PROJECT_NAME = "Comprehensive Test Project"

def setup_roles_and_get_ids():
    pa_id_admin2_project_admin = None
    pa_id_admin3_project_expert = None
    pa_id_expertuser_project_expert = None

    with app.app_context():
        try:
            # Ensure testadmin (id=1) - this user is created by the main setup_and_test.py or /setup_test_data
            admin1 = db.session.get(User, 1)
            if not (admin1 and admin1.username == 'testadmin' and admin1.role == 'admin'):
                print(f"Error: testadmin (id=1, global admin role) not found or not as expected. Please run the main 'setup_and_test.py' or GET '/setup_test_data' first.")
                # Attempt to create/fix testadmin if not present, for robustness of this specific test setup
                if not admin1:
                    admin1 = User(id=1, username='testadmin', email='admin@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Test Admin', company='Test Co')
                    db.session.add(admin1)
                    print("Attempted to create testadmin (id=1).")
                elif admin1.username != 'testadmin':
                     admin1.username = 'testadmin'
                     print("Corrected username for user id 1 to testadmin.")
                elif admin1.role != 'admin':
                    admin1.role = 'admin'
                    print(f"Corrected role for {admin1.username} to admin.")
                db.session.commit()


            project = Project.query.filter_by(name=PROJECT_NAME).first()
            if not project:
                print(f"Error: Project '{PROJECT_NAME}' not found. Creating it.")
                project = Project(name=PROJECT_NAME)
                db.session.add(project)
                # Grant admin1 access if project was just created
                db.session.flush() # Get project.id
                if not ProjectAccess.query.filter_by(user_id=admin1.id, project_id=project.id).first():
                    db.session.add(ProjectAccess(user_id=admin1.id, project_id=project.id, role='admin'))
                db.session.commit()

            project_id = project.id

            # Scenario 1: testadmin2 (global admin) with project-level 'admin' access
            admin2 = User.query.filter_by(username='testadmin2').first()
            if not admin2:
                admin2 = User(username='testadmin2', email='admin2@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Test Admin Two', company='Test Co')
                db.session.add(admin2)
            elif admin2.role != 'admin': # Ensure global admin role
                admin2.role = 'admin'
            db.session.commit() # Commit admin2 to get ID if new, or update role

            pa_admin2 = ProjectAccess.query.filter_by(user_id=admin2.id, project_id=project_id).first()
            if pa_admin2:
                pa_admin2.role = 'admin' # Ensure project-level admin
            else:
                pa_admin2 = ProjectAccess(user_id=admin2.id, project_id=project_id, role='admin')
                db.session.add(pa_admin2)
            db.session.commit()
            pa_id_admin2_project_admin = pa_admin2.id

            # Scenario 2: testadmin3 (global admin) with project-level 'expert' access
            admin3 = User.query.filter_by(username='testadmin3').first()
            if not admin3:
                admin3 = User(username='testadmin3', email='admin3@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin', status='active', name='Test Admin Three', company='Test Co')
                db.session.add(admin3)
            elif admin3.role != 'admin': # Ensure global admin role
                admin3.role = 'admin'
            db.session.commit()

            pa_admin3 = ProjectAccess.query.filter_by(user_id=admin3.id, project_id=project_id).first()
            if pa_admin3:
                pa_admin3.role = 'expert' # Ensure project-level expert
            else:
                pa_admin3 = ProjectAccess(user_id=admin3.id, project_id=project_id, role='expert')
                db.session.add(pa_admin3)
            db.session.commit()
            pa_id_admin3_project_expert = pa_admin3.id

            # Scenario 3: testexpertuser (global expert) with project-level 'expert' access
            expertuser = User.query.filter_by(username='testexpertuser').first()
            if not expertuser:
                expertuser = User(username='testexpertuser', email='expertuser@example.com', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='expert', status='active', name='Test Expert User', company='Test Co')
                db.session.add(expertuser)
            elif expertuser.role != 'expert': # Ensure global expert role
                expertuser.role = 'expert'
            db.session.commit()

            pa_expertuser = ProjectAccess.query.filter_by(user_id=expertuser.id, project_id=project_id).first()
            if pa_expertuser:
                pa_expertuser.role = 'expert' # Ensure project-level expert
            else:
                pa_expertuser = ProjectAccess(user_id=expertuser.id, project_id=project_id, role='expert')
                db.session.add(pa_expertuser)
            db.session.commit()
            pa_id_expertuser_project_expert = pa_expertuser.id

            print(f"PA_ID_ADMIN2_PROJECT_ADMIN:{pa_id_admin2_project_admin}")
            print(f"PA_ID_ADMIN3_PROJECT_EXPERT:{pa_id_admin3_project_expert}")
            print(f"PA_ID_EXPERTUSER_PROJECT_EXPERT:{pa_id_expertuser_project_expert}")

        except Exception as e:
            print(f"DATABASE SETUP ERROR: {e}")
            # Print None for all if there's an error to make downstream checks fail clearly
            print(f"PA_ID_ADMIN2_PROJECT_ADMIN:None")
            print(f"PA_ID_ADMIN3_PROJECT_EXPERT:None")
            print(f"PA_ID_EXPERTUSER_PROJECT_EXPERT:None")

if __name__ == "__main__":
    setup_roles_and_get_ids()

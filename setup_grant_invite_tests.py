import os
from app import app, db, User, Project, ProjectAccess, bcrypt

PROJECT_X_NAME = "ProjectX_GA_Test"
PROJECT_Y_NAME = "ProjectY_GA_Test"

USER_SETUP_CONFIG = {
    "testadmin": {"role": "admin"}, # Will administer X and Y
    "grantexp": {"role": "expert"},  # existing_expert_user
    "grantcon": {"role": "contractor"},# existing_contractor_user
    "grantadm": {"role": "admin"},   # existing_admin_user_for_grant
    "testviewer_expert": {"role": "expert"}
}

def create_or_update_user(username, email, global_role):
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, email=email, password=bcrypt.generate_password_hash('password').decode('utf-8'), role=global_role, status='active', name=username.capitalize(), company="Test Corp Inc.")
        db.session.add(user)
        print(f"Created user: {username} (Role: {global_role}, ID: {user.id})")
    else:
        user.role = global_role
        user.status = 'active' # Ensure active
        print(f"User {username} exists (ID: {user.id}). Ensured role is {global_role} and status active.")
    db.session.commit()
    return user

def create_or_get_project(project_name, admin_user):
    project = Project.query.filter_by(name=project_name).first()
    if not project:
        project = Project(name=project_name)
        db.session.add(project)
        db.session.flush() # Get ID for project
        print(f"Created project: {project_name} (ID: {project.id})")
        # Grant admin_user admin access if project is new
        pa = ProjectAccess(user_id=admin_user.id, project_id=project.id, role='admin')
        db.session.add(pa)
        print(f"Granted {admin_user.username} admin access to new project {project_name}")
    else:
        print(f"Project {project_name} exists (ID: {project.id}).")
        # Ensure admin_user has admin access
        pa = ProjectAccess.query.filter_by(user_id=admin_user.id, project_id=project.id).first()
        if not pa:
            pa = ProjectAccess(user_id=admin_user.id, project_id=project.id, role='admin')
            db.session.add(pa)
            print(f"Granted {admin_user.username} admin access to existing project {project_name}")
        elif pa.role != 'admin':
            pa.role = 'admin'
            print(f"Ensured {admin_user.username} has admin access to existing project {project_name}")
    db.session.commit()
    return project

def main():
    with app.app_context():
        print("--- Starting Setup for Grant/Invite Tests ---")

        # Base admin user who performs actions
        admin_user = create_or_update_user("testadmin", "testadmin@example.com", "admin")
        print(f"ADMIN_USER_ID:{admin_user.id}")

        # Other users
        user_objects = {}
        for username, config in USER_SETUP_CONFIG.items():
            if username == "testadmin": # Already handled
                user_objects[username] = admin_user
                continue
            user = create_or_update_user(username, f"{username}@example.com", config["role"])
            user_objects[username] = user
            print(f"USER_ID_{username.upper()}:{user.id}")

        # Projects, administered by testadmin
        project_x = create_or_get_project(PROJECT_X_NAME, admin_user)
        project_y = create_or_get_project(PROJECT_Y_NAME, admin_user)
        print(f"PROJECT_ID_X:{project_x.id}")
        print(f"PROJECT_ID_Y:{project_y.id}")

        # Grant testviewer_expert access to ProjectX for their test case
        viewer_expert_user = user_objects["testviewer_expert"]
        pa_viewer = ProjectAccess.query.filter_by(user_id=viewer_expert_user.id, project_id=project_x.id).first()
        if not pa_viewer:
            pa_viewer = ProjectAccess(user_id=viewer_expert_user.id, project_id=project_x.id, role='expert')
            db.session.add(pa_viewer)
            print(f"Granted testviewer_expert access to {project_x.name}")
        db.session.commit()

        # Clean up potential pre-existing ProjectAccess for grant test users on these specific projects
        # to ensure a clean slate for grant tests.
        users_for_grant_cleanup = ["grantexp", "grantcon", "grantadm"]
        projects_for_cleanup = [project_x, project_y]
        for username in users_for_grant_cleanup:
            user_obj = user_objects.get(username)
            if user_obj:
                for proj_obj in projects_for_cleanup:
                    ProjectAccess.query.filter_by(user_id=user_obj.id, project_id=proj_obj.id).delete()
        db.session.commit()
        print("Cleaned up pre-existing project access for grant test users on ProjectX and ProjectY.")


        print("--- Setup for Grant/Invite Tests Complete ---")

if __name__ == "__main__":
    # It's beneficial to ensure a completely clean state for some tests.
    # The /setup_test_data endpoint (if called by a previous generic test setup) already does db.drop_all().
    # If this script is run standalone repeatedly, you might want to add drop_all here.
    # For now, it assumes it can build on an existing schema or an empty one.
    with app.app_context():
        try:
            db.create_all() # Ensure tables exist
        except Exception as e:
            print(f"Error during db.create_all(): {e}") # Should not happen if models are fine
    main()

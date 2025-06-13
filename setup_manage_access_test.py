import os
from app import app, db, User, Project, ProjectAccess, bcrypt

PROJECT_ALPHA_NAME = "ProjectAlpha_MA" # Added suffix to avoid collision with other tests
PROJECT_BETA_NAME = "ProjectBeta_MA"
PROJECT_GAMMA_NAME = "ProjectGamma_MA"

USER_CONFIG = {
    "testadmin": {"role": "admin", "projects": {PROJECT_ALPHA_NAME: "admin", PROJECT_BETA_NAME: "admin", PROJECT_GAMMA_NAME: "admin"}},
    "testexpert": {"role": "expert", "projects": {PROJECT_ALPHA_NAME: "expert", PROJECT_BETA_NAME: "expert"}},
    "testcontractor": {"role": "contractor", "projects": {PROJECT_BETA_NAME: "contractor"}},
    "testsupervisor": {"role": "supervisor", "projects": {PROJECT_GAMMA_NAME: "supervisor"}},
    "testuser1": {"role": "contractor", "projects": {PROJECT_ALPHA_NAME: "contractor"}}, # For list testing
    "testuser2": {"role": "expert", "projects": {PROJECT_BETA_NAME: "expert"}},     # For list testing
    "testuser3": {"role": "contractor", "projects": {PROJECT_GAMMA_NAME: "contractor"}}, # For list testing
    "otheradmin": {"role": "admin", "projects": {PROJECT_ALPHA_NAME: "admin"}},   # For admin-revoke test
}

def create_or_update_user(username, email, global_role):
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, email=email, password=bcrypt.generate_password_hash('password').decode('utf-8'), role=global_role, status='active', name=username.capitalize(), company="Test Corp")
        db.session.add(user)
        print(f"Created user: {username} (Role: {global_role})")
    else:
        user.role = global_role # Ensure global role is correct
        user.status = 'active'
        print(f"User {username} exists. Ensured role is {global_role} and status is active.")
    db.session.commit()
    return user

def create_or_get_project(project_name):
    project = Project.query.filter_by(name=project_name).first()
    if not project:
        project = Project(name=project_name)
        db.session.add(project)
        db.session.commit()
        print(f"Created project: {project_name}")
    else:
        print(f"Project {project_name} exists.")
    return project

def grant_project_access(user, project, project_role):
    pa = ProjectAccess.query.filter_by(user_id=user.id, project_id=project.id).first()
    if not pa:
        pa = ProjectAccess(user_id=user.id, project_id=project.id, role=project_role)
        db.session.add(pa)
        print(f"Granted {user.username} '{project_role}' access to {project.name} (PA_ID: {pa.id})")
    else:
        pa.role = project_role # Ensure project role is correct
        print(f"{user.username} already has access to {project.name}. Ensured role is '{project_role}' (PA_ID: {pa.id}).")
    db.session.commit()
    return pa


def main():
    with app.app_context():
        print("--- Starting Test Data Setup for Manage Access Page ---")

        # Call /setup_test_data to ensure a baseline and clean state if needed.
        # This also creates the initial 'testadmin' which might be used as a creator.
        # For this specific test, we ensure users and projects are exactly as needed.
        # Consider if db.drop_all() and init_db() is better here for full isolation.
        # For now, we'll build on existing or create new.

        # Ensure base 'testadmin' exists (used by subsequent tests)
        # This user is usually created by the more generic setup_test_data.py or /setup_test_data endpoint
        base_admin_username = 'testadmin' # This is the user we log in AS
        base_admin = User.query.filter_by(username=base_admin_username).first()
        if not base_admin:
            base_admin = create_or_update_user(base_admin_username, f"{base_admin_username}@example.com", "admin")
        elif base_admin.role != 'admin': # Ensure it's an admin
            base_admin.role = 'admin'
            db.session.commit()
            print(f"Corrected role for base_admin '{base_admin_username}' to admin.")


        projects = {}
        for proj_name in [PROJECT_ALPHA_NAME, PROJECT_BETA_NAME, PROJECT_GAMMA_NAME]:
            projects[proj_name] = create_or_get_project(proj_name)

        user_objects = {}
        project_access_ids = {}

        for username, config in USER_CONFIG.items():
            user = create_or_update_user(username, f"{username}@example.com", config["role"])
            user_objects[username] = user

            for proj_name, project_role in config["projects"].items():
                project = projects[proj_name]
                pa = grant_project_access(user, project, project_role)
                # Store PA ID for specific combinations needed for assertions
                # Key: username_projectname_projectrole
                project_access_ids[f"{username}_{proj_name}"] = pa.id

        db.session.commit() # Final commit for any pending changes.

        print("\n--- User IDs ---")
        for username, user_obj in user_objects.items():
            print(f"USER_ID_{username.upper()}:{user_obj.id}")

        print("\n--- Project IDs ---")
        for proj_name, proj_obj in projects.items():
            print(f"PROJECT_ID_{proj_name.upper()}:{proj_obj.id}")

        print("\n--- Project Access IDs (for analysis) ---")
        # Specifically print out the ones mentioned in the test plan for clarity
        # These are the PA IDs for the users being *viewed* in the table
        print(f"PA_ID_OTHERADMIN_PROJECTALPHA:{project_access_ids.get('otheradmin_ProjectAlpha_MA')}")
        print(f"PA_ID_TESTEXPERT_PROJECTALPHA:{project_access_ids.get('testexpert_ProjectAlpha_MA')}")
        print(f"PA_ID_TESTEXPERT_PROJECTBETA:{project_access_ids.get('testexpert_ProjectBeta_MA')}")
        print(f"PA_ID_TESTCONTRACTOR_PROJECTBETA:{project_access_ids.get('testcontractor_ProjectBeta_MA')}")
        print(f"PA_ID_TESTSUPERVISOR_PROJECTGAMMA:{project_access_ids.get('testsupervisor_ProjectGamma_MA')}")
        print(f"PA_ID_TESTUSER1_PROJECTALPHA:{project_access_ids.get('testuser1_ProjectAlpha_MA')}")
        print(f"PA_ID_TESTUSER2_PROJECTBETA:{project_access_ids.get('testuser2_ProjectBeta_MA')}")
        print(f"PA_ID_TESTUSER3_PROJECTGAMMA:{project_access_ids.get('testuser3_ProjectGamma_MA')}")


        print("\n--- Setup Complete ---")

if __name__ == "__main__":
    main()

from app import app, db, User, Project, ProjectAccess, bcrypt

PROJECT_NAME = "Project_TitleTest_MA" # Unique name

def create_or_update_user(username, global_role):
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, email=f"{username}@example.com", password=bcrypt.generate_password_hash('password').decode('utf-8'), role=global_role, status='active', name=username.capitalize(), company="Test Co.")
        db.session.add(user)
        print(f"Created user: {username} (Role: {global_role})")
    else:
        user.role = global_role
        user.status = 'active'
        print(f"User {username} exists. Ensured role {global_role} and status active.")
    db.session.commit()
    return user

def create_or_get_project(project_name, admin_user):
    project = Project.query.filter_by(name=project_name).first()
    if not project:
        project = Project(name=project_name)
        db.session.add(project)
        db.session.flush()
        print(f"Created project: {project_name} (ID: {project.id})")
        pa = ProjectAccess(user_id=admin_user.id, project_id=project.id, role='admin')
        db.session.add(pa)
        print(f"Granted {admin_user.username} admin access to new project {project_name}")
    else:
        print(f"Project {project_name} exists (ID: {project.id}).")
        pa = ProjectAccess.query.filter_by(user_id=admin_user.id, project_id=project.id).first()
        if not pa:
            pa = ProjectAccess(user_id=admin_user.id, project_id=project.id, role='admin')
            db.session.add(pa)
            print(f"Granted {admin_user.username} admin access to existing project {project_name}")
        elif pa.role != 'admin':
            pa.role = 'admin'
            print(f"Ensured {admin_user.username} has admin access to project {project_name}")
    db.session.commit()
    return project

def main():
    with app.app_context():
        print("--- Starting Setup for Title Visibility Test ---")

        # Ensure tables are created
        db.create_all()

        admin_user = create_or_update_user("testadmin", "admin")
        expert_user = create_or_update_user("testexpert", "expert")

        project = create_or_get_project(PROJECT_NAME, admin_user)

        # Grant testexpert access to this project
        pa_expert = ProjectAccess.query.filter_by(user_id=expert_user.id, project_id=project.id).first()
        if not pa_expert:
            pa_expert = ProjectAccess(user_id=expert_user.id, project_id=project.id, role='expert')
            db.session.add(pa_expert)
            print(f"Granted {expert_user.username} expert access to {project.name}")
        elif pa_expert.role != 'expert':
            pa_expert.role = 'expert'
            print(f"Ensured {expert_user.username} has expert access to {project.name}")

        db.session.commit()
        print("--- Title Visibility Test Setup Complete ---")

if __name__ == "__main__":
    main()

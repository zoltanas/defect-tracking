import unittest
import os
from datetime import datetime
from flask import url_for

# Configure app for testing before importing
os.environ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
os.environ['TESTING'] = 'True'
os.environ['WTF_CSRF_ENABLED'] = 'False'
os.environ['SECRET_KEY'] = 'test-secret-key-for-sessions'
os.environ['BCRYPT_LOG_ROUNDS'] = '4' # Speed up hashing for tests

from app import app, db, User, Project, Drawing, Defect, DefectMarker, bcrypt, ProjectAccess

class TestDefectMarkerManagement(unittest.TestCase):

    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Create users with different roles
        admin_user = User(username='test_admin', role='admin', password=bcrypt.generate_password_hash('password').decode('utf-8'))
        expert_user = User(username='test_expert', role='expert', password=bcrypt.generate_password_hash('password').decode('utf-8'))
        db.session.add_all([admin_user, expert_user])
        db.session.commit()
        self.admin_user_id = admin_user.id
        self.expert_user_id = expert_user.id
        
        # Create a project
        project = Project(name="Test Project")
        db.session.add(project)
        db.session.commit()
        self.project_id = project.id

        # Grant access to users for the project
        admin_access = ProjectAccess(user_id=self.admin_user_id, project_id=self.project_id, role='admin')
        expert_access = ProjectAccess(user_id=self.expert_user_id, project_id=self.project_id, role='expert')
        db.session.add_all([admin_access, expert_access])
        db.session.commit()

        # Create a drawing
        drawing = Drawing(project_id=self.project_id, name="Test Drawing", file_path="drawings/test_drawing.pdf")
        db.session.add(drawing)
        db.session.commit()
        self.drawing_id = drawing.id


    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login_user(self, username='test_admin', password='password'):
        return self.client.post(url_for('login'), data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def test_delete_defect_with_marker(self):
        self.login_user(username='test_admin') # Admin role needed for deletion
        
        # Setup: Create defect and marker
        defect = Defect(project_id=self.project_id, description="Defect to delete", creator_id=self.admin_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()
        defect_id = defect.id

        marker = DefectMarker(defect_id=defect_id, drawing_id=self.drawing_id, x=0.1, y=0.1)
        db.session.add(marker)
        db.session.commit()
        marker_id = marker.id

        self.assertIsNotNone(Defect.query.get(defect_id))
        self.assertIsNotNone(DefectMarker.query.get(marker_id))

        # Action: Delete defect
        response = self.client.post(url_for('defect_detail', defect_id=defect_id), data={
            'action': 'delete_defect'
        }, follow_redirects=True)

        # Assertions
        self.assertEqual(response.status_code, 200) # Should redirect to project_detail which is 200
        self.assertIsNone(Defect.query.get(defect_id))
        self.assertIsNone(DefectMarker.query.get(marker_id))
        self.assertIn(b'Defect deleted successfully!', response.data)


    def test_add_marker_when_editing_defect(self):
        self.login_user(username='test_expert') # Expert role can edit
        
        defect = Defect(project_id=self.project_id, description="Initial defect", creator_id=self.expert_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()
        defect_id = defect.id

        self.assertEqual(DefectMarker.query.filter_by(defect_id=defect_id).count(), 0)

        # Action: Edit defect and add marker
        new_description = "Updated defect with marker"
        response = self.client.post(url_for('defect_detail', defect_id=defect_id), data={
            'action': 'edit_defect',
            'description': new_description,
            'status': 'open',
            'drawing_id': str(self.drawing_id),
            'marker_x': '0.5',
            'marker_y': '0.5'
        }, follow_redirects=True)

        # Assertions
        self.assertEqual(response.status_code, 200)
        updated_defect = Defect.query.get(defect_id)
        self.assertEqual(updated_defect.description, new_description)
        
        marker = DefectMarker.query.filter_by(defect_id=defect_id).first()
        self.assertIsNotNone(marker)
        self.assertEqual(marker.drawing_id, self.drawing_id)
        self.assertAlmostEqual(marker.x, 0.5)
        self.assertAlmostEqual(marker.y, 0.5)
        self.assertIn(b'Defect updated successfully!', response.data)

    def test_update_existing_marker_when_editing_defect(self):
        self.login_user(username='test_expert')

        defect = Defect(project_id=self.project_id, description="Defect with marker", creator_id=self.expert_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()
        defect_id = defect.id

        initial_marker = DefectMarker(defect_id=defect_id, drawing_id=self.drawing_id, x=0.2, y=0.2)
        db.session.add(initial_marker)
        db.session.commit()
        marker_id = initial_marker.id

        # Action: Edit defect and update marker coordinates
        response = self.client.post(url_for('defect_detail', defect_id=defect_id), data={
            'action': 'edit_defect',
            'description': defect.description, # No change to description
            'status': defect.status,         # No change to status
            'drawing_id': str(self.drawing_id),
            'marker_x': '0.8',
            'marker_y': '0.8'
        }, follow_redirects=True)

        # Assertions
        self.assertEqual(response.status_code, 200)
        updated_marker = DefectMarker.query.get(marker_id)
        self.assertIsNotNone(updated_marker)
        self.assertAlmostEqual(updated_marker.x, 0.8)
        self.assertAlmostEqual(updated_marker.y, 0.8)
        self.assertEqual(DefectMarker.query.filter_by(defect_id=defect_id).count(), 1) # Still only one marker
        self.assertIn(b'Defect updated successfully!', response.data)

    def test_remove_marker_when_editing_defect(self):
        self.login_user(username='test_expert')

        defect = Defect(project_id=self.project_id, description="Defect to remove marker from", creator_id=self.expert_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()
        defect_id = defect.id

        marker_to_remove = DefectMarker(defect_id=defect_id, drawing_id=self.drawing_id, x=0.3, y=0.3)
        db.session.add(marker_to_remove)
        db.session.commit()
        marker_id = marker_to_remove.id
        
        self.assertIsNotNone(DefectMarker.query.get(marker_id))

        # Action: Edit defect and remove marker by sending empty drawing_id
        updated_description_for_removal_test = "Updated, marker removed"
        response = self.client.post(url_for('defect_detail', defect_id=defect_id), data={
            'action': 'edit_defect',
            'description': updated_description_for_removal_test,
            'status': 'open',
            'drawing_id': '' # Empty drawing_id signals removal
        }, follow_redirects=True)

        # Assertions
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(DefectMarker.query.get(marker_id)) # Marker should be deleted
        self.assertEqual(DefectMarker.query.filter_by(defect_id=defect_id).count(), 0)
        
        updated_defect_after_marker_removal = Defect.query.get(defect_id)
        self.assertIsNotNone(updated_defect_after_marker_removal)
        self.assertEqual(updated_defect_after_marker_removal.description, updated_description_for_removal_test)
        self.assertIn(b'Defect updated successfully!', response.data)


    def test_edit_defect_without_changing_marker(self):
        self.login_user(username='test_expert')

        defect = Defect(project_id=self.project_id, description="Defect with stable marker", creator_id=self.expert_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()
        defect_id = defect.id

        original_x, original_y = 0.6, 0.6
        marker = DefectMarker(defect_id=defect_id, drawing_id=self.drawing_id, x=original_x, y=original_y)
        db.session.add(marker)
        db.session.commit()
        marker_id = marker.id

        # Action: Edit defect description, but keep existing marker data
        new_description_stable_marker = "New Description, marker stays"
        response = self.client.post(url_for('defect_detail', defect_id=defect_id), data={
            'action': 'edit_defect',
            'description': new_description_stable_marker,
            'status': defect.status,
            'drawing_id': str(self.drawing_id), # Existing drawing_id
            'marker_x': str(original_x),       # Existing X
            'marker_y': str(original_y)        # Existing Y
        }, follow_redirects=True)

        # Assertions
        self.assertEqual(response.status_code, 200)
        updated_defect_stable_marker = Defect.query.get(defect_id)
        self.assertEqual(updated_defect_stable_marker.description, new_description_stable_marker)

        marker_after_edit = DefectMarker.query.get(marker_id)
        self.assertIsNotNone(marker_after_edit)
        self.assertEqual(marker_after_edit.drawing_id, self.drawing_id)
        self.assertAlmostEqual(marker_after_edit.x, original_x)
        self.assertAlmostEqual(marker_after_edit.y, original_y)
        self.assertIn(b'Defect updated successfully!', response.data)

if __name__ == '__main__':
    unittest.main()

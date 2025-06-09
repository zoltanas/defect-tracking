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

from io import BytesIO
from unittest.mock import patch, mock_open

from app import app, db, User, Project, Drawing, Defect, DefectMarker, Attachment, bcrypt, ProjectAccess # Added Attachment

class TestDefectMarkerManagement(unittest.TestCase): # Will add Attachment tests here

    def setUp(self):
        self.app = app
        # Configure a separate test upload folder if not relying entirely on mocks
        # For now, we will mock filesystem interactions for attachments.
        # self.app.config['UPLOAD_FOLDER'] = 'tests/test_uploads'
        # os.makedirs(self.app.config['UPLOAD_FOLDER'], exist_ok=True)
        # os.makedirs(os.path.join(self.app.config['UPLOAD_FOLDER'], 'thumbnails'), exist_ok=True)

        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Create users with different roles
        admin_user = User(username='test_admin', role='admin', password=bcrypt.generate_password_hash('password').decode('utf-8'))
        expert_user = User(username='test_expert', role='expert', password=bcrypt.generate_password_hash('password').decode('utf-8'))
        worker_user = User(username='test_worker', role='worker', password=bcrypt.generate_password_hash('password').decode('utf-8'))
        db.session.add_all([admin_user, expert_user, worker_user])
        db.session.commit()
        self.admin_user_id = admin_user.id
        self.expert_user_id = expert_user.id
        self.worker_user_id = worker_user.id
        
        # Create a project
        project = Project(name="Test Project")
        db.session.add(project)
        db.session.commit()
        self.project_id = project.id

        # Grant access to users for the project
        admin_access = ProjectAccess(user_id=self.admin_user_id, project_id=self.project_id, role='admin')
        expert_access = ProjectAccess(user_id=self.expert_user_id, project_id=self.project_id, role='expert')
        worker_access = ProjectAccess(user_id=self.worker_user_id, project_id=self.project_id, role='worker')
        db.session.add_all([admin_access, expert_access, worker_access])
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
        # Clean up test upload folder if it was created
        # if os.path.exists(self.app.config['UPLOAD_FOLDER']) and self.app.config['UPLOAD_FOLDER'] == 'tests/test_uploads':
        #     import shutil
        #     shutil.rmtree(self.app.config['UPLOAD_FOLDER'])


    def login_user(self, username='test_admin', password='password'):
        return self.client.post(url_for('login'), data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def _create_dummy_file_bytes(self, filename="test_image.png", content=b"fake image data"):
        return BytesIO(content), filename

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

    # --- Defect Attachment Tests ---

    @patch('app.create_thumbnail')
    @patch('app.ensure_thumbnail_directory')
    @patch('os.chmod') # To prevent chmod errors on BytesIO during save mock
    @patch('builtins.open', new_callable=mock_open) # Mock open for file.save()
    def test_add_attachment_successfully_as_worker(self, mock_file_open, mock_os_chmod, mock_ensure_thumb_dir, mock_create_thumb):
        self.login_user(username='test_worker', password='password')

        defect = Defect(project_id=self.project_id, description="Defect for attachment", creator_id=self.worker_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()

        dummy_file_bytes, dummy_filename = self._create_dummy_file_bytes(filename="test_upload.jpg")

        data = {
            'attachment_file': (dummy_file_bytes, dummy_filename),
            # 'csrf_token': 'test-csrf-token' # WTF_CSRF_ENABLED is False
        }

        # Mock return value for ensure_thumbnail_directory if it's used to construct paths directly
        mock_ensure_thumb_dir.return_value = os.path.join(self.app.config['UPLOAD_FOLDER'], 'thumbnails')

        response = self.client.post(
            url_for('add_defect_attachment', defect_id=defect.id),
            data=data,
            content_type='multipart/form-data',
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 200)
        json_response = response.json
        self.assertTrue(json_response.get('success'))
        self.assertIn('Attachment added successfully', json_response.get('message', ''))

        attachment = Attachment.query.filter_by(defect_id=defect.id).first()
        self.assertIsNotNone(attachment)
        self.assertIn(dummy_filename, attachment.file_path)
        self.assertTrue(attachment.file_path.startswith('images/'))
        self.assertTrue(attachment.thumbnail_path.startswith('images/thumbnails/thumb_'))
        self.assertIn(dummy_filename, attachment.thumbnail_path)

        # Assert that create_thumbnail was called (or the mocks for file saving within it)
        mock_ensure_thumb_dir.assert_called_once()
        # The actual save path for original is app.config['UPLOAD_FOLDER'] + unique_filename_base
        # The actual save path for thumbnail is thumbnail_dir + thumbnail_filename_base
        # We need to ensure create_thumbnail is called with appropriate paths.
        # Since file.save is mocked by mock_open, we check if it was called.
        mock_file_open.assert_called() # Check if BytesIO.save (which is `file.save` in app code) was called by werkzeug's FileStorage save
        mock_create_thumb.assert_called_once()
        # Example of asserting arguments if needed:
        # args_create_thumb, _ = mock_create_thumb.call_args
        # self.assertTrue(args_create_thumb[0].endswith(dummy_filename)) # original_save_path
        # self.assertTrue(args_create_thumb[1].startswith(os.path.join(self.app.config['UPLOAD_FOLDER'], 'thumbnails', 'thumb_'))) # thumbnail_save_path

    @patch('app.create_thumbnail')
    @patch('app.ensure_thumbnail_directory')
    @patch('os.chmod')
    @patch('builtins.open', new_callable=mock_open)
    def test_add_attachment_invalid_file_type(self, mock_file_open, mock_os_chmod, mock_ensure_thumb_dir, mock_create_thumb):
        self.login_user(username='test_worker', password='password')

        defect = Defect(project_id=self.project_id, description="Defect for invalid attachment", creator_id=self.worker_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()

        dummy_file_bytes, dummy_filename = self._create_dummy_file_bytes(filename="test_invalid.txt", content=b"this is a text file")

        data = {
            'attachment_file': (dummy_file_bytes, dummy_filename)
        }

        response = self.client.post(
            url_for('add_defect_attachment', defect_id=defect.id),
            data=data,
            content_type='multipart/form-data',
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 400) # Expecting Bad Request
        json_response = response.json
        self.assertFalse(json_response.get('success'))
        self.assertEqual(json_response.get('error'), 'File type not allowed.')

        attachment_count = Attachment.query.filter_by(defect_id=defect.id).count()
        self.assertEqual(attachment_count, 0)

        mock_create_thumb.assert_not_called()
        mock_ensure_thumb_dir.assert_not_called() # Should not be called if file type check fails early

    @patch('os.remove')
    @patch('os.path.exists')
    def test_delete_attachment_successfully_as_admin(self, mock_path_exists, mock_os_remove):
        self.login_user(username='test_admin', password='password')

        defect = Defect(project_id=self.project_id, description="Defect for attachment deletion", creator_id=self.admin_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()

        # Create a dummy attachment record and simulate its files existing
        dummy_file_name = "test_delete_image.jpg"
        dummy_thumb_name = "thumb_test_delete_image.jpg"

        # Relative paths as stored in DB
        db_file_path = os.path.join('images', dummy_file_name)
        db_thumbnail_path = os.path.join('images', 'thumbnails', dummy_thumb_name)

        attachment = Attachment(
            defect_id=defect.id,
            file_path=db_file_path,
            thumbnail_path=db_thumbnail_path
        )
        db.session.add(attachment)
        db.session.commit()
        attachment_id = attachment.id

        # Mock os.path.exists to return True for these specific paths
        def side_effect_path_exists(path):
            if path == os.path.join(self.app.static_folder, db_file_path) or \
               path == os.path.join(self.app.static_folder, db_thumbnail_path):
                return True
            return False
        mock_path_exists.side_effect = side_effect_path_exists

        data = {
            'attachment_id': attachment_id,
            # 'csrf_token': 'test-csrf-token' # WTF_CSRF_ENABLED is False
        }

        response = self.client.post(
            url_for('delete_defect_attachment_json', defect_id=defect.id), # Route name from app.py
            data=data,
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 200)
        json_response = response.json
        self.assertTrue(json_response.get('success'))
        self.assertIn('Attachment deleted successfully', json_response.get('message', ''))

        self.assertIsNone(Attachment.query.get(attachment_id))

        # Check that os.remove was called for both files
        expected_remove_calls = [
            os.path.join(self.app.static_folder, db_file_path),
            os.path.join(self.app.static_folder, db_thumbnail_path)
        ]
        # Check if mock_os_remove.call_args_list contains calls with these arguments
        # This is a bit more robust than checking call_count if order might vary or other calls happen
        called_paths = [call_args[0][0] for call_args in mock_os_remove.call_args_list]
        for expected_path in expected_remove_calls:
            self.assertIn(expected_path, called_paths)
        self.assertEqual(mock_os_remove.call_count, 2)

    @patch('os.remove')
    @patch('os.path.exists')
    def test_delete_attachment_role_denied_as_worker(self, mock_path_exists, mock_os_remove):
        self.login_user(username='test_worker', password='password') # Worker role

        defect = Defect(project_id=self.project_id, description="Defect for role test", creator_id=self.admin_user_id, creation_date=datetime.now())
        db.session.add(defect)
        db.session.commit()

        attachment = Attachment(
            defect_id=defect.id,
            file_path='images/dont_delete.jpg',
            thumbnail_path='images/thumbnails/thumb_dont_delete.jpg'
        )
        db.session.add(attachment)
        db.session.commit()
        attachment_id = attachment.id

        data = {
            'attachment_id': attachment_id,
        }

        response = self.client.post(
            url_for('delete_defect_attachment_json', defect_id=defect.id),
            data=data,
            follow_redirects=True
        )

        self.assertEqual(response.status_code, 403) # Forbidden
        json_response = response.json
        self.assertFalse(json_response.get('success'))
        self.assertIn('Permission denied', json_response.get('error', ''))

        self.assertIsNotNone(Attachment.query.get(attachment_id)) # Still exists
        mock_os_remove.assert_not_called()

    def test_delete_non_existent_attachment(self):
        self.login_user(username='test_admin')
        defect = Defect(project_id=self.project_id, description="Defect for non-existent attachment test", creator_id=self.admin_user_id)
        db.session.add(defect)
        db.session.commit()

        data = {'attachment_id': 99999} # Non-existent ID
        response = self.client.post(url_for('delete_defect_attachment_json', defect_id=defect.id), data=data)

        self.assertEqual(response.status_code, 404) # Not Found
        json_response = response.json
        self.assertFalse(json_response.get('success'))
        self.assertIn('Attachment not found', json_response.get('error', ''))

    def test_delete_attachment_from_wrong_defect(self):
        self.login_user(username='test_admin')

        defect1 = Defect(project_id=self.project_id, description="Defect 1", creator_id=self.admin_user_id)
        defect2 = Defect(project_id=self.project_id, description="Defect 2", creator_id=self.admin_user_id)
        db.session.add_all([defect1, defect2])
        db.session.commit()

        attachment_defect1 = Attachment(defect_id=defect1.id, file_path="file1.jpg", thumbnail_path="thumb1.jpg")
        db.session.add(attachment_defect1)
        db.session.commit()

        data = {'attachment_id': attachment_defect1.id}
        # Try to delete attachment_defect1 using defect2's ID in the URL
        response = self.client.post(url_for('delete_defect_attachment_json', defect_id=defect2.id), data=data)

        self.assertEqual(response.status_code, 404) # Attachment not found *for this defect*
        json_response = response.json
        self.assertFalse(json_response.get('success'))
        self.assertIn('Attachment not found or does not belong to this defect', json_response.get('error', ''))

        # Ensure attachment still exists and is linked to defect1
        self.assertIsNotNone(Attachment.query.get(attachment_defect1.id))


if __name__ == '__main__':
    unittest.main()

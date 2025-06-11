import unittest
import os
import tempfile
import shutil # For robust directory removal
from app import app, db, User, Project, Checklist, ChecklistItem, Attachment, ProjectAccess, bcrypt
from flask import url_for
from io import BytesIO
from urllib.parse import urlparse

# Helper to ensure static subdirectories for attachments exist if needed by url_for or file saving logic
def ensure_static_attachment_dirs(static_folder_root):
    # These paths are relative to the 'static' folder as used in app.py
    # This is more about ensuring url_for doesn't fail if it expects these paths.
    # The actual file saving for tests will use a temp folder.
    # Based on app.py add_checklist_item_attachment, paths are 'uploads/attachments_img/'
    img_dir_rel = os.path.join('uploads', 'attachments_img')
    thumb_dir_rel = os.path.join(img_dir_rel, 'thumbnails')

    os.makedirs(os.path.join(static_folder_root, img_dir_rel), exist_ok=True)
    os.makedirs(os.path.join(static_folder_root, thumb_dir_rel), exist_ok=True)


class TestChecklistAsyncFeatures(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['LOGIN_DISABLED'] = False # Ensure login is not disabled for auth tests
        app.config['SERVER_NAME'] = 'localhost.test' # Added for url_for to work in tests
        app.config['APPLICATION_ROOT'] = '/'
        app.config['PREFERRED_URL_SCHEME'] = 'http'

        # Create a temporary directory for all static files for this test run
        self.temp_static_folder = tempfile.mkdtemp()

        # UPLOAD_FOLDER will be a subdirectory within this temp static folder.
        # This mirrors how app.py's ensure_attachment_paths structures things,
        # e.g., static/uploads/attachments_img/
        self.temp_upload_subpath_for_images = os.path.join('uploads', 'attachments_img')
        self.actual_upload_folder_for_images = os.path.join(self.temp_static_folder, self.temp_upload_subpath_for_images)
        os.makedirs(self.actual_upload_folder_for_images, exist_ok=True)

        self.actual_thumbnail_folder_for_images = os.path.join(self.actual_upload_folder_for_images, 'thumbnails')
        os.makedirs(self.actual_thumbnail_folder_for_images, exist_ok=True)

        # app.config['UPLOAD_FOLDER'] is 'static/images' in app.py, used by ensure_thumbnail_directory
        # For ensure_attachment_paths, it uses app.static_folder + 'uploads' + subfolder_name
        # We will override app.static_folder to point to self.temp_static_folder
        app.static_folder = self.temp_static_folder

        # UPLOAD_FOLDER is not directly used by ensure_attachment_paths, but it's good to set it
        # to something consistent if other parts of app were to use it.
        # Let's set it to the base of our temp static structure for clarity if any code defaults to it.
        app.config['UPLOAD_FOLDER'] = self.temp_static_folder


        self.client = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()

        self.user1 = self._create_user(username='user1', password='password1', role='admin')
        self.user2_no_access = self._create_user(username='user2_no_access', password='password2', role='contractor')
        self.project1 = self._create_project(name='Project 1')
        self._grant_access(self.user1.id, self.project1.id, role='admin') # Grant access for user1
        self.checklist1 = self._create_checklist(self.project1.id, name='Checklist 1')
        self.item1 = self._create_checklist_item(self.checklist1.id, text='Item 1')


    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
        shutil.rmtree(self.temp_static_folder)

    def _create_user(self, username='testuser', password='password', role='admin'):
        user = User(username=username, password=bcrypt.generate_password_hash(password).decode('utf-8'), role=role)
        db.session.add(user)
        db.session.commit()
        return user

    def _create_project(self, name='Test Project'):
        project = Project(name=name)
        db.session.add(project)
        db.session.commit()
        return project

    def _grant_access(self, user_id, project_id, role='admin'):
        access = ProjectAccess(user_id=user_id, project_id=project_id, role=role)
        db.session.add(access)
        db.session.commit()

    def _create_checklist(self, project_id, name='Test Checklist'):
        checklist = Checklist(project_id=project_id, name=name)
        db.session.add(checklist)
        db.session.commit()
        return checklist

    def _create_checklist_item(self, checklist_id, text='Test Item', is_checked=False, comments=''):
        item = ChecklistItem(checklist_id=checklist_id, item_text=text, is_checked=is_checked, comments=comments)
        db.session.add(item)
        db.session.commit()
        return item

    def _create_attachment(self, item_id, filename='test.jpg', is_image=True):
        # This helper creates the DB record and dummy files on disk.
        # The file paths stored in DB should be relative to app.static_folder (self.temp_static_folder)
        # as per app.py's add_checklist_item_attachment logic.

        # e.g., db_file_path = os.path.join('uploads', 'attachments_img', unique_filename_base)
        db_file_subpath = os.path.join(self.temp_upload_subpath_for_images, filename)
        db_thumb_subpath = os.path.join(self.temp_upload_subpath_for_images, 'thumbnails', f"thumb_{filename}") if is_image else None

        # Create dummy files on disk within the temp static structure
        full_file_path_on_disk = os.path.join(self.temp_static_folder, db_file_subpath)
        os.makedirs(os.path.dirname(full_file_path_on_disk), exist_ok=True)
        with open(full_file_path_on_disk, 'wb') as f:
            f.write(b"dummy image data" if is_image else b"dummy file data")

        if is_image and db_thumb_subpath:
            full_thumb_path_on_disk = os.path.join(self.temp_static_folder, db_thumb_subpath)
            os.makedirs(os.path.dirname(full_thumb_path_on_disk), exist_ok=True)
            with open(full_thumb_path_on_disk, 'wb') as f:
                f.write(b"dummy thumbnail data")

        attachment = Attachment(
            checklist_item_id=item_id,
            file_path=db_file_subpath, # Stored relative to static folder
            thumbnail_path=db_thumb_subpath # Stored relative to static folder
        )
        db.session.add(attachment)
        db.session.commit()
        return attachment


    def _login(self, username, password):
        return self.client.post(url_for('login'), data=dict(username=username, password=password), follow_redirects=True)

    def _logout(self):
        return self.client.get(url_for('logout'), follow_redirects=True)

    # --- Test Cases ---

    def test_update_status_success(self):
        self._login('user1', 'password1')
        response = self.client.post(url_for('update_checklist_item_status', item_id=self.item1.id), json={'is_checked': True})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertTrue(data['new_status'])
        updated_item = db.session.get(ChecklistItem, self.item1.id) # Use db.session.get
        self.assertTrue(updated_item.is_checked)

    def test_update_status_unauthenticated(self):
        self._logout() # Ensure logged out
        response = self.client.post(url_for('update_checklist_item_status', item_id=self.item1.id), json={'is_checked': True})
        # Unauthenticated access to @login_required routes usually redirects to login (for forms) or returns 401 (for AJAX)
        self.assertIn(response.status_code, [302, 401])
        if response.status_code == 302: # Standard redirect for form-based login
             # print(f"Login URL: {url_for('login')}") # Keep for debugging if needed
             # print(f"Response Location: {response.location}")
             parsed_location = urlparse(response.location)
             expected_path = urlparse(url_for('login')).path # url_for('login') gives relative path
             self.assertEqual(parsed_location.path, expected_path)
        # If it's 401, that's also an acceptable outcome for an AJAX endpoint when unauthenticated.


    def test_update_status_unauthorized(self):
        self._login('user2_no_access', 'password2') # This user has no access to project1
        response = self.client.post(url_for('update_checklist_item_status', item_id=self.item1.id), json={'is_checked': True})
        self.assertEqual(response.status_code, 403)

    def test_update_status_not_found(self):
        self._login('user1', 'password1')
        response = self.client.post(url_for('update_checklist_item_status', item_id=9999), json={'is_checked': True})
        self.assertEqual(response.status_code, 404)

    def test_update_status_csrf_protection(self):
        self._login('user1', 'password1')

        original_csrf_status = app.config['WTF_CSRF_ENABLED']
        app.config['WTF_CSRF_ENABLED'] = True

        try:
            response = self.client.post(
                url_for('update_checklist_item_status', item_id=self.item1.id),
                json={'is_checked': True}
                # No X-CSRFToken header intentionally
            )
            # When CSRF is enforced and no token is provided, Flask-WTF should return 400
            self.assertEqual(response.status_code, 400, "Expected 400 error due to missing CSRF token")
            # Optionally, check response data if a specific error message is expected
            # For example, if response.data is b'CSRF token missing or incorrect.'
            # self.assertIn(b"CSRF token missing", response.data) # Adjust based on actual Flask-WTF response

        finally:
            app.config['WTF_CSRF_ENABLED'] = original_csrf_status

    def test_update_comments_success(self):
        self._login('user1', 'password1')
        new_comment_text = "These are updated comments."
        response = self.client.post(url_for('update_checklist_item_comments', item_id=self.item1.id), json={'comments': new_comment_text})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['new_comments'], new_comment_text)
        updated_item = db.session.get(ChecklistItem, self.item1.id)
        self.assertEqual(updated_item.comments, new_comment_text)

    def test_add_attachment_success(self):
        self._login('user1', 'password1')
        # Minimal valid 1x1 black PNG
        dummy_file_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90\x77\x53\xde\x00\x00\x00\x0cIDAT\x18Wc\x60\x60\x60\x00\x00\x00\x04\x00\x01\xfc\x18\x98\xb7\x00\x00\x00\x00IEND\xaeB`\x82'
        dummy_file = (BytesIO(dummy_file_content), "test_image.png") # Changed to .png

        response = self.client.post(
            url_for('add_checklist_item_attachment', item_id=self.item1.id),
            content_type='multipart/form-data',
            data={'photos': [dummy_file]},
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertIn('attachments', data)
        self.assertEqual(len(data['attachments']), 1)
        attachment_info = data['attachments'][0]
        self.assertIn('id', attachment_info)
        self.assertIn('thumbnail_url', attachment_info)

        db_attachment = db.session.get(Attachment, attachment_info['id'])
        self.assertIsNotNone(db_attachment)
        self.assertEqual(db_attachment.checklist_item_id, self.item1.id)

        expected_file_path_on_disk = os.path.join(self.temp_static_folder, db_attachment.file_path)
        self.assertTrue(os.path.exists(expected_file_path_on_disk))

        if db_attachment.thumbnail_path:
            expected_thumb_path_on_disk = os.path.join(self.temp_static_folder, db_attachment.thumbnail_path)
            self.assertTrue(os.path.exists(expected_thumb_path_on_disk))

    def test_add_multiple_attachments_success(self):
        self._login('user1', 'password1')
        # Minimal valid 1x1 black PNG
        png_content = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90\x77\x53\xde\x00\x00\x00\x0cIDAT\x18Wc\x60\x60\x60\x00\x00\x00\x04\x00\x01\xfc\x18\x98\xb7\x00\x00\x00\x00IEND\xaeB`\x82'
        files_to_upload = [
            (BytesIO(png_content), "image1.png"),
            (BytesIO(png_content), "image2.png")
        ]
        response = self.client.post(
            url_for('add_checklist_item_attachment', item_id=self.item1.id),
            content_type='multipart/form-data',
            data={'photos': files_to_upload},
            follow_redirects=True
        )
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(len(data['attachments']), 2)
        # Further checks for each attachment...
        for att_info in data['attachments']:
            db_att = db.session.get(Attachment, att_info['id'])
            self.assertIsNotNone(db_att)
            disk_path = os.path.join(self.temp_static_folder, db_att.file_path)
            self.assertTrue(os.path.exists(disk_path))
            if db_att.thumbnail_path:
                thumb_disk_path = os.path.join(self.temp_static_folder, db_att.thumbnail_path)
                self.assertTrue(os.path.exists(thumb_disk_path))


    def test_delete_attachment_success(self):
        attachment_to_delete = self._create_attachment(self.item1.id, filename="delete_me.jpg")
        self.assertIsNotNone(db.session.get(Attachment, attachment_to_delete.id))

        full_file_path = os.path.join(self.temp_static_folder, attachment_to_delete.file_path)
        full_thumb_path = os.path.join(self.temp_static_folder, attachment_to_delete.thumbnail_path)
        self.assertTrue(os.path.exists(full_file_path), f"File should exist before delete: {full_file_path}")
        self.assertTrue(os.path.exists(full_thumb_path), f"Thumbnail should exist before delete: {full_thumb_path}")

        self._login('user1', 'password1')
        # The route name in app.py is delete_checklist_item_attachment_ajax
        response = self.client.post(url_for('delete_checklist_item_attachment_ajax', item_id=self.item1.id, attachment_id=attachment_to_delete.id))
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data['success'])

        self.assertIsNone(db.session.get(Attachment, attachment_to_delete.id))
        self.assertFalse(os.path.exists(full_file_path), f"File should be deleted: {full_file_path}")
        self.assertFalse(os.path.exists(full_thumb_path), f"Thumbnail should be deleted: {full_thumb_path}")

if __name__ == '__main__':
    unittest.main(verbosity=2)

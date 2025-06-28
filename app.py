from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import click # For Flask CLI
from sqlalchemy.orm import joinedload # Import joinedload
from threading import Lock
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import shutil
from PIL import Image as PILImage, ImageDraw, ImageOps
import io
from weasyprint import HTML
from pdf2image import convert_from_path # Ensure this is present
import logging
from sqlalchemy import inspect
import tempfile
import zipfile
import glob
from dotenv import load_dotenv
load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if not logger.handlers:
    handler = logging.StreamHandler() # Defaults to stderr
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.DEBUG) # Enabled DEBUG level for report generation diagnostics
# logger.propagate = False # Keep this commented for now
logger.info("Flask application logger explicitly configured for checklist debugging.") # Restored message

# Initialize Flask app
app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'your-secret-key'

# Determine which database to use
USE_SQLITE = os.environ.get('USE_SQLITE', 'False').lower() == 'true'

if USE_SQLITE:
    # Configure for SQLite
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance/myapp.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # SQLite does not require connection pooling options like PostgreSQL
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {}
    print("Using SQLite database.")
else:
    # Configure for PostgreSQL
    default_pg_uri = 'postgresql://pguser:pgpassword@localhost:5432/myappdb'
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', default_pg_uri)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': int(os.environ.get('SQLALCHEMY_POOL_SIZE', 10)),
        'max_overflow': int(os.environ.get('SQLALCHEMY_MAX_OVERFLOW', 20)),
        'pool_recycle': int(os.environ.get('SQLALCHEMY_POOL_RECYCLE', 300)),
        'pool_pre_ping': os.environ.get('SQLALCHEMY_POOL_PRE_PING', 'true').lower() == 'true'
    }
    print("Using PostgreSQL database.")
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['DRAWING_FOLDER'] = 'static/drawings'
app.config['SERIALIZER_SECRET_KEY'] = 'your-serializer-secret-key'
app.config['REPORT_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')

# --- Flask-Mail Configuration ---
# For production, configure these settings via environment variables:
# MAIL_SERVER, MAIL_PORT, MAIL_USE_TLS, MAIL_USE_SSL,
# MAIL_USERNAME, MAIL_PASSWORD, MAIL_SENDER_NAME, MAIL_DEFAULT_SENDER_EMAIL
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587')) # Ensure port is an integer
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@example.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-email-password')
app.config['MAIL_SENDER_NAME'] = os.environ.get('MAIL_SENDER_NAME', 'Defect Tracker')
app.config['MAIL_DEFAULT_SENDER_EMAIL'] = os.environ.get('MAIL_DEFAULT_SENDER_EMAIL', 'noreply@defect-tracker.com')
# Note: MAIL_DEFAULT_SENDER tuple will be constructed in the route sending the email.
# --- DEBUG: Turn on Flask-Mail's verbose logging ---
app.config['MAIL_DEBUG'] = True

# --- DEBUG: Print the loaded mail configuration to the terminal to verify ---
print("--- MAIL CONFIGURATION ---")
print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
print(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
# For security, we print only if the password exists, not the password itself
print(f"MAIL_PASSWORD loaded: {'Yes' if app.config['MAIL_PASSWORD'] else 'No'}")
print("--------------------------")

mail = Mail(app) # Initialize Flask-Mail

# Create report directory
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
logger.info(f"Ensured report directory exists: {app.config['REPORT_FOLDER']}")

# Create drawing folder
os.makedirs(app.config['DRAWING_FOLDER'], exist_ok=True)
logger.info(f"Ensured drawing directory exists: {app.config['DRAWING_FOLDER']}")

# Verify write permissions
if not os.access(app.config['REPORT_FOLDER'], os.W_OK):
    logger.error(f"No write permissions for report directory: {app.config['REPORT_FOLDER']}")
    raise PermissionError(f"No write permissions for report directory: {app.config['REPORT_FOLDER']}")

# Log the database URI
logger.info(f"Using SQLALCHEMY_DATABASE_URI: {app.config['SQLALCHEMY_DATABASE_URI']}")

# Create upload folder
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
logger.info(f"Ensured upload directory exists: {app.config['UPLOAD_FOLDER']}")

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.chmod(app.config['UPLOAD_FOLDER'], 0o755)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, index=True) # Added index=True for user_id (PK)
    username = db.Column(db.String(255), unique=True, nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(50), nullable=False, default='pending_activation')
    name = db.Column(db.String(255), nullable=False, server_default="N/A")
    company = db.Column(db.String(255), nullable=False, server_default="N/A")
    projects = db.relationship('ProjectAccess', back_populates='user', cascade='all, delete-orphan')
    # Relationships for ProductApproval
    product_requests_made = db.relationship('ProductApproval', foreign_keys='ProductApproval.requester_id', back_populates='requester', lazy='dynamic')
    product_submissions_made = db.relationship('ProductApproval', foreign_keys='ProductApproval.contractor_id', back_populates='contractor', lazy='dynamic')
    product_approvals_made = db.relationship('ProductApproval', foreign_keys='ProductApproval.approver_id', back_populates='approver', lazy='dynamic')
    uploaded_product_documents = db.relationship('ProductDocument', foreign_keys='ProductDocument.uploader_id', back_populates='uploader', lazy='dynamic')

class ProjectAccess(db.Model):
    __tablename__ = 'project_access'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    user = db.relationship('User', back_populates='projects')
    project = db.relationship('Project')

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    defects = db.relationship('Defect', back_populates='project', cascade='all, delete-orphan')
    checklists = db.relationship('Checklist', back_populates='project', cascade='all, delete-orphan')
    accesses = db.relationship('ProjectAccess', back_populates='project', cascade='all, delete-orphan')
    drawings = db.relationship('Drawing', back_populates='project', cascade='all, delete-orphan')
    product_approvals = db.relationship('ProductApproval', back_populates='project', cascade='all, delete-orphan')

class Defect(db.Model):
    __tablename__ = 'defects'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), index=True)
    description = db.Column(db.String(255))
    status = db.Column(db.String(50), default='open')
    creation_date = db.Column(db.DateTime)
    close_date = db.Column(db.DateTime)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    project = db.relationship('Project', back_populates='defects')
    attachments = db.relationship('Attachment', back_populates='defect', cascade='all, delete-orphan')
    comments = db.relationship('Comment', back_populates='defect', cascade='all, delete-orphan')
    creator = db.relationship('User')
    markers = db.relationship('DefectMarker', back_populates='defect', cascade='all, delete-orphan')

class Drawing(db.Model):
    __tablename__ = 'drawings'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    project = db.relationship('Project', back_populates='drawings')
    markers = db.relationship('DefectMarker', back_populates='drawing', cascade='all, delete-orphan')

class DefectMarker(db.Model):
    __tablename__ = 'defect_markers'
    id = db.Column(db.Integer, primary_key=True)
    defect_id = db.Column(db.Integer, db.ForeignKey('defects.id'), nullable=False, index=True)
    drawing_id = db.Column(db.Integer, db.ForeignKey('drawings.id'), nullable=False)
    x = db.Column(db.Float, nullable=False)  # Normalized x-coordinate (0 to 1)
    y = db.Column(db.Float, nullable=False)  # Normalized y-coordinate (0 to 1)
    # Add page_num if it's part of your logic, assuming it's not for now based on previous model.
    page_num = db.Column(db.Integer, nullable=False, default=1) 
    defect = db.relationship('Defect', back_populates='markers')
    drawing = db.relationship('Drawing', back_populates='markers')

    def to_dict(self):
        return {
            'id': self.id,
            'defect_id': self.defect_id,
            'drawing_id': self.drawing_id,
            'x': self.x,
            'y': self.y,
            'page_num': getattr(self, 'page_num', 1), # Default to 1 if not present
            'file_path': self.drawing.file_path if self.drawing else None,
            'drawing_name': self.drawing.name if self.drawing else None
        }

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    defect_id = db.Column(db.Integer, db.ForeignKey('defects.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    edited = db.Column(db.Boolean, default=False, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow) # Sets on creation and updates on modification
    defect = db.relationship('Defect', back_populates='comments')
    user = db.relationship('User')
    attachments = db.relationship('Attachment', back_populates='comment', cascade='all, delete-orphan')

class Attachment(db.Model):
    __tablename__ = 'attachments'
    id = db.Column(db.Integer, primary_key=True)
    defect_id = db.Column(db.Integer, db.ForeignKey('defects.id'), index=True)
    checklist_item_id = db.Column(db.Integer, db.ForeignKey('checklist_items.id'))
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    file_path = db.Column(db.String(255))
    thumbnail_path = db.Column(db.String(255)) # For images, or generic icon path for other types
    mime_type = db.Column(db.String(100), nullable=True) # To store the MIME type
    defect = db.relationship('Defect', back_populates='attachments')
    checklist_item = db.relationship('ChecklistItem', back_populates='attachments')
    comment = db.relationship('Comment', back_populates='attachments')

class Template(db.Model):
    __tablename__ = 'templates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    items = db.relationship('TemplateItem', back_populates='template', cascade='all, delete-orphan')

class TemplateItem(db.Model):
    __tablename__ = 'template_items'
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('templates.id'))
    item_text = db.Column(db.String(255))
    template = db.relationship('Template', back_populates='items')

class Checklist(db.Model):
    __tablename__ = 'checklists'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), index=True)
    template_id = db.Column(db.Integer, db.ForeignKey('templates.id'))
    name = db.Column(db.String(255), nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime.now)
    project = db.relationship('Project', back_populates='checklists')
    items = db.relationship('ChecklistItem', back_populates='checklist', cascade='all, delete-orphan')

class ChecklistItem(db.Model):
    __tablename__ = 'checklist_items'
    id = db.Column(db.Integer, primary_key=True)
    checklist_id = db.Column(db.Integer, db.ForeignKey('checklists.id'))
    item_text = db.Column(db.String(255))
    is_checked = db.Column(db.Boolean, default=False)
    comments = db.Column(db.String(255), default='')
    checklist = db.relationship('Checklist', back_populates='items')
    attachments = db.relationship('Attachment', back_populates='checklist_item', cascade='all, delete-orphan')

class ProductApproval(db.Model):
    __tablename__ = 'product_approvals'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False, index=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    product_name = db.Column(db.String(255), nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    contractor_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    product_description = db.Column(db.Text, nullable=True)
    # documentation_path = db.Column(db.String(255), nullable=True) # Path to PDF - REMOVED
    submission_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='waiting_for_proposal') # waiting_for_proposal, product_provided, approved, rejected
    approver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    approval_date = db.Column(db.DateTime, nullable=True)
    approver_comments = db.Column(db.Text, nullable=True)

    project = db.relationship('Project', back_populates='product_approvals')
    requester = db.relationship('User', foreign_keys=[requester_id], back_populates='product_requests_made')
    contractor = db.relationship('User', foreign_keys=[contractor_id], back_populates='product_submissions_made')
    approver = db.relationship('User', foreign_keys=[approver_id], back_populates='product_approvals_made')
    documents = db.relationship('ProductDocument', back_populates='product_approval', cascade='all, delete-orphan') # Removed lazy='dynamic'

class ProductDocument(db.Model):
    __tablename__ = 'product_documents'
    id = db.Column(db.Integer, primary_key=True)
    product_approval_id = db.Column(db.Integer, db.ForeignKey('product_approvals.id'), nullable=False, index=True)
    file_path = db.Column(db.String(255), nullable=False) # Just filename, e.g., pa_doc_timestamp_original.pdf
    original_filename = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    uploader_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)

    product_approval = db.relationship('ProductApproval', back_populates='documents')
    uploader = db.relationship('User', back_populates='uploaded_product_documents')

# Database initialization
db_init_lock = Lock()

def init_db():
    with app.app_context():
        with db_init_lock:  # Prevent concurrent execution
            logger.info("Checking database tables...")
            try:
                inspector = inspect(db.engine)  # Use db.engine from Flask-SQLAlchemy
                existing_tables = inspector.get_table_names()
                logger.info(f"Existing tables: {existing_tables}")
                required_tables = [
                    'users', 'project_access', 'projects', 'defects', 'comments',
                    'attachments', 'templates', 'template_items', 'checklists', 'checklist_items',
                    'drawings', 'defect_markers', 'product_approvals', 'product_documents'
                ]
                logger.info(f"Required tables: {required_tables}")

                if set(required_tables).issubset(existing_tables):
                    logger.info("All required tables already exist, skipping creation.")
                    return

                logger.info("Creating missing database tables...")
                db.create_all()
                logger.info("Database tables created successfully.")
            except Exception as e:
                logger.error(f"Error creating database tables: {str(e)}")
                raise

# Initialize database
try:
    init_db()
except Exception as e:
    logger.error(f"Failed to initialize database: {str(e)}")
    raise

@login_manager.user_loader
def load_user(user_id):
    # Eagerly load the 'projects' relationship to prevent DetachedInstanceError
    # when accessing current_user.projects after the initial session might be closed.
    return User.query.options(joinedload(User.projects)).get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def ensure_thumbnail_directory():
    # app refers to the Flask app instance, UPLOAD_FOLDER is 'static/images'
    thumbnail_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'thumbnails')
    if not os.path.exists(thumbnail_dir):
        os.makedirs(thumbnail_dir, exist_ok=True)
        os.chmod(thumbnail_dir, 0o755)  # Ensure correct permissions
    return thumbnail_dir

@app.context_processor
def utility_processor():
    def get_absolute_static_path_for_template(relative_path):
        if not relative_path:
            return None
        # Ensure the path is not attempting to escape the static folder.
        # This is a basic check; more robust validation might be needed
        # if paths were user-supplied directly in a harmful way.
        # However, these paths are typically from DB or server-generated.
        if ".." in relative_path:
            logger.warning(f"Potential path traversal attempt in get_absolute_static_path: {relative_path}")
            return None # Or raise an error, or return a placeholder

        # Use os.path.normpath to canonicalize the path, which helps resolve any redundant separators or up-level references if any slip through.
        # Then join with app.static_folder.
        # lstrip('/') ensures that if relative_path accidentally starts with '/', it doesn't break os.path.join behavior of treating it as an absolute path.
        absolute_path = os.path.normpath(os.path.join(app.static_folder, relative_path.lstrip('/\\')))

        # Final check to ensure the path is still within the static folder - might be overkill if inputs are trusted
        if os.path.commonprefix([absolute_path, app.static_folder]) != app.static_folder:
            logger.warning(f"Path {absolute_path} resolved outside static folder from relative path {relative_path}")
            return None # Or some placeholder
        return absolute_path
    return dict(get_absolute_static_path=get_absolute_static_path_for_template)

@app.context_processor
def inject_accessible_projects():
    if current_user.is_authenticated:
        accessible_project_objects = []
        # Assuming current_user.projects is a list of ProjectAccess objects
        project_accesses = ProjectAccess.query.filter_by(user_id=current_user.id).all()
        project_ids = [access.project_id for access in project_accesses]
        if project_ids:
            accessible_project_objects = Project.query.filter(Project.id.in_(project_ids)).order_by(Project.name).all()
        return dict(accessible_projects=accessible_project_objects)
    return dict(accessible_projects=[])

# Helper function to ensure specific attachment subdirectories exist
def ensure_attachment_paths(subfolder_name):
    # Base directory for all uploads, relative to 'static'
    base_upload_dir_name = 'uploads' # e.g., static/uploads/

    # Full path for the specific subfolder (e.g., static/uploads/attachments_pdf)
    specific_upload_dir = os.path.join(app.static_folder, base_upload_dir_name, subfolder_name)
    os.makedirs(specific_upload_dir, exist_ok=True)

    # For thumbnails, create a 'thumbnails' directory
    thumbnail_dir = None
    if 'img' in subfolder_name.lower(): # For images: static/uploads/attachments_img/thumbnails
        thumbnail_dir = os.path.join(specific_upload_dir, 'thumbnails')
        os.makedirs(thumbnail_dir, exist_ok=True)
    elif subfolder_name == 'attachments_pdf': # For PDF originals: static/uploads/attachments_pdf
        # This case is for the main PDF files, no specific thumbnail dir needed from here for originals.
        # However, we need a way to get the PDF thumbnail directory.
        # Let's establish a convention: if subfolder_name is 'attachments_pdf_thumbs', it's handled.
        pass # specific_upload_dir is already correct for originals
    elif subfolder_name == 'attachments_pdf_thumbs': # For PDF thumbnails: static/uploads/attachments_pdf_thumbs
        # This is a new case. specific_upload_dir will be 'static/uploads/attachments_pdf_thumbs'
        # thumbnail_dir will be this directory itself.
        thumbnail_dir = specific_upload_dir # The specific_upload_dir is the thumbnail_dir in this case
        # Ensure it exists (already done by os.makedirs(specific_upload_dir, exist_ok=True) above)

    # The return signature is (originals_dir, thumbnails_dir)
    # For 'attachments_pdf', specific_upload_dir is pdf_dir, thumbnail_dir is None
    # For 'attachments_img', specific_upload_dir is img_dir, thumbnail_dir is its 'thumbnails' subdir
    # For 'attachments_pdf_thumbs', specific_upload_dir is the thumb dir itself, so we return it as thumbnail_dir
    if subfolder_name == 'attachments_pdf_thumbs':
        return specific_upload_dir, specific_upload_dir # originals_dir is not relevant, thumb_dir is the main path

    return specific_upload_dir, thumbnail_dir

def create_thumbnail(image_path, thumbnail_save_path, size=(300, 300)):
    try:
        # Ensure the directory for the thumbnail exists (already done by ensure_attachment_paths if logic is sequential)
        thumbnail_dir_for_saving = os.path.dirname(thumbnail_save_path)
        if not os.path.exists(thumbnail_dir_for_saving):
             os.makedirs(thumbnail_dir_for_saving, exist_ok=True) # Should be redundant if called after ensure_attachment_paths

        with PILImage.open(image_path) as img:
            img = ImageOps.exif_transpose(img) # Apply EXIF orientation
            img.thumbnail(size, PILImage.Resampling.LANCZOS)
            if img.mode == 'RGBA' or img.mode == 'P': # P mode can also have transparency
                img = img.convert('RGB')
            img.save(thumbnail_save_path, quality=85, optimize=True)
            os.chmod(thumbnail_save_path, 0o644)
        logger.debug(f'Created thumbnail: {thumbnail_save_path}')
    except Exception as e:
        logger.error(f'Thumbnail creation failed for {image_path} to {thumbnail_save_path}: {str(e)}')
        raise

import json

def _export_single_project_to_zip(project_id, target_base_dir_for_zip):
    logger.info(f"Starting export for project ID: {project_id}")
    project_to_export = db.session.get(Project, project_id)

    if not project_to_export:
        logger.error(f"Project with ID {project_id} not found for export.")
        return None

    # Create a temporary directory for this specific project's export files
    project_temp_export_path = None
    try:
        project_temp_export_path = tempfile.mkdtemp()

        # Define structure within the temp path
        # attachments_img_dir = os.path.join(project_temp_export_path, 'attachments', 'images')
        # attachments_pdf_dir = os.path.join(project_temp_export_path, 'attachments', 'pdfs')
        # attachments_pdf_thumbs_dir = os.path.join(project_temp_export_path, 'attachments', 'pdf_thumbnails')
        # drawings_export_dir = os.path.join(project_temp_export_path, 'drawings')
        # os.makedirs(attachments_img_dir, exist_ok=True)
        # os.makedirs(os.path.join(attachments_img_dir, 'thumbnails'), exist_ok=True)
        # os.makedirs(attachments_pdf_dir, exist_ok=True)
        # os.makedirs(attachments_pdf_thumbs_dir, exist_ok=True)
        # os.makedirs(drawings_export_dir, exist_ok=True)
        # Simpler structure: top-level folders for drawings, attachments, attachments/thumbnails
        # The import function will need to be robust to various structures or expect one.
        # For now, let's match the ensure_attachment_paths expectation for "uploads" subfolder structure
        # but place it under a general "attachments" folder in the zip.

        # Path structure within the ZIP:
        # project_data.json
        # drawings/ (contains original drawing files)
        # attachments/ (contains original attachment files, possibly categorized by type)
        # attachments/thumbnails/ (contains corresponding thumbnails)

        # Simpler: let _copy_file_to_export handle path creation within project_temp_export_path

        project_export_data = {
            'project': {},
            'drawings': [],
            'defects': [],
            'checklists': []
        }

        # Project details
        project_export_data['project'] = {
            'id': project_to_export.id, # Original ID, will be remapped on import
            'name': project_to_export.name
        }

        # Drawings
        logger.info(f"Exporting drawings for project {project_id}...")
        drawings = Drawing.query.filter_by(project_id=project_id).all()
        for drawing in drawings:
            drawing_data = {
                'id': drawing.id,
                'name': drawing.name,
                'file_path': drawing.file_path, # This path is relative to 'static/' e.g. 'drawings/file.pdf'
                'created_at': drawing.created_at.isoformat() if drawing.created_at else None
            }
            project_export_data['drawings'].append(drawing_data)
            # Copy drawing file
            if drawing.file_path:
                source_drawing_abs_path = os.path.join(app.static_folder, drawing.file_path)
                 # Destination within zip should mirror the structure expected by import (e.g. 'drawings/filename.pdf')
                dest_drawing_in_zip_path = os.path.join(project_temp_export_path, drawing.file_path)
                os.makedirs(os.path.dirname(dest_drawing_in_zip_path), exist_ok=True)
                if os.path.exists(source_drawing_abs_path):
                    shutil.copy2(source_drawing_abs_path, dest_drawing_in_zip_path)
                else:
                    logger.warning(f"Drawing file {source_drawing_abs_path} not found for project {project_id}.")


        defects = Defect.query.filter_by(project_id=project_id).all()
        checklists = Checklist.query.filter_by(project_id=project_id).all()
        logger.info(f"Project: {project_to_export.name}, Defects: {len(defects)}, Drawings: {len(drawings)}, Checklists: {len(checklists)}")


        # Defects and related entities
        logger.info(f"Exporting defects for project {project_id}...")
        for defect in defects:
            defect_data = {
                'id': defect.id,
                'project_id': defect.project_id, # Will be remapped by importer
                'description': defect.description,
                'status': defect.status,
                'creation_date': defect.creation_date.isoformat() if defect.creation_date else None,
                'close_date': defect.close_date.isoformat() if defect.close_date else None,
                'creator_id': defect.creator_id, # Will be remapped by importer to importing user
                'markers': [],
                'attachments': [],
                'comments': []
            }

            # Defect Markers
            for marker in defect.markers:
                defect_data['markers'].append({
                    'id': marker.id,
                    'drawing_id': marker.drawing_id, # Will be remapped
                    'x': marker.x,
                    'y': marker.y,
                    'page_num': marker.page_num
                })

            # Defect Attachments
            logger.debug(f"Exporting attachments for defect {defect.id}...")
            for attachment in Attachment.query.filter_by(defect_id=defect.id).all():
                att_export_data = {
                    'id': attachment.id,
                    'file_path': attachment.file_path, # Relative to static/ e.g. uploads/attachments_img/...
                    'thumbnail_path': attachment.thumbnail_path, # Relative to static/
                    'mime_type': attachment.mime_type
                }
                defect_data['attachments'].append(att_export_data)
                # Copy attachment files
                if attachment.file_path:
                    source_file_abs = os.path.join(app.static_folder, attachment.file_path)
                    # Destination in zip: project_temp_export_path / uploads / attachments_img / file.jpg
                    dest_file_in_zip = os.path.join(project_temp_export_path, attachment.file_path)
                    os.makedirs(os.path.dirname(dest_file_in_zip), exist_ok=True)
                    if os.path.exists(source_file_abs):
                        shutil.copy2(source_file_abs, dest_file_in_zip)
                    else:
                        logger.warning(f"Attachment file {source_file_abs} for defect {defect.id} not found.")

                if attachment.thumbnail_path:
                    source_thumb_abs = os.path.join(app.static_folder, attachment.thumbnail_path)
                    dest_thumb_in_zip = os.path.join(project_temp_export_path, attachment.thumbnail_path)
                    os.makedirs(os.path.dirname(dest_thumb_in_zip), exist_ok=True)
                    if os.path.exists(source_thumb_abs):
                        shutil.copy2(source_thumb_abs, dest_thumb_in_zip)
                    else:
                        logger.warning(f"Attachment thumbnail {source_thumb_abs} for defect {defect.id} not found.")

            # Comments
            for comment in Comment.query.filter_by(defect_id=defect.id).all():
                comment_data = {
                    'id': comment.id,
                    'user_id': comment.user_id, # Will be remapped by importer
                    'content': comment.content,
                    'created_at': comment.created_at.isoformat() if comment.created_at else None,
                    'edited': comment.edited,
                    'updated_at': comment.updated_at.isoformat() if comment.updated_at else None,
                    'attachments': []
                }
                # Comment Attachments
                logger.debug(f"Exporting attachments for comment {comment.id}...")
                for c_attachment in Attachment.query.filter_by(comment_id=comment.id).all():
                    c_att_export_data = {
                        'id': c_attachment.id,
                        'file_path': c_attachment.file_path,
                        'thumbnail_path': c_attachment.thumbnail_path,
                        'mime_type': c_attachment.mime_type
                    }
                    comment_data['attachments'].append(c_att_export_data)
                    # Copy files (similar to defect attachments)
                    if c_attachment.file_path:
                        source_c_file_abs = os.path.join(app.static_folder, c_attachment.file_path)
                        dest_c_file_in_zip = os.path.join(project_temp_export_path, c_attachment.file_path)
                        os.makedirs(os.path.dirname(dest_c_file_in_zip), exist_ok=True)
                        if os.path.exists(source_c_file_abs):
                            shutil.copy2(source_c_file_abs, dest_c_file_in_zip)
                        else:
                            logger.warning(f"Attachment file {source_c_file_abs} for comment {comment.id} not found.")

                    if c_attachment.thumbnail_path:
                        source_c_thumb_abs = os.path.join(app.static_folder, c_attachment.thumbnail_path)
                        dest_c_thumb_in_zip = os.path.join(project_temp_export_path, c_attachment.thumbnail_path)
                        os.makedirs(os.path.dirname(dest_c_thumb_in_zip), exist_ok=True)
                        if os.path.exists(source_c_thumb_abs):
                             shutil.copy2(source_c_thumb_abs, dest_c_thumb_in_zip)
                        else:
                            logger.warning(f"Attachment thumbnail {source_c_thumb_abs} for comment {comment.id} not found.")
                defect_data['comments'].append(comment_data)
            project_export_data['defects'].append(defect_data)

        # Checklists and related entities
        logger.info(f"Exporting checklists for project {project_id}...")
        for checklist in checklists:
            checklist_data = {
                'id': checklist.id,
                'project_id': checklist.project_id, # Will be remapped
                'template_id': checklist.template_id, # May need remapping or handling if templates are exported
                'name': checklist.name,
                'creation_date': checklist.creation_date.isoformat() if checklist.creation_date else None,
                'items': []
            }
            for item in checklist.items:
                item_data = {
                    'id': item.id,
                    'item_text': item.item_text,
                    'is_checked': item.is_checked,
                    'comments': item.comments,
                    'attachments': []
                }
                # Checklist Item Attachments
                logger.debug(f"Exporting attachments for checklist item {item.id}...")
                for ci_attachment in Attachment.query.filter_by(checklist_item_id=item.id).all():
                    ci_att_export_data = {
                        'id': ci_attachment.id,
                        'file_path': ci_attachment.file_path,
                        'thumbnail_path': ci_attachment.thumbnail_path,
                        'mime_type': ci_attachment.mime_type
                    }
                    item_data['attachments'].append(ci_att_export_data)
                     # Copy files
                    if ci_attachment.file_path:
                        source_ci_file_abs = os.path.join(app.static_folder, ci_attachment.file_path)
                        dest_ci_file_in_zip = os.path.join(project_temp_export_path, ci_attachment.file_path)
                        os.makedirs(os.path.dirname(dest_ci_file_in_zip), exist_ok=True)
                        if os.path.exists(source_ci_file_abs):
                            shutil.copy2(source_ci_file_abs, dest_ci_file_in_zip)
                        else:
                            logger.warning(f"Attachment file {source_ci_file_abs} for checklist item {item.id} not found.")
                    if ci_attachment.thumbnail_path:
                        source_ci_thumb_abs = os.path.join(app.static_folder, ci_attachment.thumbnail_path)
                        dest_ci_thumb_in_zip = os.path.join(project_temp_export_path, ci_attachment.thumbnail_path)
                        os.makedirs(os.path.dirname(dest_ci_thumb_in_zip), exist_ok=True)
                        if os.path.exists(source_ci_thumb_abs):
                            shutil.copy2(source_ci_thumb_abs, dest_ci_thumb_in_zip)
                        else:
                             logger.warning(f"Attachment thumbnail {source_ci_thumb_abs} for checklist item {item.id} not found.")
                checklist_data['items'].append(item_data)
            project_export_data['checklists'].append(checklist_data)

        # Write project_data.json
        logger.debug(f"Structure of project_export_data for project {project_id}: Keys: {list(project_export_data.keys())}")
        if 'project' in project_export_data:
            logger.debug(f"Project details keys in export data: {list(project_export_data.get('project', {}).keys())}")

        with open(os.path.join(project_temp_export_path, 'project_data.json'), 'w') as f:
            json.dump(project_export_data, f, indent=4)

        # Create ZIP file for this project
        zip_filename_base = secure_filename(project_to_export.name) or f"project_{project_id}"
        # Place this individual project's zip into the target_base_dir_for_zip
        individual_zip_archive_path = shutil.make_archive(
            base_name=os.path.join(target_base_dir_for_zip, zip_filename_base),
            format='zip',
            root_dir=project_temp_export_path # The directory to zip
        )
        logger.info(f"Successfully created individual ZIP for project {project_id} at {individual_zip_archive_path}")
        return individual_zip_archive_path

    except Exception as e:
        logger.error(f"Error in _export_single_project_to_zip for project {project_id}: {e}", exc_info=True)
        return None
    finally:
        if project_temp_export_path and os.path.exists(project_temp_export_path):
            shutil.rmtree(project_temp_export_path)


def _perform_single_project_import(extracted_project_base_path, importing_user_id):
    json_path = os.path.join(extracted_project_base_path, 'project_data.json')
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error(f"project_data.json not found at {json_path}")
        return False, f"project_data.json not found in {os.path.basename(extracted_project_base_path)}.", None
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding project_data.json from {json_path}: {e}")
        return False, f"Invalid JSON in {os.path.basename(extracted_project_base_path)}: {e}", None
    except Exception as e: # Catch other potential errors during file reading
        logger.error(f"Error reading project_data.json from {json_path}: {e}", exc_info=True)
        return False, f"Could not read project data from {os.path.basename(extracted_project_base_path)}: {e}", None

    project_details = data.get('project')
    if not project_details:
        logger.error(f"'project' key missing or empty in {json_path}")
        return False, f"Invalid data structure in {os.path.basename(extracted_project_base_path)} (missing 'project' key or data)", None

    old_to_new_project_id = {}
    old_to_new_drawing_ids = {}
    old_to_new_defect_ids = {}
    old_to_new_comment_ids = {}
    old_to_new_checklist_ids = {}
    old_to_new_checklist_item_ids = {}

    # Nested helper for attachment import
    def _import_attachment_file_local(att_data, new_parent_id_type, new_parent_id, extracted_base_path):
        original_relative_path = att_data.get('file_path')
        original_thumbnail_relative_path = att_data.get('thumbnail_path')
        mime_type = att_data.get('mime_type') # Optional, can be None

        if not original_relative_path:
            logger.error(f"Attachment data missing 'file_path': {att_data}. Cannot import this attachment.")
            # This error should ideally cause the single project import to fail if an attachment is critical
            # For now, we skip this attachment as per original design of _import_attachment_file_local returning None
            return None

        source_file_path = os.path.join(extracted_base_path, original_relative_path)
        if not os.path.exists(source_file_path):
            logger.error(f"Source attachment file not found at {source_file_path} (original path: {original_relative_path}). Cannot import this attachment.")
            return None

        # Determine destination based on mime_type or file extension
        filename = os.path.basename(original_relative_path)
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
        unique_server_filename_base = f"imported_{timestamp}_{secure_filename(filename)}"

        dest_folder_name_segment = 'attachments_img' # Default
        if mime_type and mime_type.startswith('image/'):
            dest_folder_name_segment = 'attachments_img'
        elif mime_type == 'application/pdf' or original_relative_path.lower().endswith('.pdf'):
            dest_folder_name_segment = 'attachments_pdf'
        # Add more types if necessary, or a generic 'attachments_other'

        dest_originals_dir, dest_thumbnails_dir = ensure_attachment_paths(dest_folder_name_segment)

        new_server_file_path_abs = os.path.join(dest_originals_dir, unique_server_filename_base)
        new_db_file_path = os.path.join('uploads', dest_folder_name_segment, unique_server_filename_base)

        new_db_thumbnail_path = None

        try:
            shutil.copy2(source_file_path, new_server_file_path_abs)
            os.chmod(new_server_file_path_abs, 0o644)

            if original_thumbnail_relative_path:
                source_thumbnail_path = os.path.join(extracted_base_path, original_thumbnail_relative_path)
                if os.path.exists(source_thumbnail_path) and dest_thumbnails_dir:
                    thumb_filename = f"thumb_{unique_server_filename_base}"
                    # Ensure correct extension for PDF thumbnails if they were PNGs
                    if dest_folder_name_segment == 'attachments_pdf' and not thumb_filename.lower().endswith('.png'):
                         thumb_filename = os.path.splitext(thumb_filename)[0] + '.png'

                    new_server_thumbnail_path_abs = os.path.join(dest_thumbnails_dir, thumb_filename)
                    shutil.copy2(source_thumbnail_path, new_server_thumbnail_path_abs)
                    os.chmod(new_server_thumbnail_path_abs, 0o644)
                    new_db_thumbnail_path = os.path.join('uploads', dest_folder_name_segment, 'thumbnails', thumb_filename)
                    if dest_folder_name_segment == 'attachments_pdf_thumbs': # Special case from ensure_attachment_paths
                        new_db_thumbnail_path = os.path.join('uploads', 'attachments_pdf_thumbs', thumb_filename)


            elif mime_type and mime_type.startswith('image/') and dest_thumbnails_dir: # Create thumbnail if source didn't have one for image
                thumb_filename = f"thumb_{unique_server_filename_base}"
                new_server_thumbnail_path_abs = os.path.join(dest_thumbnails_dir, thumb_filename)
                create_thumbnail(new_server_file_path_abs, new_server_thumbnail_path_abs)
                new_db_thumbnail_path = os.path.join('uploads', dest_folder_name_segment, 'thumbnails', thumb_filename)

            elif (mime_type == 'application/pdf' or original_relative_path.lower().endswith('.pdf')):
                # Try to generate PDF thumbnail if one wasn't provided
                pdf_thumb_save_dir_check, _ = ensure_attachment_paths('attachments_pdf_thumbs') # Get the specific dir for PDF thumbs
                if pdf_thumb_save_dir_check:
                    thumb_pdf_filename = 'thumb_' + os.path.splitext(unique_server_filename_base)[0] + '.png'
                    abs_pdf_thumb_path = os.path.join(pdf_thumb_save_dir_check, thumb_pdf_filename)
                    try:
                        pdf_images = convert_from_path(new_server_file_path_abs, first_page=1, last_page=1, fmt='png', size=(300, None))
                        if pdf_images:
                            pdf_images[0].save(abs_pdf_thumb_path, 'PNG')
                            os.chmod(abs_pdf_thumb_path, 0o644)
                            new_db_thumbnail_path = os.path.join('uploads', 'attachments_pdf_thumbs', thumb_pdf_filename)
                            logger.info(f"Generated PDF thumbnail during import: {new_db_thumbnail_path}")
                    except Exception as pdf_thumb_e:
                        logger.error(f"Failed to generate PDF thumbnail during import: {pdf_thumb_e}")


            attachment_args = {
                new_parent_id_type: new_parent_id,
                'file_path': new_db_file_path,
                'thumbnail_path': new_db_thumbnail_path,
                'mime_type': mime_type
            }
            new_attachment = Attachment(**attachment_args)
            return new_attachment
        except Exception as e_file_copy:
            logger.error(f"Error processing attachment file {original_relative_path}: {e_file_copy}", exc_info=True)
            return None


    try:
        # 1. Import Project
        # project_details is already fetched and validated
        original_project_name = project_details.get('name')
        if not original_project_name: # Name is critical
            logger.error(f"Missing 'name' in project details in {json_path}")
            return False, "Invalid project data (missing project name)", None

        old_project_id = project_details.get('id')
        if old_project_id is None: # ID is critical for mapping
            logger.error(f"Missing 'id' in project details in {json_path}")
            return False, "Invalid project data (missing project id)", None

        new_project_name = original_project_name
        # Handle potential name conflicts
        name_conflict_count = 0
        while Project.query.filter_by(name=new_project_name).first():
            name_conflict_count += 1
            timestamp_suffix = datetime.now().strftime('%Y%m%d%H%M%S')
            new_project_name = f"{original_project_name}_imported_{timestamp_suffix}"
            if name_conflict_count > 1: # If timestamped name also conflicts, add counter
                 new_project_name = f"{original_project_name}_imported_{timestamp_suffix}_{name_conflict_count}"
            if name_conflict_count > 5: # Safety break
                return False, f"Too many name conflicts for project '{original_project_name}'. Please rename and try again.", None


        new_project = Project(name=new_project_name)
        db.session.add(new_project)
        db.session.flush() # To get new_project.id
        old_to_new_project_id[old_project_id] = new_project.id # Use validated old_project_id

        # Project Access for importing user
        project_access = ProjectAccess(user_id=importing_user_id, project_id=new_project.id, role='admin')
        db.session.add(project_access)

        # 2. Import Drawings
        logger.info(f"Importing drawings for project ID: {new_project.id} (Original: {old_project_id})")
        for drawing_data in data.get('drawings', []):
            old_drawing_id = drawing_data.get('id')
            original_drawing_path = drawing_data.get('file_path')
            drawing_name = drawing_data.get('name')

            if old_drawing_id is None:
                logger.error(f"Skipping drawing due to missing 'id' in drawing data: {drawing_data}")
                return False, f"Invalid drawing data (missing id) in {os.path.basename(extracted_project_base_path)}", None
            if not original_drawing_path:
                logger.error(f"Skipping drawing ID {old_drawing_id} due to missing 'file_path': {drawing_data}")
                return False, f"Invalid drawing data (missing file_path for ID {old_drawing_id}) in {os.path.basename(extracted_project_base_path)}", None
            if not drawing_name:
                logger.warning(f"Drawing ID {old_drawing_id} missing 'name', using filename as fallback.")
                drawing_name = os.path.basename(original_drawing_path)

            source_drawing_full_path = os.path.join(extracted_project_base_path, original_drawing_path)
            if not os.path.exists(source_drawing_full_path):
                logger.error(f"Drawing file {original_drawing_path} not found at {source_drawing_full_path}. Failing import for project.")
                return False, f"Missing drawing file ({original_drawing_path}) in archive for {os.path.basename(extracted_project_base_path)}", None

            drawing_filename = os.path.basename(original_drawing_path)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
            unique_drawing_filename = f"imported_{timestamp}_{secure_filename(drawing_filename)}"

            dest_drawing_full_path = os.path.join(app.config['DRAWING_FOLDER'], unique_drawing_filename)
            new_drawing_db_path = os.path.join('drawings', unique_drawing_filename)

            try:
                shutil.copy2(source_drawing_full_path, dest_drawing_full_path)
                os.chmod(dest_drawing_full_path, 0o644)
            except Exception as e_draw_copy:
                logger.error(f"Error copying drawing file {original_drawing_path} to {dest_drawing_full_path}: {e_draw_copy}", exc_info=True)
                return False, f"Could not copy drawing file ({original_drawing_path}): {e_draw_copy}", None

            created_at_str = drawing_data.get('created_at')
            created_at_dt = datetime.fromisoformat(created_at_str) if created_at_str else datetime.now()

            new_drawing = Drawing(
                project_id=new_project.id,
                name=drawing_name,
                file_path=new_drawing_db_path,
                created_at=created_at_dt
            )
            db.session.add(new_drawing)
            db.session.flush()
            old_to_new_drawing_ids[old_drawing_id] = new_drawing.id

        # 3. Import Defects
        logger.info(f"Importing defects for project ID: {new_project.id} (Original: {old_project_id})")
        for defect_data in data.get('defects', []):
            old_defect_id = defect_data.get('id')
            if old_defect_id is None:
                logger.error(f"Skipping defect due to missing 'id': {defect_data}")
                return False, f"Invalid defect data (missing id) in {os.path.basename(extracted_project_base_path)}", None

            original_project_id_in_defect = defect_data.get('project_id')
            if original_project_id_in_defect not in old_to_new_project_id:
                 logger.error(f"Defect {old_defect_id} references unknown project_id {original_project_id_in_defect}. Skipping defect.")
                 return False, f"Invalid defect data (unknown project_id {original_project_id_in_defect})", None

            creation_date_str = defect_data.get('creation_date')
            close_date_str = defect_data.get('close_date')

            new_defect = Defect(
                project_id=old_to_new_project_id[original_project_id_in_defect],
                description=defect_data.get('description', ''),
                status=defect_data.get('status', 'open'),
                creation_date=datetime.fromisoformat(creation_date_str) if creation_date_str else datetime.now(),
                close_date=datetime.fromisoformat(close_date_str) if close_date_str else None,
                creator_id=importing_user_id
            )
            db.session.add(new_defect)
            db.session.flush()
            old_to_new_defect_ids[old_defect_id] = new_defect.id

            # DefectMarkers
            for marker_data in defect_data.get('markers', []):
                old_drawing_id_for_marker = marker_data.get('drawing_id')
                marker_x = marker_data.get('x')
                marker_y = marker_data.get('y')

                if old_drawing_id_for_marker is None or marker_x is None or marker_y is None:
                    logger.warning(f"Skipping marker for defect {old_defect_id} due to missing critical data: {marker_data}")
                    continue

                if old_drawing_id_for_marker in old_to_new_drawing_ids:
                    new_marker = DefectMarker(
                        defect_id=new_defect.id,
                        drawing_id=old_to_new_drawing_ids[old_drawing_id_for_marker],
                        x=marker_x,
                        y=marker_y,
                        page_num=marker_data.get('page_num', 1)
                    )
                    db.session.add(new_marker)
                else:
                    logger.warning(f"Skipping marker for defect {old_defect_id} as its drawing {old_drawing_id_for_marker} was not imported.")

            # Defect Attachments
            for att_data in defect_data.get('attachments', []):
                imported_att = _import_attachment_file_local(att_data, 'defect_id', new_defect.id, extracted_project_base_path)
                if imported_att:
                    db.session.add(imported_att)

            # Comments
            for comment_data in defect_data.get('comments', []):
                old_comment_id = comment_data.get('id')
                if old_comment_id is None:
                    logger.error(f"Skipping comment for defect {old_defect_id} due to missing 'id': {comment_data}")
                    # Decide if this should fail the whole import or just skip the comment
                    return False, f"Invalid comment data (missing id) for defect {old_defect_id}", None

                created_at_c_str = comment_data.get('created_at')
                updated_at_c_str = comment_data.get('updated_at', created_at_c_str) # Default updated_at to created_at if missing

                new_comment = Comment(
                    defect_id=new_defect.id,
                    user_id=importing_user_id,
                    content=comment_data.get('content', ''),
                    created_at=datetime.fromisoformat(created_at_c_str) if created_at_c_str else datetime.now(),
                    edited=comment_data.get('edited', False),
                    updated_at=datetime.fromisoformat(updated_at_c_str) if updated_at_c_str else (datetime.fromisoformat(created_at_c_str) if created_at_c_str else datetime.now())
                )
                db.session.add(new_comment)
                db.session.flush()
                old_to_new_comment_ids[old_comment_id] = new_comment.id

                # Comment Attachments
                for c_att_data in comment_data.get('attachments', []):
                    imported_c_att = _import_attachment_file_local(c_att_data, 'comment_id', new_comment.id, extracted_project_base_path)
                    if imported_c_att: # If None, it means the file was missing or couldn't be copied
                        db.session.add(imported_c_att)
                    # else:
                        # Potentially fail the import if an attachment is critical:
                        # return False, f"Failed to import attachment for comment {old_comment_id}", None

        # 4. Import Checklists
        logger.info(f"Importing checklists for project ID: {new_project.id} (Original: {old_project_id})")
        for checklist_data in data.get('checklists', []):
            old_checklist_id = checklist_data.get('id')
            checklist_name = checklist_data.get('name')
            if old_checklist_id is None:
                logger.error(f"Skipping checklist due to missing 'id': {checklist_data}")
                return False, "Invalid checklist data (missing id)", None
            if not checklist_name:
                logger.error(f"Skipping checklist ID {old_checklist_id} due to missing 'name': {checklist_data}")
                return False, f"Invalid checklist data (missing name for ID {old_checklist_id})", None

            creation_date_cl_str = checklist_data.get('creation_date')
            new_checklist = Checklist(
                project_id=new_project.id,
                template_id=checklist_data.get('template_id'), # Assuming template_id is either valid or nullable/handled by DB default
                name=checklist_name,
                creation_date=datetime.fromisoformat(creation_date_cl_str) if creation_date_cl_str else datetime.now()
            )
            db.session.add(new_checklist)
            db.session.flush()
            old_to_new_checklist_ids[old_checklist_id] = new_checklist.id

            # ChecklistItems
            for item_data in checklist_data.get('items', []):
                old_item_id = item_data.get('id')
                if old_item_id is None:
                    logger.error(f"Skipping checklist item for checklist {old_checklist_id} due to missing 'id': {item_data}")
                    return False, f"Invalid item data (missing id) for checklist {old_checklist_id}", None

                new_item = ChecklistItem(
                    checklist_id=new_checklist.id,
                    item_text=item_data.get('item_text', ''),
                    is_checked=item_data.get('is_checked', False),
                    comments=item_data.get('comments', '')
                )
                db.session.add(new_item)
                db.session.flush()
                old_to_new_checklist_item_ids[old_item_id] = new_item.id

                # ChecklistItem Attachments
                for ci_att_data in item_data.get('attachments', []):
                    imported_ci_att = _import_attachment_file_local(ci_att_data, 'checklist_item_id', new_item.id, extracted_project_base_path)
                    if imported_ci_att:
                        db.session.add(imported_ci_att)
                    # else:
                        # return False, f"Failed to import attachment for checklist item {old_item_id}", None

        db.session.commit()
        logger.info(f"Successfully imported project '{new_project_name}' (New ID: {new_project.id}) for user {importing_user_id}")
        return True, new_project_name, new_project.id

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error in _perform_single_project_import for project {data.get('project',{}).get('id', 'UNKNOWN_OLD_ID')}: {e}", exc_info=True)
        return False, f"An unexpected error occurred during import: {str(e)}", None


@app.route('/project/<int:project_id>/export')
@login_required
def export_project(project_id):
    project = Project.query.get_or_404(project_id) # Ensure project exists
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()

    # Check if user has admin role for this specific project
    if not access or access.role != 'admin':
        flash('You do not have permission to export this project.', 'error')
        # Redirect to the new project data management page if accessed from there,
        # or to index if referrer is not available/not that page.
        if request.referrer and 'project_data_management' in request.referrer:
            return redirect(url_for('project_data_management'))
        return redirect(url_for('project_detail', project_id=project_id)) # Fallback, though less likely now

    export_temp_dir = None  # Initialize to None for finally block
    try:
        export_temp_dir = tempfile.mkdtemp()
        logger.info(f"Created temporary directory for single project export: {export_temp_dir}")

        # _export_single_project_to_zip is expected to create the zip inside export_temp_dir
        # and return the full path to the zip file.
        zip_file_path = _export_single_project_to_zip(project_id, export_temp_dir)

        if zip_file_path and os.path.exists(zip_file_path):
            logger.info(f"Project {project_id} successfully exported to ZIP: {zip_file_path}")
            return send_file(zip_file_path, as_attachment=True, download_name=os.path.basename(zip_file_path))
        else:
            logger.error(f"Export failed for project {project_id}. Helper did not return a valid ZIP file path or file does not exist.")
            flash('Failed to export project. The export process did not generate a file. Please check server logs for details.', 'error')
            if request.referrer and 'project_data_management' in request.referrer:
                return redirect(url_for('project_data_management'))
            return redirect(url_for('project_detail', project_id=project_id)) # Fallback

    except Exception as e:
        logger.error(f"Exception during export_project for project_id {project_id}: {e}", exc_info=True)
        flash(f"An unexpected error occurred during project export: {str(e)}", 'error')
        if request.referrer and 'project_data_management' in request.referrer:
            return redirect(url_for('project_data_management'))
        return redirect(url_for('project_detail', project_id=project_id)) # Fallback
    finally:
        if export_temp_dir and os.path.exists(export_temp_dir):
            try:
                shutil.rmtree(export_temp_dir)
                logger.info(f"Successfully cleaned up temporary export directory: {export_temp_dir}")
            except Exception as e_clean:
                logger.error(f"Error cleaning up temporary export directory {export_temp_dir}: {e_clean}", exc_info=True)


@app.route('/admin/import_project', methods=['POST'])
@login_required
def import_project():
    if current_user.role != 'admin':
        flash('You are not authorized to perform this action.', 'error')
        return redirect(url_for('index'))

    if 'project_zip' not in request.files:
        flash('No file part in the request.', 'error')
        return redirect(request.referrer or url_for('index'))

    file = request.files['project_zip']
    uploaded_master_zip_filename = file.filename # Store the master ZIP filename
    if file.filename == '':
        flash('No file selected for upload.', 'error')
        return redirect(request.referrer or url_for('index'))

    if not file.filename.lower().endswith('.zip'):
        flash('Invalid file type. Only .zip files are allowed.', 'error')
        return redirect(request.referrer or url_for('index'))

    extraction_temp_dir = None
    try:
        extraction_temp_dir = tempfile.mkdtemp()
        zip_path = os.path.join(extraction_temp_dir, secure_filename(file.filename))
        file.save(zip_path)

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extraction_temp_dir)

        logger.debug(f"Contents of extraction_temp_dir before glob: {os.listdir(extraction_temp_dir)}")
        project_data_json_path = os.path.join(extraction_temp_dir, 'project_data.json')

        if os.path.exists(project_data_json_path):
            # Single project ZIP
            logger.info(f"Attempting single project import from: {extraction_temp_dir}")
            success, message, new_project_id = _perform_single_project_import(extraction_temp_dir, current_user.id)
            if success:
                flash(f"Project '{message}' imported successfully!", 'success')
                return redirect(url_for('project_detail', project_id=new_project_id))
            # If single project import failed, ensure we redirect and exit.
            flash(f"Failed to import project: {message}", 'error')
            return redirect(url_for('index'))
        else: # project_data.json not found at root
            logger.info("project_data.json not found at root. Checking for inner ZIP files (master export).")
            inner_zip_files = glob.glob(os.path.join(extraction_temp_dir, '*.zip'))

            if not inner_zip_files: # Invalid format: No project_data.json at root AND no inner zips
                logger.warning(f"No project_data.json at root and no inner ZIPs found in {extraction_temp_dir}. Treating as invalid format.")
                flash("The uploaded ZIP file does not appear to be a valid single project (missing project_data.json at root) and does not contain any inner project .zip files. Please check the ZIP file structure.", "error")
                return redirect(url_for('index'))

            # Master ZIP detected (inner_zip_files is not empty)
            logger.info(f"Found potential inner project ZIPs: {inner_zip_files}")
            successful_imports_names = []
            failed_imports_details = []

            # This 'if' block now correctly encompasses the master ZIP processing
            if inner_zip_files:
                for inner_zip_path in inner_zip_files:
                    # *** ADDED BLOCK TO SKIP MASTER ZIP IF FOUND INSIDE ITSELF ***
                    current_inner_zip_filename = os.path.basename(inner_zip_path)
                    if current_inner_zip_filename == uploaded_master_zip_filename:
                        logger.warning(f"Skipping processing of master ZIP file ('{current_inner_zip_filename}') found within its own extracted contents. This is a safeguard.")
                        continue
                    # *** END OF ADDED BLOCK ***
                    current_inner_project_dir = None
                    inner_zip_filename = os.path.basename(inner_zip_path) # This line is now redundant due to the block above, but harmless
                    try:
                        current_inner_project_dir = tempfile.mkdtemp()
                        with zipfile.ZipFile(inner_zip_path, 'r') as inner_zip_ref:
                            inner_zip_ref.extractall(current_inner_project_dir)

                        if not os.path.exists(os.path.join(current_inner_project_dir, 'project_data.json')):
                            logger.warning(f"Inner ZIP '{inner_zip_filename}' does not contain project_data.json at its root.")
                            failed_imports_details.append({'name': inner_zip_filename, 'reason': 'project_data.json not found'})
                            if current_inner_project_dir and os.path.exists(current_inner_project_dir): # Cleanup inner dir
                                shutil.rmtree(current_inner_project_dir)
                            continue

                        logger.info(f"Attempting import of inner project from: {current_inner_project_dir} (Original name: {inner_zip_filename})")
                        success, message, new_project_id = _perform_single_project_import(current_inner_project_dir, current_user.id)
                        if success:
                            successful_imports_names.append(message)
                        else:
                            failed_imports_details.append({'name': inner_zip_filename, 'reason': message})
                    except zipfile.BadZipFile:
                        logger.error(f"Inner ZIP file '{inner_zip_filename}' is corrupted or not a valid ZIP.")
                        failed_imports_details.append({'name': inner_zip_filename, 'reason': 'Corrupted or invalid ZIP file'})
                    except Exception as e_inner:
                        logger.error(f"Error processing inner ZIP '{inner_zip_filename}': {str(e_inner)}", exc_info=True)
                        failed_imports_details.append({'name': inner_zip_filename, 'reason': f'Unexpected error: {str(e_inner)}'})
                    finally:
                        if current_inner_project_dir and os.path.exists(current_inner_project_dir):
                            shutil.rmtree(current_inner_project_dir)

                logger.debug(f"Before building master ZIP summary flash: successful_imports_names = {successful_imports_names}")
                logger.debug(f"Before building master ZIP summary flash: failed_imports_details = {failed_imports_details}")
                # Flash message logic for master ZIP processing outcomes
                if successful_imports_names or failed_imports_details: # Only flash summary if attempts were made on inner zips
                    flash_messages_parts = []
                    if successful_imports_names:
                        flash_messages_parts.append(f"Successfully imported: {', '.join(successful_imports_names)}.")
                    if failed_imports_details:
                        failed_strings = [f"'{item['name']}' ({item['reason']})" for item in failed_imports_details]
                        flash_messages_parts.append(f"Failed to import: {'; '.join(failed_strings)}.")

                    final_message = " ".join(flash_messages_parts)
                    if not successful_imports_names and failed_imports_details:
                        flash(final_message, "error")
                    elif successful_imports_names and failed_imports_details:
                        flash(final_message, "warning")
                    elif successful_imports_names and not failed_imports_details:
                        flash(final_message, "success")
                    # else: No explicit message if flash_messages_parts is empty, implying no processable inner zips.
                else: # This means inner_zip_files was true, but the loop didn't populate success/failure (e.g. all inner zips were empty/corrupt before _perform_single_project_import)
                    flash("Master ZIP processed, but no valid project data was found in the inner ZIP files, or inner ZIPs were empty/corrupt.", "warning")
                return redirect(url_for('index'))

            else: # This 'else' corresponds to 'if not inner_zip_files' - Invalid Format Path
                  # This block should have already been executed and returned if no inner_zip_files were found.
                  # Re-affirming the logger and flash for clarity, though the previous structure should handle this.
                logger.warning(f"No project_data.json at root and no inner ZIPs found in {extraction_temp_dir}. Treating as invalid format.")
                flash("The uploaded ZIP file does not appear to be a valid single project (missing project_data.json at root) and does not contain any inner project .zip files. Please check the ZIP file structure.", "error")
                return redirect(url_for('index'))

    except zipfile.BadZipFile:
        logger.error("Uploaded file is corrupted or not a valid ZIP file.")
        flash('The uploaded file is corrupted or not a valid ZIP file.', 'error')
        return redirect(request.referrer or url_for('index'))
    except Exception as e:
        logger.error(f"An unexpected error occurred during project import: {str(e)}", exc_info=True)
        flash(f'An unexpected error occurred: {str(e)}', 'error')
        return redirect(request.referrer or url_for('index'))
    finally:
        if extraction_temp_dir and os.path.exists(extraction_temp_dir):
            shutil.rmtree(extraction_temp_dir)


@app.route('/admin/export_all_projects')
@login_required
def export_all_projects():
    if current_user.role != 'admin':
        flash('You are not authorized to perform this action.', 'error')
        return redirect(url_for('index'))

    admin_project_accesses = ProjectAccess.query.filter_by(user_id=current_user.id, role='admin').all()
    project_ids_to_export = [pa.project_id for pa in admin_project_accesses]

    projects_to_export = Project.query.filter(Project.id.in_(project_ids_to_export)).all()

    if not projects_to_export:
        flash('No projects found for you to export.', 'info')
        return redirect(url_for('project_data_management'))

    main_temp_dir_for_individual_zips = None
    master_zip_temp_dir = None
    master_zip_archive_path = None

    try:
        main_temp_dir_for_individual_zips = tempfile.mkdtemp()
        master_zip_temp_dir = tempfile.mkdtemp()

        successful_individual_zip_paths = []
        failed_project_names = []

        for project in projects_to_export:
            try:
                # _export_single_project_to_zip is assumed to exist and take (project_id, target_directory_for_zip)
                # It should return the full path to the created zip file, or None/raise error on failure.
                # For this implementation, we'll assume it places the zip directly in main_temp_dir_for_individual_zips

                # Placeholder for where _export_single_project_to_zip would be called.
                # Since it's not defined in this subtask, we'll simulate its behavior.
                # This function needs to be implemented in a separate task.
                # For now, let's assume it's available and works.
                # if not hasattr(app, '_export_single_project_to_zip'):
                #     raise NotImplementedError("_export_single_project_to_zip is not implemented")

                individual_zip_path = _export_single_project_to_zip(project.id, main_temp_dir_for_individual_zips)

                if individual_zip_path and os.path.exists(individual_zip_path):
                    successful_individual_zip_paths.append(individual_zip_path)
                    logger.info(f"Successfully created individual ZIP for project '{project.name}' at {individual_zip_path}")
                else:
                    logger.error(f"Failed to create ZIP for project '{project.name}'. _export_single_project_to_zip returned: {individual_zip_path}")
                    failed_project_names.append(project.name)
            except Exception as e_single_export:
                logger.error(f"Error exporting project '{project.name}': {str(e_single_export)}", exc_info=True)
                failed_project_names.append(project.name)

        if not successful_individual_zip_paths:
            flash('No projects could be exported successfully.', 'error')
            if failed_project_names:
                flash(f"Failed projects: {', '.join(failed_project_names)}", 'error')
            return redirect(url_for('edit_profile'))

        master_zip_filename_base = f"MASTER_EXPORT_ALL_{current_user.id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        # shutil.make_archive will create a zip file containing the contents of main_temp_dir_for_individual_zips
        # The third argument to make_archive is the root directory to be zipped.
        master_zip_archive_path = shutil.make_archive(
            base_name=os.path.join(master_zip_temp_dir, master_zip_filename_base),
            format='zip',
            root_dir=main_temp_dir_for_individual_zips
        )
        logger.info(f"Master ZIP created at: {master_zip_archive_path}")

        # Construct a more user-friendly filename for the download
        download_filename = f"{master_zip_filename_base}.zip"

        if failed_project_names:
             flash(f"Successfully exported {len(successful_individual_zip_paths)} project(s). Failed to export: {', '.join(failed_project_names)}.", 'warning')
        else:
            flash(f"Successfully exported all {len(successful_individual_zip_paths)} accessible projects.", 'success')

        return send_file(master_zip_archive_path, as_attachment=True, download_name=download_filename)

    except Exception as e:
        logger.error(f"Error during 'export all projects': {str(e)}", exc_info=True)
        flash(f'An error occurred while exporting all projects: {str(e)}', 'error')
        return redirect(url_for('edit_profile'))
    finally:
        if main_temp_dir_for_individual_zips and os.path.exists(main_temp_dir_for_individual_zips):
            shutil.rmtree(main_temp_dir_for_individual_zips)
        if master_zip_temp_dir and os.path.exists(master_zip_temp_dir):
            # The master_zip_archive_path is inside master_zip_temp_dir.
            # send_file should handle its own temp file if it makes one,
            # but make_archive creates the file directly.
            # If send_file is asynchronous or doesn't block until file is sent,
            # removing master_zip_temp_dir too soon could be an issue.
            # However, for typical Flask send_file usage, this cleanup should be okay.
            # If issues arise, delaying this rmtree might be needed, e.g. using @after_this_request.
            # For now, assume direct cleanup is fine.
             shutil.rmtree(master_zip_temp_dir)
             logger.info(f"Cleaned up temporary master ZIP directory: {master_zip_temp_dir}")
        # No need to os.remove(master_zip_archive_path) separately if its parent dir is removed.

# Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        company = request.form['company'].strip()
        email = request.form['email'].strip() # Changed username to email
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = 'admin'

        if not name or not company:
            flash('Name and Company are required.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')

        # Server-side email validation (basic regex)
        import re
        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            flash('Invalid email format.', 'error')
            return render_template('register.html')

        if User.query.filter_by(email=email).first(): # Check if email is taken
            flash('This email is already registered. Please log in or use a different email.', 'error')
            return render_template('register.html')

        # For now, username will be the same as email.
        # Ensure username is unique if it's different from email in the future.
        if User.query.filter_by(username=email).first():
            flash('This username (derived from email) is already taken. This should not happen if email is unique.', 'error')
            return render_template('register.html')


        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        # User status defaults to 'pending_activation' as per model, so no need to set it explicitly.
        user = User(username=email, email=email, password=hashed_password, role=role, name=name, company=company)
        db.session.add(user)
        db.session.commit()

        # Generate confirmation token
        s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
        token = s.dumps(user.email, salt='email-confirm-salt') # Using email and a salt

        # Send confirmation email
        confirmation_link = url_for('confirm_email', token=token, _external=True)
        current_year = datetime.now().year
        html_body = render_template('email/confirmation_email.html',
                                    confirmation_link=confirmation_link,
                                    current_year=current_year)
        sender_name = app.config.get('MAIL_SENDER_NAME', 'Defect Tracker')
        sender_email = app.config.get('MAIL_DEFAULT_SENDER_EMAIL', 'noreply@defect-tracker.com')
        email_sender = (sender_name, sender_email)

        msg = Message(subject="Confirm Your Email - Defect Tracker",
                      sender=email_sender,
                      recipients=[user.email],
                      html=html_body)
        try:
            mail.send(msg)
            flash('Registration successful! A confirmation email has been sent to your email address. Please verify your email to activate your account.', 'info')
        except Exception as e:
            logger.error(f"Failed to send confirmation email to {user.email}: {str(e)}", exc_info=True)
            # Rollback user creation if email fails? For now, we'll let the user exist but unverified.
            # db.session.rollback()
            flash('Registration successful, but failed to send confirmation email. Please contact support.', 'warning')

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600) # 1 hour expiration
    except Exception as e: # Catches SignatureExpired, BadTimeSignature, BadSignature, etc.
        logger.warning(f"Email confirmation token validation failed. Token: {token}, Error: {str(e)}")
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found for this confirmation link.', 'danger')
        return redirect(url_for('login'))

    if user.status == 'active':
        flash('Your account is already active. Please log in.', 'info')
        return redirect(url_for('login'))

    user.status = 'active'
    db.session.commit()
    login_user(user) # Log the user in directly
    flash('Email confirmed! Your account is now active and you have been logged in.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        email = request.form['username'] # Login form still uses 'username' field for email
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if not user:
            user = User.query.filter_by(username=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            if user.status == 'pending_activation': # Check status before login
                flash('Please verify your email address before logging in. A confirmation email was sent to you upon registration.', 'warning')
                return redirect(url_for('login'))
            elif user.status == 'active':
                login_user(user)
                flash('Logged in successfully!', 'success')
                return redirect(url_for('index'))
            else: # Other statuses like 'suspended', 'deactivated' etc.
                flash('Your account is not active. Please contact support.', 'error')
                return redirect(url_for('login'))

        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# Replace your existing invite() function with this one
@app.route('/invite', methods=['GET', 'POST'])
@login_required
def invite():
    if current_user.role != 'admin':
        flash('Only admins can invite users.', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        admin_project_accesses = ProjectAccess.query.filter_by(user_id=current_user.id).all()
        admin_accessible_project_ids = {pa.project_id for pa in admin_project_accesses}

        recipient_email = request.form.get('email')
        if not recipient_email:
            return jsonify({'status': 'error', 'message': 'Recipient email is required.'}), 400

        submitted_project_ids_str = request.form.getlist('invite_project_ids')
        role = request.form.get('role')

        if not submitted_project_ids_str:
            return jsonify({'status': 'error', 'message': 'No projects selected.'}), 400

        # Validate submitted project IDs
        valid_project_ids_for_invite = []
        skipped_project_names = []
        processed_project_names = [] # For successful grants/updates

        for project_id_str in submitted_project_ids_str:
            try:
                project_id_int = int(project_id_str)
                if project_id_int not in admin_accessible_project_ids:
                    # Try to get project name for skipped message if it exists, even if admin can't access
                    project_obj_skipped = db.session.get(Project, project_id_int)
                    skipped_project_names.append(project_obj_skipped.name if project_obj_skipped else f"ID {project_id_int} (Unauthorized)")
                    logger.warning(f"Admin {current_user.username} attempted to invite to unauthorized project ID: {project_id_int}")
                    continue

                project_obj = db.session.get(Project, project_id_int)
                if not project_obj:
                    skipped_project_names.append(f"ID {project_id_int} (Not Found)")
                    logger.warning(f"Project ID {project_id_int} not found during invite, though admin had access rights.")
                    continue
                valid_project_ids_for_invite.append(project_id_int)
                # processed_project_names list will be populated later based on successful operations
            except ValueError:
                skipped_project_names.append(f"ID '{project_id_str}' (Invalid Format)")
                logger.warning(f"Invalid project ID format received in invite: {project_id_str}")
                continue

        if not valid_project_ids_for_invite:
            message = "No valid or accessible projects were selected."
            if skipped_project_names:
                message += f" Skipped: {', '.join(skipped_project_names)}."
            return jsonify({'status': 'error', 'message': message}), 400

        existing_user = User.query.filter_by(email=recipient_email, status='active').first()
        email_status = {}

        if existing_user:
            # Handle existing active user
            updated_count = 0
            newly_granted_count = 0
            for project_id in valid_project_ids_for_invite:
                project = db.session.get(Project, project_id) # Already validated that project exists
                if not project: continue # Should not happen

                project_access = ProjectAccess.query.filter_by(user_id=existing_user.id, project_id=project.id).first()
                if project_access:
                    if project_access.role != role:
                        project_access.role = role
                        logger.info(f"Updated role to '{role}' for existing user {existing_user.email} on project '{project.name}'.")
                        updated_count += 1
                        processed_project_names.append(project.name)
                else:
                    new_access = ProjectAccess(user_id=existing_user.id, project_id=project.id, role=role)
                    db.session.add(new_access)
                    logger.info(f"Granted new access to project '{project.name}' with role '{role}' for existing user {existing_user.email}.")
                    newly_granted_count += 1
                    processed_project_names.append(project.name)

            try:
                db.session.commit()
                projects_affected_msg = ""
                if processed_project_names:
                    projects_affected_msg = f" for project(s): {', '.join(list(set(processed_project_names)))}." # Use set to avoid duplicates if a project was listed twice

                response_message = f"Access granted/updated for existing user {existing_user.email}{projects_affected_msg}"
                if updated_count == 0 and newly_granted_count == 0 and not skipped_project_names:
                     response_message = f"No changes made. User {existing_user.email} already has the specified role(s) for the selected project(s)."

                if skipped_project_names:
                    response_message += f" Some projects/IDs were skipped: {', '.join(skipped_project_names)}."

                # Send notification email to existing user
                try:
                    with mail.connect() as conn:
                        current_year = datetime.now().year
                        html_body = render_template('email/invitation_email.html',
                                                    current_year=current_year,
                                                    existing_user_invite=True,
                                                    user_name=existing_user.name or existing_user.username,
                                                    projects_granted=[db.session.get(Project, pid).name for pid in valid_project_ids_for_invite if db.session.get(Project, pid)]) # Pass project names

                        sender_name = app.config.get('MAIL_SENDER_NAME', 'Defect Tracker')
                        sender_email = app.config.get('MAIL_DEFAULT_SENDER_EMAIL', 'noreply@defect-tracker.com')
                        email_sender = (sender_name, sender_email)

                        msg = Message(subject="Project Access Update - Defect Tracker",
                                      sender=email_sender,
                                      recipients=[recipient_email],
                                      html=html_body)
                        conn.send(msg)
                    email_status = {'sent': True, 'error': None}
                    logger.info(f"Notification email sent to existing user {recipient_email}.")
                except Exception as e_mail:
                    logger.error(f"Failed to send notification email to existing user {recipient_email}: {str(e_mail)}", exc_info=True)
                    email_status = {'sent': False, 'error': str(e_mail)}
                    response_message += " Email notification failed."

                return jsonify({
                    'status': 'success',
                    'message': response_message,
                    'email_info': email_status,
                    'invite_link': None # No invite link for existing users
                })
            except Exception as e_db:
                db.session.rollback()
                logger.error(f"Error updating access for existing user {recipient_email}: {str(e_db)}", exc_info=True)
                return jsonify({'status': 'error', 'message': 'Could not update access due to a server error.'}), 500
        else:
            # Handle new user (original logic)
            temp_username = f"temp_{os.urandom(8).hex()}"
            temp_password = os.urandom(16).hex() # This password is temporary and will be changed by user
            hashed_password = bcrypt.generate_password_hash(temp_password).decode('utf-8')

            # Check if a user (active or not) already exists with this email to avoid duplicate email errors
            # This is slightly different from the existing_user check which was for status='active'
            user_with_email_exists = User.query.filter_by(email=recipient_email).first()
            if user_with_email_exists:
                # If user exists but not active, or some other state, admin might need to manage that user directly.
                # For now, prevent creating a new temp user with the same email.
                return jsonify({'status': 'error', 'message': f"A user with email {recipient_email} already exists. If they are not active, please manage their account or ask them to complete activation."}), 409 # 409 Conflict

            user = User(username=temp_username, email=recipient_email, password=hashed_password, role=role, status='pending_activation') # Ensure status is pending
            db.session.add(user)
            db.session.flush() # Get user.id

            for project_id in valid_project_ids_for_invite:
                project = db.session.get(Project, project_id) # Already validated
                if project: # Should always be true here
                    access = ProjectAccess(user_id=user.id, project_id=project.id, role=role)
                    db.session.add(access)
                    processed_project_names.append(project.name)


            s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
            token = s.dumps({'user_id': user.id}) # Token now contains temporary user_id
            invite_link = url_for('accept_invite', token=token, _external=True)

            try:
                db.session.commit()
                projects_granted_msg = ""
                if processed_project_names:
                    projects_granted_msg = f" for project(s): {', '.join(list(set(processed_project_names)))}"

                logger.info(f"Temporary user {user.username} (ID: {user.id}) and access to {len(valid_project_ids_for_invite)} projects committed.")

                try:
                    with mail.connect() as conn:
                        current_year = datetime.now().year
                        html_body = render_template('email/invitation_email.html',
                                                    invite_link=invite_link,
                                                    current_year=current_year,
                                                    existing_user_invite=False) # Explicitly false for new user

                        sender_name = app.config.get('MAIL_SENDER_NAME', 'Defect Tracker')
                        sender_email = app.config.get('MAIL_DEFAULT_SENDER_EMAIL', 'noreply@defect-tracker.com')
                        email_sender = (sender_name, sender_email)

                        msg = Message(subject="You're invited to Defect Tracker",
                                      sender=email_sender,
                                      recipients=[recipient_email],
                                      html=html_body)
                        conn.send(msg)
                    email_status = {'sent': True, 'error': None}
                    logger.info(f"Invitation email sent to {recipient_email} for new user ID {user.id}.")
                except Exception as e_mail:
                    logger.error(f"Failed to send invitation email to {recipient_email} for new user ID {user.id}: {str(e_mail)}", exc_info=True)
                    email_status = {'sent': False, 'error': str(e_mail)}

                response_message = f"Invitation link generated for {recipient_email}{projects_granted_msg}."
                if skipped_project_names:
                    response_message += f" Some projects/IDs were skipped: {', '.join(skipped_project_names)}."
                if not email_status.get('sent'):
                     response_message += " Email sending failed."

                return jsonify({
                    'status': 'success',
                    'invite_link': invite_link,
                    'message': response_message,
                    'email_info': email_status
                })
            except Exception as e_db:
                db.session.rollback()
                logger.error(f"Error during new user invite DB operations: {str(e_db)}", exc_info=True)
                return jsonify({'status': 'error', 'message': 'Could not process invitation due to a server error.'}), 500

    # GET request
    # Fetch projects manageable by the current admin to populate the form
    admin_project_accesses_get = ProjectAccess.query.filter_by(user_id=current_user.id).all()
    admin_project_ids_get = [pa.project_id for pa in admin_project_accesses_get]
    if admin_project_ids_get:
        manageable_projects_for_form = Project.query.filter(Project.id.in_(admin_project_ids_get)).order_by(Project.name).all()
    else:
        manageable_projects_for_form = []
    return render_template('invite.html', projects=manageable_projects_for_form)


@app.route('/manage_access', methods=['GET', 'POST'])
@login_required
def manage_access():
    allowed_roles_to_view = ['admin', 'expert', 'contractor', 'supervisor']
    if current_user.role not in allowed_roles_to_view:
        flash('You do not have permission to view this page.', 'error')
        return redirect(url_for('index'))

    is_admin_view = (current_user.role == 'admin')

    if request.method == 'POST':
        if not is_admin_view:
            flash('You do not have permission to perform this action.', 'error')
            return redirect(url_for('manage_access'))

        action = request.form.get('action')
        if action == 'grant_access':
            # First, get the set of project IDs the current admin can manage
            admin_project_accesses_for_post_action = ProjectAccess.query.filter_by(user_id=current_user.id).all()
            admin_accessible_project_ids = {pa.project_id for pa in admin_project_accesses_for_post_action}

            user_id_str = request.form.get('user_id')
            project_ids_from_form = request.form.getlist('project_ids')
            # role = request.form.get('role') # Removed

            if not user_id_str or not project_ids_from_form: # 'or not role' Removed
                flash('User and project(s) are required.', 'error') # Flash message updated
                return redirect(url_for('manage_access'))

            try:
                user_id = int(user_id_str)
            except ValueError:
                flash('Invalid user ID format.', 'error')
                return redirect(url_for('manage_access'))

            user = db.session.get(User, user_id)
            if not user:
                flash('Selected user not found.', 'error')
                return redirect(url_for('manage_access'))

            role_to_assign = user.role # Assign role from user's global role

            successfully_processed_count = 0
            skipped_projects_count = 0
            
            for project_id_str_from_form in project_ids_from_form:
                try:
                    submitted_project_id = int(project_id_str_from_form)
                except ValueError:
                    logger.warning(f"Invalid project ID format received: {project_id_str_from_form}")
                    skipped_projects_count += 1
                    continue

                if submitted_project_id not in admin_accessible_project_ids:
                    logger.warning(f"Admin {current_user.username} (ID: {current_user.id}) attempted to grant access to unauthorized project ID: {submitted_project_id}")
                    skipped_projects_count += 1
                    continue

                project = db.session.get(Project, submitted_project_id)
                if not project: # Should not happen if admin_accessible_project_ids is accurate, but good check
                    flash(f'Project with ID {submitted_project_id} not found, though admin had access.', 'error')
                    skipped_projects_count += 1
                    continue 

                project_access = ProjectAccess.query.filter_by(user_id=user.id, project_id=project.id).first()
                if project_access:
                    if project_access.role != role_to_assign:
                        project_access.role = role_to_assign
                        logger.info(f"Updated access for user {user.username} to project {project.name} with role {role_to_assign} (based on global role)")
                        successfully_processed_count +=1 # Count as processed if role changed
                    # If role is the same, we don't count it as a new "successful update" for messaging
                else:
                    project_access = ProjectAccess(user_id=user.id, project_id=project.id, role=role_to_assign)
                    db.session.add(project_access)
                    logger.info(f"Granted access for user {user.username} to project {project.name} with role {role_to_assign} (based on global role)")
                    successfully_processed_count +=1
            
            if successfully_processed_count > 0:
                try:
                    db.session.commit()
                    flash_message = f'User access updated for {successfully_processed_count} project(s).'
                    if skipped_projects_count > 0:
                        flash_message += f' {skipped_projects_count} project(s) were skipped due to insufficient permissions or invalid ID.'
                    flash(flash_message, 'success' if skipped_projects_count == 0 else 'warning')
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error updating project access for user {user.id}: {str(e)}")
                    flash('Error updating user access. Please try again.', 'error')
            else:
                if skipped_projects_count > 0:
                    flash(f'No projects were updated. {skipped_projects_count} project(s) were skipped due to insufficient permissions or invalid ID.', 'warning')
                else:
                    flash('No changes made to user access (user may already have access with their global role on selected projects).', 'info')
            return redirect(url_for('manage_access'))

    # Data for GET request
    projects_for_forms = []
    relevant_users_to_display = []
    project_ids_to_filter_table_rows = []

    if is_admin_view:
        # Admin: Load projects they administer for forms, and users on those projects
        admin_project_accesses_get = ProjectAccess.query.filter_by(user_id=current_user.id, role='admin').all()
        project_ids_admin_administers = [pa.project_id for pa in admin_project_accesses_get]
        project_ids_to_filter_table_rows = project_ids_admin_administers

        if project_ids_admin_administers:
            projects_for_forms = Project.query.filter(Project.id.in_(project_ids_admin_administers)).order_by(Project.name).all()

            # Fetch all ProjectAccess entries for projects managed by this admin
            shared_project_access_entries = ProjectAccess.query.filter(
                ProjectAccess.project_id.in_(project_ids_admin_administers)
            ).all()

            if shared_project_access_entries:
                user_ids_on_shared_projects = {pa.user_id for pa in shared_project_access_entries}
                if user_ids_on_shared_projects:
                    relevant_users_to_display = User.query.filter(
                        User.id.in_(user_ids_on_shared_projects),
                        User.id != current_user.id, # Exclude current admin from the list
                        User.status == 'active'
                    ).all()
    else: # For 'expert', 'contractor', 'supervisor'
        # Non-admin: Load projects they are part of, and users on those projects
        current_user_project_accesses = ProjectAccess.query.filter_by(user_id=current_user.id).all()
        project_ids_user_is_on = [pa.project_id for pa in current_user_project_accesses]
        project_ids_to_filter_table_rows = project_ids_user_is_on

        if project_ids_user_is_on:
            # Fetch all ProjectAccess entries for projects the current user is part of
            shared_project_access_entries = ProjectAccess.query.filter(
                ProjectAccess.project_id.in_(project_ids_user_is_on)
            ).all()
            if shared_project_access_entries:
                user_ids_on_shared_projects = {pa.user_id for pa in shared_project_access_entries}
                if user_ids_on_shared_projects:
                    relevant_users_to_display = User.query.filter(
                        User.id.in_(user_ids_on_shared_projects),
                        User.id != current_user.id, # Still exclude self from the list
                        User.status == 'active'
                    ).all()
        # projects_for_forms remains empty as these forms will be hidden for non-admins

    return render_template('manage_access.html',
                           users=relevant_users_to_display,
                           projects_for_forms=projects_for_forms,
                           project_ids_for_filter=project_ids_to_filter_table_rows,
                           is_admin_view=is_admin_view)


@app.route('/revoke_access/<int:project_access_id>', methods=['POST'])
@login_required
def revoke_access(project_access_id):
    if current_user.role != 'admin':
        flash('Only admins can revoke access.', 'error')
        return redirect(url_for('manage_access'))

    project_access_entry = db.session.get(ProjectAccess, project_access_id)

    if project_access_entry:
        target_user = project_access_entry.user
        if target_user and target_user.role == 'admin' and target_user.id != current_user.id:
            flash('Project access for a global admin user cannot be revoked by another admin via this page.', 'warning')
            return redirect(url_for('manage_access'))
        try:
            db.session.delete(project_access_entry)
            db.session.commit()
            flash('Access revoked successfully.', 'success')
            logger.info(f"Revoked access for ProjectAccess ID: {project_access_id} by admin {current_user.username}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error revoking access for ProjectAccess ID {project_access_id}: {str(e)}")
            flash('Error revoking access. Please try again.', 'error')
    else:
        flash('Project access entry not found.', 'error')
        logger.warning(f"Attempt to revoke non-existent ProjectAccess ID: {project_access_id} by admin {current_user.username}")
    
    return redirect(url_for('manage_access'))

@app.route('/accept_invite/<token>', methods=['GET', 'POST'])
def accept_invite(token):
    if current_user.is_authenticated:
        logout_user()
    try:
        s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
        data = s.loads(token, max_age=86400)
        user = db.session.get(User, data['user_id'])
        if not user:
            flash('Invalid or expired invitation.', 'error')
            return redirect(url_for('login'))
        if request.method == 'POST':
            name = request.form['name'].strip()
            company = request.form['company'].strip()
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            if not name or not company:
                flash('Name and Company are required.', 'error')
                # Pass email back to template as it's needed for display
                return redirect(url_for('accept_invite', token=token, email=user.email))

            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return redirect(url_for('accept_invite', token=token, email=user.email))

            user.name = name
            user.company = company
            user.username = user.email
            user.status = 'active'
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            login_user(user)
            flash('Invitation accepted! You are now logged in.', 'success')
            return redirect(url_for('index'))
        return render_template('accept_invite.html', token=token, email=user.email)
    except Exception as e:
        flash('Invalid or expired invitation.', 'error')
        return redirect(url_for('login'))

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        name = request.form['name'].strip()
        company = request.form['company'].strip()
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_new_password']

        if not name or not company:
            flash('Name and Company are required fields.', 'error')
            # Re-render with current data to avoid losing other valid inputs or context
            return render_template('edit_profile.html',
                                   user=current_user,
                                   name=name if name else current_user.name,  # Use entered value or original
                                   company=company if company else current_user.company,
                                   project_accesses=current_user.projects)

        current_user.name = name
        current_user.company = company

        password_changed = False
        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match.', 'error')
                return render_template('edit_profile.html',
                                       user=current_user,
                                       name=current_user.name,
                                       company=current_user.company,
                                       project_accesses=current_user.projects)
            current_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            password_changed = True

        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
            if password_changed:
                flash('Password updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'error')
            logger.error(f"Error updating profile for user {current_user.username}: {str(e)}")

        return redirect(url_for('edit_profile'))

    # For GET request
    # The current_user object is already loaded by Flask-Login and is available.
    # current_user.projects should provide ProjectAccess objects.
    project_accesses = [
        pa for pa in current_user.projects
        if pa.project and pa.project.name
    ]
    return render_template('edit_profile.html',
                           user=current_user,
                           name=current_user.name,
                           company=current_user.company,
                           project_accesses=project_accesses)

@app.route('/project_data_management')
@login_required
def project_data_management():
    if current_user.role != 'admin':
        flash('You are not authorized to access this page.', 'error')
        return redirect(url_for('index'))

    projects = Project.query.order_by(Project.name).all()
    return render_template('project_import_export.html', projects=projects)

# Application Routes
@app.route('/')
@login_required
def index():
    # Get project IDs where the user has access (either as creator or assigned)
    project_ids = [access.project_id for access in current_user.projects]
    projects_query = Project.query.filter(Project.id.in_(project_ids))

    projects_data = []
    for project in projects_query.all():
        open_defects_count = Defect.query.filter_by(project_id=project.id, status='open').count()

        # Calculate open_defects_with_reply_count with new logic
        count_open_defects_with_other_user_reply = 0
        all_open_defects = Defect.query.filter_by(project_id=project.id, status='open').all()
        for defect in all_open_defects:
            last_comment = Comment.query.filter_by(defect_id=defect.id).order_by(Comment.created_at.desc()).first()
            if last_comment and last_comment.user_id != current_user.id:
                count_open_defects_with_other_user_reply += 1
        open_defects_with_reply_count = count_open_defects_with_other_user_reply

        open_checklists_count = Checklist.query.filter(
            Checklist.project_id == project.id,
            Checklist.items.any(ChecklistItem.is_checked == False)
        ).count()

        products_waiting_for_proposal_count = ProductApproval.query.filter_by(
            project_id=project.id,
            status='waiting_for_proposal'
        ).count()

        products_provided_waiting_for_approval_count = ProductApproval.query.filter_by(
            project_id=project.id,
            status='product_provided'
        ).count()

        products_rejected_count = ProductApproval.query.filter_by(
            project_id=project.id,
            status='rejected'
        ).count()

        projects_data.append({
            'project': project,
            'open_defects_count': open_defects_count,
            'open_defects_with_reply_count': open_defects_with_reply_count,
            'open_checklists_count': open_checklists_count,
            'products_waiting_for_proposal_count': products_waiting_for_proposal_count,
            'products_provided_waiting_for_approval_count': products_provided_waiting_for_approval_count,
            'products_rejected_count': products_rejected_count,
        })

    return render_template('project_list.html', projects_data=projects_data)

@app.errorhandler(413)
def request_entity_too_large(error):
    flash('File too large. Maximum upload size is 16MB.', 'error')
    return redirect(request.url), 413

@app.route('/add_project', methods=['GET', 'POST'])
@login_required
def add_project():
    if current_user.role != 'admin':
        flash('Only admins can create projects.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        if name:
            project = Project(name=name)
            db.session.add(project)
            db.session.commit()
            access = ProjectAccess(user_id=current_user.id, project_id=project.id, role='admin')
            db.session.add(access)
            db.session.commit()
            flash('Project added successfully!', 'success')
            return redirect(url_for('index'))
        flash('Project name is required!', 'error')
    return render_template('add_project.html')

@app.route('/project/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    if current_user.role != 'admin':
        flash('Only admins can delete projects.', 'error')
        return redirect(url_for('index'))
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id, role='admin').first()
    if not access:
        flash('You do not have permission to delete this project.', 'error')
        return redirect(url_for('index'))
    # Delete drawing files
    for drawing in project.drawings:
        file_path = os.path.join(app.config['DRAWING_FOLDER'], os.path.basename(drawing.file_path))
        if os.path.exists(file_path):
            os.remove(file_path)
    # Delete attachment files
    for defect in project.defects:
        for attachment in defect.attachments:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path))
            thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.thumbnail_path)) if attachment.thumbnail_path else None
            if os.path.exists(file_path):
                os.remove(file_path)
            if thumbnail_path and os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)
    for checklist in project.checklists:
        for item in checklist.items:
            for attachment in item.attachments:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path))
                thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.thumbnail_path)) if attachment.thumbnail_path else None
                if os.path.exists(file_path):
                    os.remove(file_path)
                if thumbnail_path and os.path.exists(thumbnail_path):
                    os.remove(thumbnail_path)
    db.session.delete(project)
    db.session.commit()
    flash('Project deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/project/<int:project_id>')
@login_required
def project_detail(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access:
        flash('You do not have access to this project.', 'error')
        return redirect(url_for('index'))
    filter_status = request.args.get('filter', 'All')
    active_tab_override = request.args.get('active_tab_override', 'defects') # New line
    defects_query = Defect.query.filter_by(project_id=project_id)

    # Add this condition for expert users, but not for Technical Supervisors
    if current_user.role == 'expert' and current_user.role != 'Technical supervisor':
        defects_query = defects_query.filter_by(creator_id=current_user.id)
    # Technical supervisors should see all defects, so no additional filter is applied here for them.

    if filter_status == 'Open':
        defects = defects_query.filter_by(status='open').all()
    elif filter_status == 'OpenNoReply':
        defects = defects_query.filter_by(status='open').outerjoin(Defect.comments).filter(Comment.id == None).all()
    elif filter_status == 'OpenWithReply':
        open_defects = defects_query.filter_by(status='open').all()
        defects_with_reply_from_other = []
        for defect in open_defects:
            try:
                app.logger.info(f"[DEBUG_REDIRECT] Processing defect ID: {defect.id}, Desc: '{defect.description}' for OpenWithReply filter.")
                app.logger.info(f"[DEBUG_REDIRECT] Current user: ID={current_user.id}, Authenticated={current_user.is_authenticated}")

                last_comment = Comment.query.filter_by(defect_id=defect.id).order_by(Comment.created_at.desc()).first()

                if not last_comment:
                    app.logger.info(f"[DEBUG_REDIRECT] No last comment found for defect ID: {defect.id}.")
                    continue

                app.logger.info(f"[DEBUG_REDIRECT] Last comment for defect ID {defect.id}: CommentID={last_comment.id}, CommenterUserID={last_comment.user_id}")

                if last_comment.user_id != current_user.id:
                    app.logger.info(f"[DEBUG_REDIRECT] Defect ID {defect.id} will be INCLUDED (commenter {last_comment.user_id} != current_user {current_user.id}).")
                    defects_with_reply_from_other.append(defect)
                else:
                    app.logger.info(f"[DEBUG_REDIRECT] Defect ID {defect.id} will be EXCLUDED (commenter {last_comment.user_id} == current_user {current_user.id}).")

            except Exception as e:
                app.logger.error(f"[DEBUG_REDIRECT] EXCEPTION while processing defect ID {defect.id} in OpenWithReply: {str(e)}", exc_info=True)
                # continue # Optional: to continue processing other defects if one fails
        defects = defects_with_reply_from_other
    elif filter_status == 'Closed':
        defects = defects_query.filter_by(status='closed').all()
    else: # All
        defects = defects_query.all()

    for defect in defects:
        defect.first_thumbnail_path = None
        defect.first_attachment_file_path = None
        defect.first_attachment_id = None
        defect.has_marker = False
        if defect.attachments:
            first_attachment = defect.attachments[0]
            defect.first_thumbnail_path = first_attachment.thumbnail_path
            defect.first_attachment_file_path = first_attachment.file_path
            defect.first_attachment_id = first_attachment.id

        defect.marker_data = None
        if defect.markers:
            defect.has_marker = True
            first_marker = defect.markers[0]
            # Ensure drawing is loaded to prevent DetachedInstanceError if accessed later
            # by touching first_marker.drawing.file_path once
            _ = first_marker.drawing.file_path
            defect.marker_data = {
                'file_path': first_marker.drawing.file_path,
                'x': first_marker.x,
                'y': first_marker.y
                # 'page_num': getattr(first_marker, 'page_num', 1) # Assuming page 1 for now
            }


    checklists_query = Checklist.query.filter_by(project_id=project_id)
    # The user story implies filtering on the main 'filter' parameter.
    # So, filter_status (from request.args.get('filter', 'All')) will drive both.

    checklists = checklists_query.all()
    filtered_checklists = []

    for checklist in checklists:
        items = ChecklistItem.query.filter_by(checklist_id=checklist.id).all()

        all_items_checked = True # Assume all checked initially
        if not items: # If a checklist has no items
            all_items_checked = True # Corrected: Empty checklist is considered Closed.
        else: # Checklist has items
            all_items_checked = all(item.is_checked for item in items)

        # Now apply filter logic
        if filter_status == 'Open':
            if all_items_checked: # If all items are checked (i.e., it's Closed), skip it for 'Open' filter.
                continue
        elif filter_status == 'Closed':
            if not all_items_checked: # If not all items are checked (i.e., it's Open), skip it for 'Closed' filter.
                continue
        # If filter_status is 'All', or it matches the criteria, it's included.

        # Calculate completion status for display
        total_items = len(items)
        completed_items = sum(1 for item in items if item.is_checked)
        checklist.total_items = total_items
        checklist.completed_items = completed_items

        filtered_checklists.append(checklist)

    # Product Approvals Logic
    product_approvals_query = ProductApproval.query.filter_by(project_id=project_id).order_by(ProductApproval.request_date.desc())

    # Apply status filter for product approvals if a specific filter is active
    # Note: The 'filter_status' from request.args is currently tied to Defects/Checklists.
    # We might need a separate filter parameter for product approvals if their statuses are different
    # or if we want independent filtering. For now, let's assume we might reuse or adapt.
    # For simplicity, this example does not implement separate filtering for product approvals based on 'filter_status'
    # but shows how you would fetch them. You'll need to decide how filtering applies to this new tab.

    # Example: If you wanted to filter product approvals by their own status, you'd add another
    # request argument like `product_approval_filter=approved` and use that here.
    # product_approval_filter_status = request.args.get('product_approval_filter', 'All')
    # if product_approval_filter_status != 'All':
    #    product_approvals_query = product_approvals_query.filter(ProductApproval.status == product_approval_filter_status)

    product_approvals_for_template = product_approvals_query.options(
        joinedload(ProductApproval.documents).joinedload(ProductDocument.uploader),
        joinedload(ProductApproval.requester),
        joinedload(ProductApproval.contractor),
        joinedload(ProductApproval.approver)
    ).all()

    return render_template('project_detail.html', project=project, defects=defects, checklists=filtered_checklists, filter_status=filter_status, user_role=access.role, active_tab_name=active_tab_override, product_approvals=product_approvals_for_template) # Added product_approvals

@app.route('/project/<int:project_id>/add_drawing', methods=['GET', 'POST'])
@login_required
def add_drawing(project_id):
    if current_user.role != 'admin':
        flash('Only admins can add drawings.', 'error')
        return redirect(url_for('index'))
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        file = request.files['drawing']
        if not name or not file:
            flash('Name and file are required!', 'error')
            return redirect(url_for('add_drawing', project_id=project_id))
        if file and allowed_file(file.filename) and file.filename.lower().endswith('.pdf'):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = secure_filename(f'drawing_{project_id}_{timestamp}_{file.filename}')
            file_path = os.path.join(app.config['DRAWING_FOLDER'], filename)
            file.save(file_path)
            os.chmod(file_path, 0o644)
            drawing = Drawing(project_id=project_id, name=name, file_path=f'drawings/{filename}')
            db.session.add(drawing)
            db.session.commit()
            flash('Drawing added successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid file format. Only PDF files are allowed.', 'error')
    return render_template('add_drawing.html', project=project)

@app.route('/drawing/<int:drawing_id>/delete', methods=['POST'])
@login_required
def delete_drawing(drawing_id):
    if current_user.role != 'admin':
        flash('Only admins can delete drawings.', 'error')
        return redirect(url_for('index'))
    drawing = db.session.get(Drawing, drawing_id)
    if not drawing:
        flash('Drawing not found.', 'error')
        return redirect(url_for('index'))
    file_path = os.path.join(app.config['DRAWING_FOLDER'], os.path.basename(drawing.file_path))
    if os.path.exists(file_path):
        os.remove(file_path)
    db.session.delete(drawing)
    db.session.commit()
    flash('Drawing deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/project/<int:project_id>/drawing/<int:drawing_id>')
@login_required
def view_drawing(project_id, drawing_id):
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access:
        flash('You do not have access to this project.', 'error')
        return redirect(url_for('index'))
    drawing = db.session.get(Drawing, drawing_id)
    if not drawing or drawing.project_id != project_id:
        flash('Drawing not found.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))

    # Updated query to eagerly load related defect, creator, and defect attachments
    markers_query = DefectMarker.query.options(
        joinedload(DefectMarker.defect).joinedload(Defect.creator),
        joinedload(DefectMarker.defect).joinedload(Defect.attachments)
    ).filter_by(drawing_id=drawing_id)

    markers = markers_query.all()

    markers_data = []
    user_role = current_user.role # Use global current_user.role for filtering logic

    for marker in markers:
        if not marker.defect: # Skip if marker is orphaned (should not happen with good data integrity)
            continue

        defect = marker.defect
        include_marker = False

        if user_role in ['admin', 'contractor', 'supervisor']:
            if defect.status == 'open':
                include_marker = True
        elif user_role == 'expert':
            if defect.status == 'open' and defect.creator_id == current_user.id:
                include_marker = True

        if include_marker:
            creator_name = defect.creator.username if defect.creator else "N/A"
            creation_date_formatted = defect.creation_date.strftime('%Y-%m-%d %H:%M') if defect.creation_date else "N/A"

            # Perform a direct query for attachments for this specific defect
            app.logger.info(f"DEBUG_POPUP: Processing marker for defect ID: {defect.id}")
            current_defect_attachments = Attachment.query.filter_by(defect_id=defect.id).all()
            attachment_thumbnail_url = None  # Initialize to None

            if current_defect_attachments:
                app.logger.info(f"DEBUG_POPUP: Defect ID {defect.id} - Found {len(current_defect_attachments)} attachments.")
                for attachment in current_defect_attachments:
                    app.logger.info(f"DEBUG_POPUP: Defect ID {defect.id} - Checking attachment ID: {attachment.id}, Path: '{attachment.file_path}', Thumb: '{attachment.thumbnail_path}', MIME: '{attachment.mime_type}'")
                    is_image = False
                    # Check MIME type first
                    if attachment.mime_type and attachment.mime_type.startswith('image/'):
                        is_image = True
                    # Fallback to file extension if MIME type is missing or not explicitly image
                    elif attachment.file_path:
                        filename_lower = attachment.file_path.lower()
                        if filename_lower.endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
                            is_image = True

                    if is_image:
                        # Prefer thumbnail_path, fallback to file_path if thumbnail is missing
                        image_file_to_use = None
                        if attachment.thumbnail_path and attachment.thumbnail_path.strip():
                            image_file_to_use = attachment.thumbnail_path.strip()
                        elif attachment.file_path and attachment.file_path.strip(): # Fallback to main image if no thumb
                            image_file_to_use = attachment.file_path.strip()

                        if image_file_to_use:
                            app.logger.info(f"DEBUG_POPUP: Defect ID {defect.id} - Selected image_file_to_use: '{image_file_to_use}' for attachment ID: {attachment.id}")
                            try:
                                # Ensure url_for is called within an app context if this code
                                # were ever moved outside a request handler.
                                # Here, it's fine as it's in a route.
                                attachment_thumbnail_url = url_for('static', filename=image_file_to_use)
                                app.logger.info(f"DEBUG_POPUP: Defect ID {defect.id} - Generated attachment_thumbnail_url: '{attachment_thumbnail_url}' for attachment ID: {attachment.id}")
                                break  # Found the first suitable image attachment
                            except Exception as e:
                                # Log error if url_for fails for some reason
                                app.logger.error(f"Error generating URL for attachment {attachment.id} in view_drawing: {e}")
                                app.logger.info(f"DEBUG_POPUP: Defect ID {defect.id} - url_for failed for attachment ID: {attachment.id}. URL set to None.")
                                attachment_thumbnail_url = None # Reset on error

            app.logger.info(f"DEBUG_POPUP: Defect ID {defect.id} - Final attachment_thumbnail_url for markers_data: '{attachment_thumbnail_url}'")
            markers_data.append({
                'defect_id': marker.defect_id,
                'x': marker.x,
                'y': marker.y,
                'description': defect.description,
                'status': defect.status,
                'creator_name': creator_name,
                'creation_date_formatted': creation_date_formatted,
                'page_num': getattr(marker, 'page_num', 1), # Use getattr for safety, default to 1
                'attachment_thumbnail_url': attachment_thumbnail_url # This will now be the correct URL or None
            })

    return render_template('view_drawing.html', drawing=drawing, markers=markers_data, user_role=access.role)

@app.route('/project/<int:project_id>/add_defect', methods=['GET', 'POST'])
@login_required
def add_defect(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access:
        flash('You do not have access to this project.', 'error')
        return redirect(url_for('index'))
    drawings = Drawing.query.filter_by(project_id=project_id).all()
    # Serialize drawings to JSON-compatible format
    drawings_data = [
        {
            'id': drawing.id,
            'name': drawing.name,
            'file_path': drawing.file_path
        } for drawing in drawings
    ]
    logger.debug(f"Drawings data for project {project_id}: {drawings_data}")
    if request.method == 'POST':
        description = request.form.get('description', '').strip()
        drawing_id = request.form.get('drawing_id')
        marker_x = request.form.get('marker_x')
        marker_y = request.form.get('marker_y')
        if not description:
            flash('Description is required.', 'error')
            return redirect(url_for('add_defect', project_id=project_id))
        defect = Defect(
            project_id=project_id,
            creator_id=current_user.id,
            description=description,
            status='open',
            creation_date=datetime.now()
        )
        db.session.add(defect)
        db.session.commit()
        if drawing_id and marker_x and marker_y:
            try:
                marker_x = float(marker_x)
                marker_y = float(marker_y)
                if 0 <= marker_x <= 1 and 0 <= marker_y <= 1:
                    marker = DefectMarker(
                        defect_id=defect.id,
                        drawing_id=int(drawing_id),
                        x=marker_x,
                        y=marker_y
                    )
                    db.session.add(marker)
                    db.session.commit()
                    logger.debug(f"Marker saved for defect {defect.id}: x={marker_x}, y={marker_y}, drawing_id={drawing_id}")
                else:
                    flash('Marker coordinates out of bounds.', 'error')
                    logger.warning(f"Invalid marker coordinates: x={marker_x}, y={marker_y}")
            except ValueError:
                flash('Invalid marker coordinates.', 'error')
                logger.error(f"Failed to parse marker coordinates: x={marker_x}, y={marker_y}")
        # Handle attachments (if any)
        attachment_ids = []
        if 'photos' in request.files:
            files = request.files.getlist('photos')
            for file in files:
                if file and file.filename and allowed_file(file.filename): # Added file.filename check
                    mime_type = file.content_type
                    if mime_type.startswith('image/'):
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S%f') # Added %f for microseconds
                        original_filename_secure = secure_filename(file.filename)
                        # Use defect.id available after initial commit of defect
                        unique_filename_base = f"defect_{defect.id}_{timestamp}_{original_filename_secure}"

                        img_save_dir, thumb_save_dir = ensure_attachment_paths('attachments_img') # Uses new helper

                        original_save_path = os.path.join(img_save_dir, unique_filename_base)
                        file.seek(0) # Reset file pointer
                        file.save(original_save_path)
                        os.chmod(original_save_path, 0o644)
                        # DB path relative to 'static/uploads/'
                        file_path_for_db = os.path.join('uploads', 'attachments_img', unique_filename_base)

                        thumbnail_filename = f"thumb_{unique_filename_base}"
                        # thumbnail_save_path is the full disk path for saving thumbnail
                        thumbnail_save_path = os.path.join(thumb_save_dir, thumbnail_filename)

                        try:
                            create_thumbnail(original_save_path, thumbnail_save_path)
                            # DB path relative to 'static/uploads/'
                            thumbnail_path_for_db = os.path.join('uploads', 'attachments_img', 'thumbnails', thumbnail_filename)

                            attachment = Attachment(
                                defect_id=defect.id,
                                file_path=file_path_for_db,
                                thumbnail_path=thumbnail_path_for_db,
                                mime_type=mime_type # Save mime_type
                            )
                            db.session.add(attachment)
                            db.session.commit()
                            attachment_ids.append(attachment.id)
                        except Exception as e: # Catch errors during thumbnailing or DB operations
                            db.session.rollback()
                            logger.error(f'Error processing image {original_filename_secure} in add_defect: {str(e)}')
                            flash(f'Error processing image {original_filename_secure}.', 'error')
                            continue # Continue with the next file
                    else:
                        # Handle non-image file if necessary for 'photos' field
                        flash(f"File '{file.filename}' is not a supported image type for initial defect photos and was skipped.", "warning")
                        continue # Skip this file
                elif file and file.filename: # If file is present but not allowed by allowed_file()
                    flash(f"File type for '{file.filename}' is not allowed.", "warning")
                    continue
        if attachment_ids:
            return redirect(url_for('draw', attachment_id=attachment_ids[0], next=url_for('defect_detail', defect_id=defect.id)))
        flash('Defect created successfully!', 'success')
        return redirect(url_for('defect_detail', defect_id=defect.id))
    return render_template('add_defect.html', project=project, drawings=drawings_data, user_role=access.role, csrf_token_value=generate_csrf())

@app.route('/defect/<int:defect_id>', methods=['GET', 'POST'])
@login_required
def defect_detail(defect_id):
    app.logger.info(f"--- defect_detail route for defect_id: {defect_id} ---")
    try:
        # Fetch defect
        defect = db.session.get(Defect, defect_id)
        if not defect:
            logger.error(f"Defect {defect_id} not found")
            flash('Defect not found.', 'error')
            return redirect(url_for('index'))

        # Check access
        access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=defect.project_id).first()
        if not access:
            logger.error(f"User {current_user.id} has no access to project {defect.project_id}")
            flash('You do not have access to this defect.', 'error')
            return redirect(url_for('index'))

        # ADD THIS CHECK FOR EXPERT USER VIEWING PERMISSION
        if current_user.role == 'expert' and defect.creator_id != current_user.id:
            logger.warning(f"Expert user {current_user.id} attempted to view defect {defect_id} created by {defect.creator_id}.")
            flash('You do not have permission to view this defect as it was not created by you.', 'error')
            return redirect(url_for('project_detail', project_id=defect.project_id))
        # END OF ADDED CHECK

        # Handle POST requests
        if request.method == 'POST':
            action = request.form.get('action')

            if action == 'delete_defect':
                if access.role != 'admin':
                    logger.warning(f"User {current_user.id} attempted to delete defect {defect_id} without admin role")
                    flash('Only admins can delete defects.', 'error')
                    return redirect(url_for('defect_detail', defect_id=defect_id))
                project_id = defect.project_id
                attachments = Attachment.query.filter_by(defect_id=defect_id).all()
                for attachment in attachments:
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path))
                    thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.thumbnail_path)) if attachment.thumbnail_path else None
                    try:
                        if os.path.exists(file_path):
                            os.remove(file_path)
                        if thumbnail_path and os.path.exists(thumbnail_path):
                            os.remove(thumbnail_path)
                    except Exception as e:
                        logger.error(f"Error deleting attachment files for defect {defect_id}: {str(e)}")
                    db.session.delete(attachment)
                db.session.delete(defect)
                db.session.commit()
                logger.info(f"Defect {defect_id} deleted successfully")
                flash('Defect deleted successfully!', 'success')
                return redirect(url_for('project_detail', project_id=project_id))

            elif action == 'add_comment':
                content = request.form.get('comment_content', '').strip()
                if content:
                    comment = Comment(defect_id=defect_id, user_id=current_user.id, content=content)
                    db.session.add(comment)
                    db.session.commit() # Commit comment to get comment.id for attachments
                    attachment_ids = []
                    if 'comment_photos' in request.files:
                        files = request.files.getlist('comment_photos')
                        for file in files:
                            if file and allowed_file(file.filename):
                                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                                # Ensure comment.id is available
                                filename = secure_filename(f'comment_{comment.id}_{timestamp}_{file.filename}')
                                file_path_for_db = os.path.join('images', filename) 
                                full_disk_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) 
                                
                                thumbnail_dir = ensure_thumbnail_directory()
                                thumbnail_filename_base = f'thumb_{filename}'
                                thumbnail_disk_path = os.path.join(thumbnail_dir, thumbnail_filename_base) # Full path for saving
                                thumbnail_path_for_db = os.path.join('images', 'thumbnails', thumbnail_filename_base) # Relative path for DB

                                try:
                                    img = PILImage.open(file)
                                    img = ImageOps.exif_transpose(img) 
                                    img = img.convert('RGB')
                                    img.save(full_disk_path, quality=85, optimize=True)
                                    os.chmod(full_disk_path, 0o644)
                                    create_thumbnail(full_disk_path, thumbnail_disk_path) # create_thumbnail saves to thumbnail_disk_path
                                    
                                    attachment = Attachment(comment_id=comment.id, 
                                                            file_path=file_path_for_db, 
                                                            thumbnail_path=thumbnail_path_for_db)
                                    db.session.add(attachment)
                                    db.session.commit() # Commit each attachment
                                    attachment_ids.append(attachment.id)
                                except Exception as e:
                                    logger.error(f'Error processing file {file.filename} for comment {comment.id} on defect {defect_id}: {str(e)}')
                                    flash(f'Error uploading file {file.filename}.', 'error')
                                    db.session.rollback() # Rollback this attachment's transaction
                                    continue # Continue with other files
                    if attachment_ids:
                        logger.info(f"Comment with {len(attachment_ids)} attachments added to defect {defect_id}")
                        # Redirect to draw tool for the first attachment, then back to defect detail
                        return redirect(url_for('draw', attachment_id=attachment_ids[0], next=url_for('defect_detail', defect_id=defect_id)))
                    
                    logger.info(f"Comment added to defect {defect_id} (no attachments or attachments processed).")
                    flash('Comment added successfully!', 'success')
                else:
                    logger.warning(f"Empty comment submitted for defect {defect_id}")
                    flash('Comment cannot be empty.', 'error')
                # This redirect should be here, after processing the comment (or lack thereof)
                return redirect(url_for('defect_detail', defect_id=defect_id))

            elif action == 'edit_defect': # Corresponds to the main "Save Changes" form
                can_edit = False
                if current_user.role == 'admin':
                    if defect.creator_id == current_user.id:
                        can_edit = True
                elif current_user.role == 'expert':
                    if defect.creator_id == current_user.id:
                        can_edit = True
                elif current_user.role == 'Technical supervisor':
                    if defect.creator_id == current_user.id:
                        can_edit = True
                # No else needed, can_edit remains False by default

                if can_edit:
                    error_occurred = False

                    # --- Update Defect Properties ---
                    new_description = request.form.get('description', '').strip()
                    new_status = request.form.get('status', defect.status).lower()

                    if not new_description:
                        flash('Description cannot be empty.', 'error')
                        error_occurred = True
                    else:
                        defect.description = new_description

                    if not error_occurred: # Only proceed if description was okay
                        if new_status in ['open', 'closed']:
                            if defect.status != new_status:
                                if new_status == 'closed':
                                    # Apply ownership check for closing for ALL roles, including admin
                                    if defect.creator_id != current_user.id:
                                        # If we want to allow admins to close any defect, this check needs to be:
                                        # if defect.creator_id != current_user.id and current_user.role != 'admin':
                                        # For now, strictly apply creator or specific role for closing
                                        flash('Only the defect creator can close this defect.', 'error') # Simplified message
                                        error_occurred = True
                                    else:
                                        defect.status = new_status
                                        defect.close_date = datetime.now()
                                else: # new_status == 'open'
                                    defect.status = new_status
                                    defect.close_date = None
                        else:
                            flash('Invalid status value.', 'error')
                            error_occurred = True
                   
                    # --- Handle Marker Data (only if no prior errors) ---
                    if not error_occurred:
                        drawing_id_str = request.form.get('drawing_id')
                        marker_x_str = request.form.get('marker_x')
                        marker_y_str = request.form.get('marker_y')

                        if drawing_id_str and marker_x_str and marker_y_str:
                            try:
                                drawing_id_val = int(drawing_id_str)
                                marker_x_val = float(marker_x_str)
                                marker_y_val = float(marker_y_str)

                                if not (0 <= marker_x_val <= 1 and 0 <= marker_y_val <= 1):
                                    flash('Marker coordinates must be between 0 and 1.', 'error')
                                    error_occurred = True
                                else:
                                    valid_drawing = Drawing.query.filter_by(id=drawing_id_val, project_id=defect.project_id).first()
                                    if not valid_drawing:
                                        flash('Invalid drawing selected for marker.', 'error')
                                        error_occurred = True
                                    else:
                                        existing_marker = DefectMarker.query.filter_by(defect_id=defect_id).first()
                                        if existing_marker:
                                            existing_marker.drawing_id = drawing_id_val
                                            existing_marker.x = marker_x_val
                                            existing_marker.y = marker_y_val
                                            logger.info(f"Updated marker for defect {defect_id}")
                                        else:
                                            new_marker = DefectMarker(defect_id=defect_id, drawing_id=drawing_id_val, x=marker_x_val, y=marker_y_val)
                                            db.session.add(new_marker)
                                            logger.info(f"Created new marker for defect {defect_id}")
                            except ValueError:
                                flash('Invalid marker data format (e.g., non-numeric values).', 'error')
                                error_occurred = True
                                logger.warning(f"ValueError for marker data, defect {defect_id}: drawing_id='{drawing_id_str}', x='{marker_x_str}', y='{marker_y_str}'")

                        elif not drawing_id_str:
                            existing_marker = DefectMarker.query.filter_by(defect_id=defect_id).first()
                            if existing_marker:
                                db.session.delete(existing_marker)
                                logger.info(f"Deleted marker for defect {defect_id} as no drawing was selected.")

                    if error_occurred:
                        db.session.rollback()
                    else:
                        db.session.commit()
                        flash('Defect updated successfully!', 'success')
                
                else: # if not can_edit
                    logger.warning(f"User {current_user.id} (Role: {current_user.role}) attempted to edit defect {defect_id} (Creator ID: {defect.creator_id}) without permission.")
                    flash('You do not have permission to edit this defect.', 'error')
                
                return redirect(url_for('defect_detail', defect_id=defect_id))

            else:
                # Handle cases where no specific action matched or 'action' was not 'delete_defect' or 'add_comment'
                # This also covers the old 'description' in request.form check if it's not part of 'edit_defect' action explicitly
                if 'description' in request.form and action != 'edit_defect':
                     # This case might occur if a form is submitted with 'description' but not action='edit_defect'
                     # For now, we'll treat it as an edit attempt, but log it.
                     logger.warning(f"Defect edit attempt for defect_id {defect_id} without action='edit_defect'. Form keys: {list(request.form.keys())}")
                     # Redirect to avoid unintended processing, or handle as a specific case if necessary.
                     # For safety, let's assume it might be an incomplete/malformed request and redirect.
                     flash("Potential issue with form submission. Please try again.", "warning")

                logger.warning(f"Unhandled POST action '{action}' for defect_id {defect_id}. Redirecting.")
                return redirect(url_for('defect_detail', defect_id=defect_id))

        # --- GET Request Processing ---
        # Fetch attachments and comments (already present from previous structure)
        attachments = Attachment.query.filter_by(defect_id=defect_id, checklist_item_id=None, comment_id=None).all()
        comments = Comment.query.filter_by(defect_id=defect_id).order_by(Comment.created_at.asc()).all()
        
        # Fetch project drawings for the dropdown
        project_drawings = Drawing.query.filter_by(project_id=defect.project.id).all()
        drawings_data_for_template = [{'id': d.id, 'name': d.name, 'file_path': d.file_path} for d in project_drawings]

        # Logging for defect
        if defect:
            app.logger.info(f"Fetched defect: id={defect.id}, description='{defect.description}', status='{defect.status}'")
        else:
            # This case is already handled by the initial check, but good for robustness if that check were removed.
            app.logger.error(f"Defect object somehow None after initial check for defect_id: {defect_id}")
            # flash('Defect not found.', 'error') # Already flashed
            # return redirect(url_for('index')) # Already redirected

        # Fetch marker and drawing (already present from previous structure)
        marker_sqla = DefectMarker.query.filter_by(defect_id=defect_id).first() # Renamed to marker_sqla to avoid confusion
        drawing_obj = None # Initialize drawing_obj
        marker_data = None # Initialize marker_data

        if marker_sqla:
            app.logger.info(f"Fetched marker (SQLAlchemy): id={marker_sqla.id}, x={marker_sqla.x}, y={marker_sqla.y}, drawing_id={marker_sqla.drawing_id}, page_num={getattr(marker_sqla, 'page_num', 'N/A')}")
            drawing_obj = db.session.get(Drawing, marker_sqla.drawing_id) # Use db.session.get for PK lookup
            if drawing_obj:
                app.logger.info(f"Fetched drawing_obj: id={drawing_obj.id}, file_path='{drawing_obj.file_path}'")
                marker_data = {
                    'drawing_id': marker_sqla.drawing_id,
                    'x': marker_sqla.x,
                    'y': marker_sqla.y,
                    'file_path': drawing_obj.file_path, # Use path from the fetched drawing object
                    'page_num': getattr(marker_sqla, 'page_num', 1) # If page_num is implemented
                }
                # logger.debug already exists below, so we use app.logger.info for consistency or app.logger.debug
                app.logger.debug(f"Defect {defect_id} - Marker data for display: {marker_data}") # Changed from logger.debug to app.logger.debug
            else:
                app.logger.warning(f"Drawing object not found for drawing_id: {marker_sqla.drawing_id} (associated with marker id: {marker_sqla.id})")
                # marker_data remains None if drawing_obj is not found
        else:
            app.logger.info(f"No marker (SQLAlchemy object) found for defect_id: {defect_id}")
            # marker_data remains None

        # Log the final marker_data dictionary
        app.logger.info(f"Final marker_data for template: {marker_data}")

        # ADD THE NEW LOGGING HERE:
        if current_user.role == 'contractor' and marker_data:
            app.logger.info(f"CONTRACTOR USER ({current_user.id}) - Defect {defect_id} - Marker data being passed to template: {marker_data}")

        # logger.info already exists below, so we use app.logger.info for consistency or app.logger.debug
        app.logger.info(f"Rendering defect_detail for defect {defect_id} (GET request or after POST error without redirect)") # Changed from logger.info to app.logger.info
        return render_template(
            'defect_detail.html',
            defect=defect,
            attachments=attachments,
            comments=comments,
            user_role=access.role,
            marker=marker_data, # This is for displaying existing marker
            project=defect.project,
            drawings=drawings_data_for_template, # This is for the dropdown
            csrf_token_value=generate_csrf()
        )

    except Exception as e:
        logger.error(f"Error in defect_detail for defect {defect_id}: {str(e)}", exc_info=True)
        flash('An error occurred while loading the defect.', 'error')
        return redirect(url_for('index'))

@app.route('/defect/<int:defect_id>/delete', methods=['POST'])
@login_required
def delete_defect_route(defect_id): # Renamed to avoid conflict with any potential 'delete_defect' function
    defect = db.session.get(Defect, defect_id)
    if not defect:
        flash('Defect not found.', 'error')
        return redirect(url_for('index'))

    # Authorization: Only admins can delete defects
    if current_user.role != 'admin':
        flash('You are not authorized to delete this defect.', 'error')
        # Redirect to the defect detail page or project page
        return redirect(url_for('defect_detail', defect_id=defect.id))

    project_id_for_redirect = defect.project_id # Store before defect is deleted

    try:
        # 1. Delete associated DefectMarkers
        markers = DefectMarker.query.filter_by(defect_id=defect.id).all()
        for marker in markers:
            db.session.delete(marker)
        logger.info(f"Deleted {len(markers)} markers for defect {defect.id}")

        # 2. Delete associated Comments and their Attachments
        comments = Comment.query.filter_by(defect_id=defect.id).all()
        for comment in comments:
            # Delete attachments associated with this comment
            comment_attachments = Attachment.query.filter_by(comment_id=comment.id).all()
            for att in comment_attachments:
                # Delete physical files (original and thumbnail)
                if att.file_path:
                    full_file_path = os.path.join(app.static_folder, att.file_path)
                    if os.path.exists(full_file_path):
                        try:
                            os.remove(full_file_path)
                            logger.info(f"Deleted comment attachment file: {full_file_path}")
                        except OSError as e:
                            logger.error(f"Error deleting comment attachment file {full_file_path}: {e}")
                    else:
                        logger.warning(f"Comment attachment file not found for deletion: {full_file_path}")

                if att.thumbnail_path:
                    full_thumbnail_path = os.path.join(app.static_folder, att.thumbnail_path)
                    if os.path.exists(full_thumbnail_path):
                        try:
                            os.remove(full_thumbnail_path)
                            logger.info(f"Deleted comment attachment thumbnail: {full_thumbnail_path}")
                        except OSError as e:
                            logger.error(f"Error deleting comment attachment thumbnail {full_thumbnail_path}: {e}")
                    else:
                        logger.warning(f"Comment attachment thumbnail not found for deletion: {full_thumbnail_path}")
                db.session.delete(att)
            logger.info(f"Deleted {len(comment_attachments)} attachments for comment {comment.id}")
            db.session.delete(comment)
        logger.info(f"Deleted {len(comments)} comments for defect {defect.id}")

        # 3. Delete associated Attachments (directly linked to the defect)
        defect_attachments = Attachment.query.filter_by(defect_id=defect.id, comment_id=None, checklist_item_id=None).all()
        for att in defect_attachments:
            # Delete physical files (original and thumbnail)
            if att.file_path:
                full_file_path = os.path.join(app.static_folder, att.file_path)
                if os.path.exists(full_file_path):
                    try:
                        os.remove(full_file_path)
                        logger.info(f"Deleted defect attachment file: {full_file_path}")
                    except OSError as e:
                        logger.error(f"Error deleting defect attachment file {full_file_path}: {e}")
                else:
                    logger.warning(f"Defect attachment file not found for deletion: {full_file_path}")

            if att.thumbnail_path:
                full_thumbnail_path = os.path.join(app.static_folder, att.thumbnail_path)
                if os.path.exists(full_thumbnail_path):
                    try:
                        os.remove(full_thumbnail_path)
                        logger.info(f"Deleted defect attachment thumbnail: {full_thumbnail_path}")
                    except OSError as e:
                        logger.error(f"Error deleting defect attachment thumbnail {full_thumbnail_path}: {e}")
                else:
                    logger.warning(f"Defect attachment thumbnail not found for deletion: {full_thumbnail_path}")
            db.session.delete(att)
        logger.info(f"Deleted {len(defect_attachments)} direct attachments for defect {defect.id}")

        # 4. Delete the Defect itself
        db.session.delete(defect)

        db.session.commit()
        flash('Defect and all associated data deleted successfully!', 'success')
        logger.info(f"Successfully deleted defect {defect_id} and all associated data.")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during deletion of defect {defect_id}: {str(e)}", exc_info=True)
        flash('An error occurred while deleting the defect. Please try again.', 'error')
        return redirect(url_for('defect_detail', defect_id=defect.id)) # Redirect back to defect page on error

    return redirect(url_for('project_detail', project_id=project_id_for_redirect))

@app.route('/defect/<int:defect_id>/delete_attachment/<int:attachment_id>', methods=['POST'])
@login_required
def delete_attachment(defect_id, attachment_id):
    logger.debug(f'Attempting to delete attachment {attachment_id} for defect {defect_id}')
    attachment = db.session.get(Attachment, attachment_id)
    if not attachment:
        flash('Attachment not found.', 'error')
        return redirect(url_for('defect_detail', defect_id=defect_id))
    defect = db.session.get(Defect, defect_id)
    if not defect:
        flash('Defect not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=defect.project_id).first()
    if not access:
        flash('You do not have access to this defect.', 'error')
        return redirect(url_for('defect_detail', defect_id=defect_id))

    # Permission checks
    if attachment.defect_id:
        # Only admins can delete defect attachments
        if access.role != 'admin':
            flash('Only admins can delete defect attachments.', 'error')
            return redirect(url_for('defect_detail', defect_id=defect_id))
    elif attachment.comment_id:
        # Contractors can delete their own comment attachments
        comment = db.session.get(Comment, attachment.comment_id)
        if access.role == 'contractor' and comment.user_id != current_user.id:
            flash('You can only delete attachments from your own comments.', 'error')
            return redirect(url_for('defect_detail', defect_id=defect_id))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path))
    thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.thumbnail_path)) if attachment.thumbnail_path else None
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.debug(f'Deleted attachment file: {file_path}')
        if thumbnail_path and os.path.exists(thumbnail_path):
            os.remove(thumbnail_path)
            logger.debug(f'Deleted thumbnail: {thumbnail_path}')
        db.session.delete(attachment)
        db.session.commit()
        flash('Attachment deleted successfully!', 'success')
        logger.debug(f'Attachment {attachment_id} deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting attachment: {str(e)}', 'error')
        logger.error(f'Error deleting attachment {attachment_id}: {str(e)}')
    return redirect(url_for('defect_detail', defect_id=defect_id))


@app.route('/defect/<int:defect_id>/attachment/add', methods=['POST'])
@login_required
def add_defect_attachment(defect_id):
    defect = db.session.get(Defect, defect_id)
    if not defect:
        return jsonify({'success': False, 'error': 'Defect not found.'}), 404

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=defect.project_id).first()
    if not access or access.role not in ['admin', 'expert', 'worker']: # Workers can add attachments
        return jsonify({'success': False, 'error': 'Permission denied.'}), 403

    if 'attachment_file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part.'}), 400
    
    file = request.files['attachment_file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file.'}), 400

    if file and allowed_file(file.filename):
        mime_type = file.content_type
        logger.info(f"Uploading file with MIME type: {mime_type}")

        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S%f')
            original_filename_secure = secure_filename(file.filename)
            unique_filename_base = f"defect_{defect.id}_{timestamp}_{original_filename_secure}"

            db_file_path = None
            db_thumbnail_path = None

            if mime_type.startswith('image/'):
                img_dir, thumb_dir = ensure_attachment_paths('attachments_img') # static/uploads/attachments_img, static/uploads/attachments_img/thumbnails

                original_save_path = os.path.join(img_dir, unique_filename_base)
                file.seek(0) # Reset file pointer before saving
                file.save(original_save_path)
                os.chmod(original_save_path, 0o644)
                # DB path relative to 'static' folder
                db_file_path = os.path.join('uploads', 'attachments_img', unique_filename_base)

                thumbnail_filename = f"thumb_{unique_filename_base}"
                thumbnail_save_path = os.path.join(thumb_dir, thumbnail_filename) # Full disk path for saving thumbnail
                create_thumbnail(original_save_path, thumbnail_save_path)
                # DB path relative to 'static' folder
                db_thumbnail_path = os.path.join('uploads', 'attachments_img', 'thumbnails', thumbnail_filename)
                logger.info(f"Image attachment processed: {db_file_path}")

            elif mime_type == 'application/pdf':
                app.logger.info(f"Processing PDF attachment: {original_filename_secure}")
                pdf_dir, _ = ensure_attachment_paths('attachments_pdf') # Gets static/uploads/attachments_pdf
                app.logger.info(f"PDF original save directory: {pdf_dir}")

                absolute_pdf_path = os.path.join(pdf_dir, unique_filename_base)
                app.logger.info(f"Attempting to save PDF to: {absolute_pdf_path}")
                file.seek(0)
                file.save(absolute_pdf_path)
                os.chmod(absolute_pdf_path, 0o644)
                app.logger.info(f"PDF saved successfully to: {absolute_pdf_path}")

                db_file_path = os.path.join('uploads', 'attachments_pdf', unique_filename_base)
                app.logger.info(f"DB path for original PDF: {db_file_path}")

                # PDF Thumbnail Generation
                db_thumbnail_path = None # Default to None
                try:
                    pdf_thumb_save_dir, _ = ensure_attachment_paths('attachments_pdf_thumbs')
                    app.logger.info(f"PDF thumbnail save directory: {pdf_thumb_save_dir}")

                    thumb_filename = 'thumb_' + os.path.splitext(unique_filename_base)[0] + '.png'
                    absolute_thumb_path = os.path.join(pdf_thumb_save_dir, thumb_filename)
                    app.logger.info(f"Attempting to generate PDF thumbnail. Original PDF path: {absolute_pdf_path}, Thumbnail save path: {absolute_thumb_path}")

                    if not os.path.exists(absolute_pdf_path):
                        app.logger.error(f"CRITICAL: Original PDF file does not exist at {absolute_pdf_path} before calling convert_from_path.")
                        raise FileNotFoundError(f"Original PDF not found at {absolute_pdf_path} for thumbnail generation")

                    images = convert_from_path(absolute_pdf_path, first_page=1, last_page=1, fmt='png', size=(300, None))
                    if images:
                        images[0].save(absolute_thumb_path, 'PNG')
                        os.chmod(absolute_thumb_path, 0o644)
                        db_thumbnail_path = os.path.join('uploads', 'attachments_pdf_thumbs', thumb_filename)
                        app.logger.info(f"PDF thumbnail generated successfully: {absolute_thumb_path}. DB path: {db_thumbnail_path}")
                    else:
                        app.logger.warning(f"PDF thumbnail generation returned no images for {unique_filename_base}. Original PDF: {absolute_pdf_path}")
                except Exception as e:
                    # Log the full error with traceback
                    app.logger.error(f"PDF Thumbnail generation failed for {unique_filename_base}: {str(e)}", exc_info=True)
                    # db_thumbnail_path remains None

                app.logger.info(f"PDF attachment processed. Final DB original path: {db_file_path}, Final DB thumbnail path: {db_thumbnail_path}")
            else:
                logger.warning(f"Unsupported file type attempted: {mime_type}")
                return jsonify({'success': False, 'error': 'Unsupported file type. Only images and PDFs are allowed.'}), 400

            attachment = Attachment(
                defect_id=defect.id,
                file_path=db_file_path,
                thumbnail_path=db_thumbnail_path,
                mime_type=mime_type
            )
            db.session.add(attachment)
            db.session.commit()
            app.logger.info(f"Attachment record saved to DB: ID {attachment.id}, Defect ID {defect.id}, File Path {db_file_path}, Thumbnail Path {db_thumbnail_path}, MIME Type {mime_type}")

            # The JS expects to reload, but sending back details is good practice
            return jsonify({
                'success': True, 
                'message': 'Attachment added successfully.',
                'attachment': { 
                    'id': attachment.id,
                    'file_path_url': url_for('static', filename=attachment.file_path) if attachment.file_path else None,
                    'thumbnail_path_url': url_for('static', filename=attachment.thumbnail_path) if attachment.thumbnail_path else None,
                    'mime_type': attachment.mime_type
                }
            })
        except Exception as e:
            db.session.rollback()
            # Use app.logger for consistency and ensure exc_info=True for traceback
            app.logger.error(f"Overall error adding attachment to defect {defect.id}: {str(e)}", exc_info=True)
            return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500
    else:
        return jsonify({'success': False, 'error': 'File type not allowed.'}), 400


@app.route('/defect/<int:defect_id>/attachment/delete', methods=['POST'])
@login_required
def delete_defect_attachment_json(defect_id):
    defect = db.session.get(Defect, defect_id)
    if not defect:
        return jsonify({'success': False, 'error': 'Defect not found.'}), 404

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=defect.project_id).first()
    if not access or access.role not in ['admin', 'expert']: 
        return jsonify({'success': False, 'error': 'Permission denied to delete attachments for this defect.'}), 403

    attachment_id = request.form.get('attachment_id')
    if not attachment_id:
        return jsonify({'success': False, 'error': 'Attachment ID missing.'}), 400
    
    # Ensure attachment belongs to the specific defect by querying with defect_id
    attachment = Attachment.query.filter_by(id=attachment_id, defect_id=defect.id).first() 
    if not attachment:
        return jsonify({'success': False, 'error': 'Attachment not found or does not belong to this defect.'}), 404

    try:
        # Delete physical files
        if attachment.file_path:
            # Construct full path from app.static_folder and the relative path stored in DB
            full_file_path = os.path.join(app.static_folder, attachment.file_path)
            if os.path.exists(full_file_path):
                os.remove(full_file_path)
                logger.info(f"Deleted file: {full_file_path}")
            else:
                logger.warning(f"Attachment file not found for deletion: {full_file_path} (DB path: {attachment.file_path})")
        
        if attachment.thumbnail_path:
            full_thumbnail_path = os.path.join(app.static_folder, attachment.thumbnail_path)
            if os.path.exists(full_thumbnail_path):
                os.remove(full_thumbnail_path)
                logger.info(f"Deleted thumbnail: {full_thumbnail_path}")
            else:
                logger.warning(f"Attachment thumbnail not found for deletion: {full_thumbnail_path} (DB path: {attachment.thumbnail_path})")

        db.session.delete(attachment)
        db.session.commit()
        logger.info(f"Attachment {attachment_id} deleted from defect {defect.id} by user {current_user.id}")
        return jsonify({'success': True, 'message': 'Attachment deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting attachment {attachment_id} from defect {defect.id}: {str(e)}", exc_info=True)
        return jsonify({'success': False, 'error': f'Server error: {str(e)}'}), 500

@app.route('/project/<int:project_id>/add_checklist', methods=['GET', 'POST'])
@login_required
def add_checklist(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access or access.role not in ['admin', 'Technical supervisor']:
        flash('Only admins or technical supervisors can add checklists.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))
    templates = Template.query.all()
    if request.method == 'POST':
        name = request.form['name']
        template_id = request.form['template_id']
        if not name:
            flash('Checklist name is required!', 'error')
            return redirect(url_for('add_checklist', project_id=project_id))
        checklist = Checklist(
            project_id=project_id,
            template_id=template_id,
            name=name,
            creation_date=datetime.now()
        )
        db.session.add(checklist)
        db.session.commit()
        template_items = TemplateItem.query.filter_by(template_id=template_id).all()
        for item in template_items:
            checklist_item = ChecklistItem(checklist_id=checklist.id, item_text=item.item_text)
            db.session.add(checklist_item)
        db.session.commit()
        flash('Checklist added successfully!', 'success')
        return redirect(url_for('project_detail', project_id=project_id, _anchor='checklists'))
    return render_template('add_checklist.html', project=project, templates=templates)

@app.route('/checklist/<int:checklist_id>', methods=['GET']) # Removed POST from methods
@login_required
def checklist_detail(checklist_id):
    checklist = db.session.get(Checklist, checklist_id)
    if not checklist:
        flash('Checklist not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=checklist.project_id).first()
    if not access:
        flash('You do not have access to this checklist.', 'error')
        return redirect(url_for('index'))
    items = ChecklistItem.query.filter_by(checklist_id=checklist_id).all()
    # The POST block that handled form submission for all items has been removed.
    # All updates will be handled by the new AJAX routes.
    project = checklist.project
    return render_template('checklist_detail.html', checklist=checklist, items=items, project=project)

# --- New AJAX routes for Checklist Item Updates ---

@app.route('/checklist_item/<int:item_id>/update_status', methods=['POST'])
@login_required
def update_checklist_item_status(item_id):
    item = db.session.get(ChecklistItem, item_id)
    if not item:
        return jsonify(success=False, error='Checklist item not found.'), 404

    checklist = db.session.get(Checklist, item.checklist_id)
    if not checklist:
        return jsonify(success=False, error='Associated checklist not found.'), 404 # Should not happen

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=checklist.project_id).first()
    if not access:
        return jsonify(success=False, error='Access denied to this project.'), 403

    data = request.get_json(force=True, silent=True) # Kept force=True, silent=True
    if data is None:
        # Retain a simpler error message if JSON parsing fails or content is not JSON
        app.logger.error(f"PY update_checklist_item_status: Failed to parse JSON or no JSON data for item {item_id}. Request Content-Type: {request.content_type}")
        return jsonify(success=False, error='Invalid request: No JSON data or incorrect Content-Type.'), 400

    if 'is_checked' not in data:
        return jsonify(success=False, error='Missing is_checked status in request.'), 400

    is_checked_from_request = data.get('is_checked')
    item.is_checked = bool(is_checked_from_request) # Ensure it's a boolean
    db.session.add(item)

    try:
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"PY update_checklist_item_status: Error during DB commit for item {item_id}: {str(e)}", exc_info=True)
        return jsonify(success=False, message="Database error during update."), 500

    updated_item_check = db.session.get(ChecklistItem, item_id) # Re-fetch to confirm
    if not updated_item_check:
        app.logger.error(f"PY update_checklist_item_status: Item {item_id} NOT FOUND after commit. Critical error.")
        return jsonify(success=False, message="Failed to confirm update, item not found after commit."), 500

    response_new_status = updated_item_check.is_checked
    return jsonify(success=True, message='Status updated', new_status=response_new_status)

@app.route('/checklist_item/<int:item_id>/update_comments', methods=['POST'])
@login_required
def update_checklist_item_comments(item_id):
    item = db.session.get(ChecklistItem, item_id)
    if not item:
        return jsonify(success=False, error='Checklist item not found.'), 404

    checklist = db.session.get(Checklist, item.checklist_id)
    if not checklist:
        return jsonify(success=False, error='Associated checklist not found.'), 404

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=checklist.project_id).first()
    if not access:
        return jsonify(success=False, error='Access denied to this project.'), 403

    data = request.get_json()
    if data is None or 'comments' not in data:
        return jsonify(success=False, error='Missing comments in request.'), 400

    try:
        item.comments = data['comments'].strip()
        db.session.commit()
        logger.info(f"Checklist item {item_id} comments updated by user {current_user.id}")
        return jsonify(success=True, message='Comments updated', new_comments=item.comments)
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error updating checklist item {item_id} comments: {str(e)}", exc_info=True)
        return jsonify(success=False, error='Server error updating comments.'), 500

@app.route('/checklist_item/<int:item_id>/add_attachment', methods=['POST'])
@login_required
def add_checklist_item_attachment(item_id):
    item = db.session.get(ChecklistItem, item_id)
    if not item:
        return jsonify(success=False, error='Checklist item not found.'), 404

    checklist = db.session.get(Checklist, item.checklist_id)
    if not checklist:
        return jsonify(success=False, error='Associated checklist not found.'), 404

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=checklist.project_id).first()
    if not access: # Any user with project access can add attachments for now
        return jsonify(success=False, error='Access denied to this project.'), 403

    if 'photos' not in request.files:
        return jsonify(success=False, error='No photo files part in the request.'), 400

    files = request.files.getlist('photos')
    if not files or all(f.filename == '' for f in files):
        return jsonify(success=False, error='No selected files.'), 400

    new_attachments_data = []

    for file in files:
        if file and allowed_file(file.filename):
            mime_type = file.content_type
            if not mime_type.startswith('image/'):
                logger.warning(f"Skipping non-image file {file.filename} for checklist item {item_id}")
                continue # Skip non-image files

            try:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S%f')
                original_filename_secure = secure_filename(file.filename)
                unique_filename_base = f"checklistitem_{item.id}_{timestamp}_{original_filename_secure}"

                # Using 'attachments_img' subfolder within 'static/uploads/'
                img_dir, thumb_dir = ensure_attachment_paths('attachments_img')

                original_save_path = os.path.join(img_dir, unique_filename_base)
                file.seek(0)
                file.save(original_save_path)
                os.chmod(original_save_path, 0o644)
                # DB path relative to 'static' folder
                db_file_path = os.path.join('uploads', 'attachments_img', unique_filename_base)

                thumbnail_filename = f"thumb_{unique_filename_base}"
                thumbnail_save_path = os.path.join(thumb_dir, thumbnail_filename)
                create_thumbnail(original_save_path, thumbnail_save_path)
                # DB path relative to 'static' folder
                db_thumbnail_path = os.path.join('uploads', 'attachments_img', 'thumbnails', thumbnail_filename)

                attachment = Attachment(
                    checklist_item_id=item.id,
                    file_path=db_file_path,
                    thumbnail_path=db_thumbnail_path,
                    mime_type=mime_type
                )
                db.session.add(attachment)
                db.session.commit() # Commit each attachment to get its ID

                new_attachments_data.append({
                    'id': attachment.id,
                    'thumbnail_url': url_for('static', filename=attachment.thumbnail_path),
                    'original_url': url_for('static', filename=attachment.file_path)
                })
                logger.info(f"Attachment {attachment.id} added to checklist item {item_id} by user {current_user.id}")

            except Exception as e:
                db.session.rollback()
                logger.error(f"Error adding attachment to checklist item {item_id}: {str(e)}", exc_info=True)
                # Continue to next file if one fails
                # Consider returning partial success or specific errors per file
        elif file: # File present but not allowed
             logger.warning(f"File type not allowed for {file.filename} for checklist item {item_id}")


    if not new_attachments_data:
        return jsonify(success=False, error='No valid image files processed.'), 400

    return jsonify(success=True, message=f'{len(new_attachments_data)} attachment(s) added.', attachments=new_attachments_data)

@app.route('/checklist_item/<int:item_id>/delete_attachment/<int:attachment_id>', methods=['POST']) # Using POST for simplicity with JS fetch
@login_required
def delete_checklist_item_attachment_ajax(item_id, attachment_id): # Renamed to avoid conflict with existing route
    attachment = db.session.get(Attachment, attachment_id)
    if not attachment:
        return jsonify(success=False, error='Attachment not found.'), 404

    # Verify attachment belongs to the item_id
    if attachment.checklist_item_id != item_id:
        return jsonify(success=False, error='Attachment does not belong to this checklist item.'), 400

    item = db.session.get(ChecklistItem, item_id)
    if not item: # Should be redundant if attachment.checklist_item_id is valid
        return jsonify(success=False, error='Checklist item not found.'), 404

    checklist = db.session.get(Checklist, item.checklist_id)
    if not checklist:
        return jsonify(success=False, error='Associated checklist not found.'), 404

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=checklist.project_id).first()
    if not access: # Any user with project access can delete for now, adjust if needed
        return jsonify(success=False, error='Access denied to this project.'), 403

    try:
        # Delete physical files (original and thumbnail)
        # Paths are relative to 'static' folder, e.g., 'uploads/attachments_img/file.jpg'
        if attachment.file_path:
            full_file_path = os.path.join(app.static_folder, attachment.file_path)
            if os.path.exists(full_file_path):
                os.remove(full_file_path)
                logger.info(f"Deleted file: {full_file_path}")
            else:
                logger.warning(f"Attachment file not found for deletion: {full_file_path}")

        if attachment.thumbnail_path:
            full_thumbnail_path = os.path.join(app.static_folder, attachment.thumbnail_path)
            if os.path.exists(full_thumbnail_path):
                os.remove(full_thumbnail_path)
                logger.info(f"Deleted thumbnail: {full_thumbnail_path}")
            else:
                logger.warning(f"Attachment thumbnail not found for deletion: {full_thumbnail_path}")

        db.session.delete(attachment)
        db.session.commit()
        logger.info(f"Attachment {attachment_id} deleted from checklist item {item_id} by user {current_user.id}")
        return jsonify(success=True, message='Attachment deleted successfully.')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting attachment {attachment_id} from checklist item {item_id}: {str(e)}", exc_info=True)
        return jsonify(success=False, error='Server error deleting attachment.'), 500

# --- End of new AJAX routes ---

@app.route('/checklist/<int:checklist_id>/delete', methods=['POST'])
@login_required
def delete_checklist_route(checklist_id): # Renamed to be distinct
    checklist = db.session.get(Checklist, checklist_id)
    if not checklist:
        flash('Checklist not found.', 'error')
        return redirect(url_for('index'))

    # Authorization: Only admins or technical supervisors can delete checklists
    if current_user.role not in ['admin', 'Technical supervisor']:
        flash('You are not authorized to delete this checklist.', 'error')
        return redirect(url_for('checklist_detail', checklist_id=checklist.id))

    project_id_for_redirect = checklist.project_id # Store before checklist is deleted

    try:
        # Iterate through each ChecklistItem associated with the checklist
        checklist_items = ChecklistItem.query.filter_by(checklist_id=checklist.id).all()
        for item in checklist_items:
            # Delete attachments associated with this checklist item
            item_attachments = Attachment.query.filter_by(checklist_item_id=item.id).all()
            for att in item_attachments:
                # Delete physical files (original and thumbnail)
                if att.file_path:
                    full_file_path = os.path.join(app.static_folder, att.file_path)
                    if os.path.exists(full_file_path):
                        try:
                            os.remove(full_file_path)
                            logger.info(f"Deleted checklist item attachment file: {full_file_path}")
                        except OSError as e:
                            logger.error(f"Error deleting checklist item attachment file {full_file_path}: {e}")
                    else:
                        logger.warning(f"Checklist item attachment file not found for deletion: {full_file_path}")

                if att.thumbnail_path:
                    full_thumbnail_path = os.path.join(app.static_folder, att.thumbnail_path)
                    if os.path.exists(full_thumbnail_path):
                        try:
                            os.remove(full_thumbnail_path)
                            logger.info(f"Deleted checklist item attachment thumbnail: {full_thumbnail_path}")
                        except OSError as e:
                            logger.error(f"Error deleting checklist item attachment thumbnail {full_thumbnail_path}: {e}")
                    else:
                        logger.warning(f"Checklist item attachment thumbnail not found for deletion: {full_thumbnail_path}")
                db.session.delete(att)
            logger.info(f"Deleted {len(item_attachments)} attachments for checklist item {item.id}")

            # Delete the ChecklistItem itself
            db.session.delete(item)
        logger.info(f"Deleted {len(checklist_items)} items for checklist {checklist.id}")

        # After all items and their attachments are deleted, delete the Checklist itself
        db.session.delete(checklist)

        db.session.commit()
        flash('Checklist and all associated data deleted successfully!', 'success')
        logger.info(f"Successfully deleted checklist {checklist_id} and all associated data.")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error during deletion of checklist {checklist_id}: {str(e)}", exc_info=True)
        flash('An error occurred while deleting the checklist. Please try again.', 'error')
        return redirect(url_for('checklist_detail', checklist_id=checklist.id))

    return redirect(url_for('project_detail', project_id=project_id_for_redirect, _anchor='checklists'))

@app.route('/checklist/<int:checklist_id>/delete_attachment/<int:attachment_id>', methods=['POST'])
@login_required
def delete_checklist_attachment(checklist_id, attachment_id):
    checklist = db.session.get(Checklist, checklist_id)
    if not checklist:
        flash('Checklist not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=checklist.project_id).first()
    if not access or access.role != 'admin':
        flash('Only admins can delete attachments.', 'error')
        return redirect(url_for('checklist_detail', checklist_id=checklist_id))
    attachment = db.session.get(Attachment, attachment_id)
    if not attachment:
        flash('Attachment not found.', 'error')
        return redirect(url_for('checklist_detail', checklist_id=checklist_id))
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path))
    thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.thumbnail_path)) if attachment.thumbnail_path else None
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
        if thumbnail_path and os.path.exists(thumbnail_path):
            os.remove(thumbnail_path)
        db.session.delete(attachment)
        db.session.commit()
        flash('Attachment deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting attachment: {str(e)}', 'error')
    return redirect(url_for('checklist_detail', checklist_id=checklist_id))

@app.route('/defect/<int:defect_id>/update_description', methods=['POST'])
@login_required
def update_defect_description(defect_id):
    defect = Defect.query.get_or_404(defect_id)
    
    can_perform_action = False
    if hasattr(current_user, 'role'): # Check if current_user has a role attribute
        allowed_editing_roles = ['admin', 'expert', 'Technical supervisor'] # Roles that can edit THEIR OWN defects
        if current_user.role in allowed_editing_roles:
            if current_user.id == defect.creator_id:
                can_perform_action = True
        # Add other general rules if any user, regardless of role, can edit their own defect
        # For example, if a 'contractor' who is a creator should also be able to edit:
        # elif current_user.id == defect.creator_id:
        #    can_perform_action = True
        # However, the issue is about admin, expert, TS, so we focus on them.
        # The most restrictive interpretation for "can only edit their own" is applied per role.

    if not can_perform_action:
        # It's good to log this attempt
        logger.warning(f"User {current_user.id} (Role: {getattr(current_user, 'role', 'N/A')}) attempted unauthorized edit on defect {defect_id} (Creator ID: {defect.creator_id}) via AJAX route.")
        return jsonify(success=False, error="Permission denied. You can only edit defects you created."), 403

    data = request.get_json()
    if not data or 'description' not in data:
        return jsonify(success=False, error="Missing description data."), 400
    
    new_description = data['description'].strip()
    if not new_description:
        return jsonify(success=False, error="Description cannot be empty."), 400

    # Assuming a reasonable max length for description, e.g., 1000 characters
    # This should match any frontend validation or database constraints if they exist
    MAX_DESC_LENGTH = 1000 
    if len(new_description) > MAX_DESC_LENGTH:
        return jsonify(success=False, error=f"Description is too long (max {MAX_DESC_LENGTH} characters)."), 400

    defect.description = new_description
    try:
        db.session.commit()
        app.logger.info(f"Defect {defect_id} description updated by user {current_user.id}")
        return jsonify(success=True, message="Description updated successfully.", new_description=defect.description)
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating defect description for defect {defect_id}: {e}", exc_info=True)
        return jsonify(success=False, error="Failed to update description due to a server error."), 500

@app.route('/defect/<int:defect_id>/update_status', methods=['POST'])
@login_required
def update_defect_status(defect_id):
    defect = Defect.query.get_or_404(defect_id)
    
    can_perform_action = False
    if hasattr(current_user, 'role'): # Check if current_user has a role attribute
        allowed_editing_roles = ['admin', 'expert', 'Technical supervisor'] # Roles that can edit THEIR OWN defects
        if current_user.role in allowed_editing_roles:
            if current_user.id == defect.creator_id:
                can_perform_action = True
        # Add other general rules if any user, regardless of role, can edit their own defect
        # For example, if a 'contractor' who is a creator should also be able to edit:
        # elif current_user.id == defect.creator_id:
        #    can_perform_action = True
        # However, the issue is about admin, expert, TS, so we focus on them.
        # The most restrictive interpretation for "can only edit their own" is applied per role.

    if not can_perform_action:
        # It's good to log this attempt
        logger.warning(f"User {current_user.id} (Role: {getattr(current_user, 'role', 'N/A')}) attempted unauthorized edit on defect {defect_id} (Creator ID: {defect.creator_id}) via AJAX route.")
        return jsonify(success=False, error="Permission denied. You can only edit defects you created."), 403

    data = request.get_json()
    if not data or 'status' not in data:
        return jsonify(success=False, error="Missing status data."), 400
    
    new_status = data['status']
    # Validate if new_status is one of the allowed statuses
    allowed_statuses = ['Open', 'Closed'] # Assuming these are the only valid string representations from the dropdown
    if new_status not in allowed_statuses:
        return jsonify(success=False, error=f"Invalid status value: {new_status}."), 400

    defect.status = new_status.lower() # Store status as lowercase in DB as per existing patterns
    if defect.status == 'closed':
        if not defect.close_date: # Only set if not already closed to preserve original close date
            defect.close_date = datetime.utcnow()
    elif defect.status == 'open':
        defect.close_date = None # Clear close_date if reopened

    try:
        db.session.commit()
        app.logger.info(f"Defect {defect_id} status updated to {defect.status} by user {current_user.id}")
        # The function `update_checklist_item_status_from_defect` was hypothetical.
        # If such logic is needed, it should be implemented based on actual requirements.
        # For now, we focus on updating the defect's status.
        return jsonify(success=True, message="Status updated successfully.", new_status=defect.status.capitalize())
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating defect status for defect {defect_id}: {e}", exc_info=True)
        return jsonify(success=False, error="Failed to update status due to a server error."), 500

@app.route('/defect/<int:defect_id>/update_location', methods=['POST'])
@login_required
def update_defect_location(defect_id):
    defect = Defect.query.get_or_404(defect_id)
    # project = Project.query.get_or_404(defect.project_id) # Project query not strictly needed if drawing check is done correctly

    can_perform_action = False
    if hasattr(current_user, 'role'): # Check if current_user has a role attribute
        allowed_editing_roles = ['admin', 'expert', 'Technical supervisor'] # Roles that can edit THEIR OWN defects
        if current_user.role in allowed_editing_roles:
            if current_user.id == defect.creator_id:
                can_perform_action = True
        # Add other general rules if any user, regardless of role, can edit their own defect
        # For example, if a 'contractor' who is a creator should also be able to edit:
        # elif current_user.id == defect.creator_id:
        #    can_perform_action = True
        # However, the issue is about admin, expert, TS, so we focus on them.
        # The most restrictive interpretation for "can only edit their own" is applied per role.

    if not can_perform_action:
        # It's good to log this attempt
        logger.warning(f"User {current_user.id} (Role: {getattr(current_user, 'role', 'N/A')}) attempted unauthorized edit on defect {defect_id} (Creator ID: {defect.creator_id}) via AJAX route.")
        return jsonify(success=False, error="Permission denied. You can only edit defects you created."), 403

    data = request.get_json()
    drawing_id_str = data.get('drawing_id')
    marker_x_str = data.get('x')
    marker_y_str = data.get('y')
    page_num_str = data.get('page_num', '1') # Default to page 1 if not provided

    # Try to find existing marker
    existing_marker = DefectMarker.query.filter_by(defect_id=defect.id).first()

    if not drawing_id_str or drawing_id_str == "None" or drawing_id_str == "": # Request to remove marker
        if existing_marker:
            db.session.delete(existing_marker)
            defect.location = None # Clear simple location string
            try:
                db.session.commit()
                app.logger.info(f"Marker removed for defect {defect_id} by user {current_user.id}")
                return jsonify(success=True, message="Marker removed successfully.", marker_removed=True)
            except Exception as e:
                db.session.rollback()
                app.logger.error(f"Error removing marker for defect {defect_id}: {e}", exc_info=True)
                return jsonify(success=False, error="Server error removing marker."), 500
        else:
            # No marker existed, and none is being set. Consider this a success.
            return jsonify(success=True, message="No marker to remove and no new marker specified.", marker_removed=False)

    # Validate drawing_id
    try:
        drawing_id = int(drawing_id_str)
        # Ensure the drawing belongs to the same project as the defect
        drawing = Drawing.query.filter_by(id=drawing_id, project_id=defect.project_id).first()
        if not drawing:
            return jsonify(success=False, error="Selected drawing not found or does not belong to this project."), 400
    except ValueError:
        return jsonify(success=False, error="Invalid drawing ID format."), 400
        
    # Validate coordinates and page number
    try:
        marker_x = float(marker_x_str)
        marker_y = float(marker_y_str)
        page_num = int(page_num_str)
        if not (0 <= marker_x <= 1 and 0 <= marker_y <= 1 and page_num > 0):
            # Consider checking against actual page count of PDF if possible, though complex here.
            raise ValueError("Marker coordinates or page number out of bounds.")
    except (ValueError, TypeError, AttributeError): # AttributeError for None.get on potentially missing x/y/page_num
        return jsonify(success=False, error="Invalid marker coordinates or page number."), 400

    updated_marker_data = None
    if existing_marker:
        existing_marker.drawing_id = drawing_id
        existing_marker.x = marker_x
        existing_marker.y = marker_y
        existing_marker.page_num = page_num
        db.session.flush() # Flush to ensure to_dict() gets updated data if it relies on DB state
        updated_marker_data = existing_marker.to_dict()
        app.logger.info(f"Marker updated for defect {defect_id} by user {current_user.id}")
    else:
        new_marker = DefectMarker(
            defect_id=defect.id,
            drawing_id=drawing_id,
            x=marker_x,
            y=marker_y,
            page_num=page_num
        )
        db.session.add(new_marker)
        db.session.flush() # Flush to get ID and allow to_dict()
        updated_marker_data = new_marker.to_dict()
        app.logger.info(f"New marker created for defect {defect_id} by user {current_user.id}")
    
    # Update simple defect.location string for display consistency
    defect.location = f"Drawing: {drawing.name}, Page: {page_num}, X: {marker_x:.3f}, Y: {marker_y:.3f}"

    try:
        db.session.commit()
        return jsonify(success=True, message="Location updated successfully.", marker=updated_marker_data, location_string=defect.location)
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error updating defect location for defect {defect_id}: {e}", exc_info=True)
        return jsonify(success=False, error="Server error updating location."), 500

@app.route('/comment/<int:comment_id>/edit', methods=['POST'])
@login_required
def edit_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    # Permission: Comment author or admin
    if not (current_user.id == comment.user_id or (hasattr(current_user, 'role') and current_user.role == 'admin')):
        return jsonify(success=False, error="Permission denied."), 403

    data = request.get_json()
    if not data: # Ensure data is not None
        return jsonify(success=False, error="Invalid request. No JSON data received."), 400
        
    new_content = data.get('content', '').strip()
    if not new_content:
        return jsonify(success=False, error="Comment content cannot be empty."), 400
    
    comment.content = new_content
    comment.edited = True
    comment.updated_at = datetime.utcnow() # Explicitly set, though onupdate might also handle it.
    try:
        db.session.commit()
        app.logger.info(f"Comment {comment_id} edited by user {current_user.id}")
        return jsonify(success=True, message="Comment updated.", new_content=comment.content, edited_at=comment.updated_at.strftime('%Y-%m-%d %H:%M'))
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error editing comment {comment_id}: {e}", exc_info=True)
        return jsonify(success=False, error="Server error updating comment."), 500

@app.route('/comment/<int:comment_id>/delete', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    # Permission: Comment author or admin
    if not (current_user.id == comment.user_id or (hasattr(current_user, 'role') and current_user.role == 'admin')):
        return jsonify(success=False, error="Permission denied."), 403

    # Handle comment attachments: Delete files and Attachment records
    comment_attachments = Attachment.query.filter_by(comment_id=comment.id).all()
    for att in comment_attachments:
        try:
            if att.file_path: # Path like 'images/filename.jpg' or 'images/thumbnails/thumb_filename.jpg'
                full_path = os.path.join(app.static_folder, att.file_path)
                if os.path.exists(full_path):
                    os.remove(full_path)
                    app.logger.info(f"Deleted attachment file: {full_path}")
                else:
                    app.logger.warning(f"Attachment file not found for deletion: {full_path}")
            
            if att.thumbnail_path: # Path like 'images/thumbnails/thumb_filename.jpg'
                thumb_full_path = os.path.join(app.static_folder, att.thumbnail_path)
                if os.path.exists(thumb_full_path):
                    os.remove(thumb_full_path)
                    app.logger.info(f"Deleted attachment thumbnail: {thumb_full_path}")
                else:
                    app.logger.warning(f"Attachment thumbnail not found for deletion: {thumb_full_path}")
        except Exception as e:
            app.logger.error(f"Error deleting file for attachment {att.id} during comment {comment_id} deletion: {e}", exc_info=True)
            # Continue to delete other files and the DB record even if one file fails
        db.session.delete(att)
    
    db.session.delete(comment)
    try:
        db.session.commit()
        app.logger.info(f"Comment {comment_id} and its attachments deleted by user {current_user.id}")
        return jsonify(success=True, message="Comment and its attachments deleted.")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting comment {comment_id} from DB: {e}", exc_info=True)
        return jsonify(success=False, error="Server error deleting comment."), 500

@app.route('/delete_image/<int:attachment_id>', methods=['DELETE'])
@login_required
def delete_image_route(attachment_id):
    attachment = db.session.get(Attachment, attachment_id)
    if not attachment:
        return jsonify({'status': 'error', 'message': 'Attachment not found.'}), 404

    project_id = None
    permission_ok = False

    if attachment.defect_id:
        defect = db.session.get(Defect, attachment.defect_id)
        if not defect:
            return jsonify({'status': 'error', 'message': 'Associated defect not found.'}), 404
        project_id = defect.project_id
        access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
        if access and current_user.role == 'admin':
            permission_ok = True
        else:
            return jsonify({'status': 'error', 'message': 'Permission denied to delete this defect attachment.'}), 403

    elif attachment.checklist_item_id:
        checklist_item = db.session.get(ChecklistItem, attachment.checklist_item_id)
        if not checklist_item or not checklist_item.checklist:
            return jsonify({'status': 'error', 'message': 'Associated checklist item or checklist not found.'}), 404
        project_id = checklist_item.checklist.project_id
        access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
        if access and current_user.role == 'admin':
            permission_ok = True
        else:
            return jsonify({'status': 'error', 'message': 'Permission denied to delete this checklist attachment.'}), 403

    elif attachment.comment_id:
        comment = db.session.get(Comment, attachment.comment_id)
        if not comment or not comment.defect: # Assuming comments are always linked to defects for project context
            return jsonify({'status': 'error', 'message': 'Associated comment or defect not found.'}), 404
        project_id = comment.defect.project_id
        access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
        if not access:
             return jsonify({'status': 'error', 'message': 'No project access.'}), 403 # Should not happen if other checks pass
        if current_user.role == 'admin' or comment.user_id == current_user.id:
            permission_ok = True
        else:
            return jsonify({'status': 'error', 'message': 'Permission denied to delete this comment attachment.'}), 403
    else:
        # Orphaned or unknown context
        return jsonify({'status': 'error', 'message': 'Cannot determine attachment context or invalid attachment.'}), 400

    if not permission_ok: # Should be caught by specific context checks, but as a safeguard
        return jsonify({'status': 'error', 'message': 'Permission denied.'}), 403

    # Delete files
    try:
        if attachment.file_path:
            full_file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path))
            if os.path.exists(full_file_path):
                os.remove(full_file_path)
                logger.info(f"Deleted file: {full_file_path}")
        if attachment.thumbnail_path:
            full_thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.thumbnail_path))
            if os.path.exists(full_thumbnail_path):
                os.remove(full_thumbnail_path)
                logger.info(f"Deleted thumbnail: {full_thumbnail_path}")
    except Exception as e:
        app.logger.error(f"Error deleting physical files for attachment {attachment_id}: {str(e)}")
        # Depending on policy, you might want to stop if files can't be deleted.
        # For now, we log and proceed to DB deletion.
        # return jsonify({'status': 'error', 'message': f'Error deleting image files: {str(e)}'}), 500

    # Delete database record
    try:
        db.session.delete(attachment)
        db.session.commit()
        logger.info(f"Deleted attachment {attachment_id} from database.")
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting attachment {attachment_id} from database: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Error deleting image from database.'}), 500

    return jsonify({'status': 'success', 'message': 'Image deleted successfully'}), 200

@app.route('/templates')
@login_required
def template_list():
    if current_user.role not in ['admin', 'Technical supervisor']:
        flash('Only admins or technical supervisors can manage templates.', 'error')
        return redirect(url_for('index'))
    templates = Template.query.all()
    return render_template('template_list.html', templates=templates)

@app.route('/add_template', methods=['GET', 'POST'])
@login_required
def add_template():
    if current_user.role not in ['admin', 'Technical supervisor']:
        flash('Only admins or technical supervisors can add templates.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        items = request.form['items']
        if name:
            template = Template(name=name)
            db.session.add(template)
            db.session.commit()
            for item in items.split(','):
                if item.strip():
                    template_item = TemplateItem(template_id=template.id, item_text=item.strip())
                    db.session.add(template_item)
            db.session.commit()
            flash('Template added successfully!', 'success')
            project_id = request.args.get('project_id')
            if project_id:
                return redirect(url_for('add_checklist', project_id=project_id))
            return redirect(url_for('template_list'))
        flash('Template name is required!', 'error')
    return render_template('add_template.html')

@app.route('/template/<int:template_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_template(template_id):
    if current_user.role not in ['admin', 'Technical supervisor']:
        flash('Only admins or technical supervisors can edit templates.', 'error')
        return redirect(url_for('index'))
    template = db.session.get(Template, template_id)
    if not template:
        flash('Template not found.', 'error')
        return redirect(url_for('template_list'))
    if request.method == 'POST':
        name = request.form['name']
        items = request.form['items']
        if name:
            template.name = name
            TemplateItem.query.filter_by(template_id=template.id).delete()
            for item in items.split(','):
                if item.strip():
                    template_item = TemplateItem(template_id=template.id, item_text=item.strip())
                    db.session.add(template_item)
            db.session.commit()
            flash('Template updated successfully!', 'success')
            return redirect(url_for('template_list'))
        flash('Template name is required!', 'error')
    items = TemplateItem.query.filter_by(template_id=template_id).all()
    item_text = ', '.join(item.item_text for item in items)
    return render_template('edit_template.html', template=template, item_text=item_text)

@app.route('/template/<int:template_id>/delete', methods=['POST'])
@login_required
def delete_template(template_id):
    if current_user.role not in ['admin', 'Technical supervisor']:
        flash('Only admins or technical supervisors can delete templates.', 'error')
        return redirect(url_for('index'))
    template = db.session.get(Template, template_id)
    if not template:
        flash('Template not found.', 'error')
        return redirect(url_for('template_list'))
    TemplateItem.query.filter_by(template_id=template_id).delete()
    db.session.delete(template)
    db.session.commit()
    flash('Template deleted successfully!', 'success')
    return redirect(url_for('template_list'))

@app.route('/project/<int:project_id>/new_report')
@login_required
def generate_new_report(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('index'))

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access:
        flash('You do not have access to this project.', 'error')
        return redirect(url_for('index'))

    # Check for POPPLER_PATH
    poppler_path_env = os.environ.get('POPPLER_PATH')
    if not poppler_path_env:
        logger.warning("POPPLER_PATH environment variable is not set. PDF to image conversion for marked drawings might fail or use a system-dependent Poppler installation.")
    else:
        logger.info(f"Using POPPLER_PATH: {poppler_path_env}")

    logger.info(f"Starting new report generation for project ID: {project_id}")
    filter_status = request.args.get('filter', 'All')
    logger.info(f"Report filter status: {filter_status}")
    generation_date_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    resolved_static_folder = app.static_folder

    temp_report_images_dir = os.path.join(resolved_static_folder, 'images', 'report_temp')
    os.makedirs(temp_report_images_dir, exist_ok=True)
    logger.debug(f"Ensured temporary report image directory exists: {temp_report_images_dir}")

    temp_files_to_clean = []

    # Fetch defects
    defects_query_base = Defect.query.options(
        db.joinedload(Defect.creator),
        db.joinedload(Defect.attachments),
        db.joinedload(Defect.comments).joinedload(Comment.user),
        db.joinedload(Defect.comments).joinedload(Comment.attachments),
        db.joinedload(Defect.markers).joinedload(DefectMarker.drawing)
    ).filter_by(project_id=project_id)

    user_is_privileged = current_user.role in ['admin', 'Technical supervisor']

    if filter_status == 'Open':
        final_query = defects_query_base.filter_by(status='open')
        if not user_is_privileged:
            final_query = final_query.filter_by(creator_id=current_user.id)
        defects = final_query.order_by(Defect.creation_date.asc()).all()
    elif filter_status == 'Closed':
        final_query = defects_query_base.filter_by(status='closed')
        if not user_is_privileged:
            final_query = final_query.filter_by(creator_id=current_user.id)
        defects = final_query.order_by(Defect.close_date.desc(), Defect.creation_date.asc()).all()
    elif filter_status == 'OpenNoReply':
        current_query = defects_query_base
        if not user_is_privileged:
            current_query = current_query.filter_by(creator_id=current_user.id)
        current_query = current_query.filter_by(status='open').outerjoin(Defect.comments).filter(Comment.id == None)
        defects = current_query.order_by(Defect.creation_date.asc()).all()
    elif filter_status == 'OpenWithReply':
        current_query = defects_query_base
        if not user_is_privileged:
            current_query = current_query.filter_by(creator_id=current_user.id)

        # Fetch open defects matching the current user/project filters
        open_defects_for_user = current_query.filter_by(status='open').order_by(Defect.creation_date.asc()).all()

        defects_with_reply_from_other = []
        for defect_item in open_defects_for_user:
            last_comment = Comment.query.filter_by(defect_id=defect_item.id).order_by(Comment.created_at.desc()).first()
            if last_comment and last_comment.user_id != current_user.id:
                defects_with_reply_from_other.append(defect_item)
        defects = defects_with_reply_from_other
    else:  # All
        final_query_for_all = defects_query_base
        if not user_is_privileged:
            final_query_for_all = final_query_for_all.filter_by(creator_id=current_user.id)
        all_defects_db = final_query_for_all.order_by(Defect.creation_date.asc()).all()

        # The python sorting logic for open/closed can remain the same
        defects = sorted([d for d in all_defects_db if d.status == 'open'], key=lambda d: d.creation_date if d.creation_date else datetime.min) + \
                  sorted([d for d in all_defects_db if d.status == 'closed'],
                         key=lambda d: (d.close_date if d.close_date else datetime.min, d.creation_date if d.creation_date else datetime.min), reverse=True)

    logger.info(f"Fetched {len(defects)} defects for the report for user {current_user.username} (Role: {current_user.role}).")

    for defect in defects:
        logger.info(f"Processing Defect ID {defect.id} ('{defect.description}') for report.")
        # Log defect attachments
        if defect.attachments:
            logger.info(f"  Defect ID {defect.id} - Attachments:")
            for att_idx, attachment in enumerate(defect.attachments):
                logger.info(f"    Attachment {att_idx + 1}: file_path for template='{attachment.file_path}', thumbnail_path for template='{attachment.thumbnail_path}'")
        else:
            logger.info(f"  Defect ID {defect.id} - No direct attachments.")

        # Log comment attachments
        if defect.comments:
            logger.info(f"  Defect ID {defect.id} - Comments:")
            for comment_idx, comment in enumerate(defect.comments):
                logger.info(f"    Comment ID {comment.id} (index {comment_idx + 1}) by User ID {comment.user_id}:")
                if comment.attachments:
                    for c_att_idx, c_attachment in enumerate(comment.attachments):
                        logger.info(f"      Attachment {c_att_idx + 1}: file_path for template='{c_attachment.file_path}', thumbnail_path for template='{c_attachment.thumbnail_path}'")
                else:
                    logger.info(f"      No attachments for this comment.")
        else:
            logger.info(f"  Defect ID {defect.id} - No comments.")

        defect.marked_drawing_image_path = None # Ensure it's initialized
        if defect.markers and defect.markers[0].drawing and defect.markers[0].drawing.file_path.lower().endswith('.pdf'):
            marker = defect.markers[0]
            drawing_db_path = marker.drawing.file_path # Path like 'drawings/drawing_name.pdf'

            # Construct full path to the PDF drawing file
            # Assuming drawing_db_path is relative to the app's root or a known base for drawings
            # If DRAWING_FOLDER is absolute, this might need adjustment.
            # For now, assume DRAWING_FOLDER is 'static/drawings' and drawing_db_path is 'drawings/file.pdf'
            # We need the actual file system path.
            pdf_filename = os.path.basename(drawing_db_path)
            pdf_full_path = os.path.join(app.config['DRAWING_FOLDER'], pdf_filename)
            logger.debug(f"Attempting PDF to image conversion for defect {defect.id}, drawing: {pdf_full_path}")

            if os.path.exists(pdf_full_path):
                try:
                    images = convert_from_path(pdf_full_path, first_page=1, last_page=1, poppler_path=os.environ.get('POPPLER_PATH'))
                    if images:
                        pil_image = images[0].convert('RGB')
                        draw_obj = ImageDraw.Draw(pil_image) # Renamed to avoid conflict
                        img_w, img_h = pil_image.size
                        abs_marker_x = marker.x * img_w
                        abs_marker_y = marker.y * img_h
                        radius = max(5, int(min(img_w, img_h) * 0.02))
                        draw_obj.ellipse(
                            (abs_marker_x - radius, abs_marker_y - radius, abs_marker_x + radius, abs_marker_y + radius),
                            fill='red', outline='red'
                        )

                        # Use NamedTemporaryFile correctly to get a path within the desired directory
                        with tempfile.NamedTemporaryFile(suffix='.png', dir=temp_report_images_dir, delete=False) as tmp_file:
                            temp_image_abs_path = tmp_file.name

                        pil_image.save(temp_image_abs_path)
                        temp_files_to_clean.append(temp_image_abs_path)

                        # Path relative to 'static' folder for url_for
                        defect.marked_drawing_image_path = os.path.join('images', 'report_temp', os.path.basename(temp_image_abs_path))
                        # Log template path and absolute disk path for marked drawing
                        logger.info(f"Marked drawing for Defect ID {defect.id}: Template path='{defect.marked_drawing_image_path}', Absolute disk path='{temp_image_abs_path}'")
                        # logger.info(f"Successfully generated marked drawing for defect {defect.id}: {defect.marked_drawing_image_path}") # This is now part of the above log
                    else:
                        logger.warning(f"convert_from_path returned no images for PDF: {pdf_full_path}, defect {defect.id}")
                        logger.info(f"Marked drawing for Defect ID {defect.id}: No marked drawing generated (convert_from_path issue). Path remains '{defect.marked_drawing_image_path}'")
                except Exception as e:
                    logger.error(f"Error during PDF to image conversion or drawing marker for defect {defect.id}, PDF: {pdf_full_path}. Error: {e}", exc_info=True)
                    defect.marked_drawing_image_path = None # Ensure it's None if conversion failed
                    logger.info(f"Marked drawing for Defect ID {defect.id}: No marked drawing generated (exception during conversion/drawing). Path remains '{defect.marked_drawing_image_path}'")
            else:
                # Changed from logger.warning to logger.error as a missing PDF for an existing marker is a more significant issue.
                logger.error(f"Marked drawing PDF not found at path: {pdf_full_path} for defect {defect.id}. This defect marker may be pointing to a deleted/moved drawing.")
                logger.info(f"Marked drawing for Defect ID {defect.id}: No marked drawing generated (PDF not found). Path remains '{defect.marked_drawing_image_path}'")
        else: # Handles cases where no marker, no drawing, or drawing is not PDF
            if not (defect.markers and defect.markers[0].drawing):
                logger.info(f"Marked drawing for Defect ID {defect.id}: No marker or drawing associated with the defect for marked image generation. Path remains '{defect.marked_drawing_image_path}'.")
            elif not defect.markers[0].drawing.file_path.lower().endswith('.pdf'):
                logger.info(f"Marked drawing for Defect ID {defect.id}: Drawing is not a PDF, skipping marked image generation. Drawing path: '{defect.markers[0].drawing.file_path}'. Path remains '{defect.marked_drawing_image_path}'.")


    # Fetch checklists
    # checklists_db = Checklist.query.filter_by(project_id=project_id).order_by(Checklist.name.asc()).all()
    report_checklists = []
    # for checklist_obj in checklists_db:
    #     items_db = ChecklistItem.query.options(
    #         db.joinedload(ChecklistItem.attachments)
    #     ).filter_by(checklist_id=checklist_obj.id).order_by(ChecklistItem.id.asc()).all()

    #     filtered_items = []
    #     for item_obj in items_db:
    #         item_status_val = 'closed' if item_obj.is_checked else 'open'
    #         if filter_status == 'Open' and item_status_val != 'open':
    #             continue
    #         elif filter_status == 'Closed' and item_status_val != 'closed':
    #             continue
    #         filtered_items.append(item_obj)

    #     if filtered_items: # Only add checklist if it has items matching the filter
    #         report_checklists.append({'checklist_info': checklist_obj, 'items': filtered_items})

    html_out = render_template(
        'report_template.html',
        project=project,
        generation_date=generation_date_str,
        defects=defects,
        checklists=report_checklists, # Ensure this is the empty list
        filter_status=filter_status,
        app_config=app.config
    )

    logger.info(f"Fetched {len(report_checklists)} checklists with items matching filter for the report.") # This will now log 0

    logger.info("Rendering HTML template for WeasyPrint...")
    html_out = render_template(
        'report_template.html',
        project=project,
        generation_date=generation_date_str,
        defects=defects,
        checklists=report_checklists, # Ensure this is the empty list
        filter_status=filter_status,
        app_config=app.config
    )
    logger.info("HTML template rendered.")

    # Log base_url for WeasyPrint
    logger.info(f"Report base_url for WeasyPrint: {request.url_root}")

    # Convert the rendered HTML to PDF using WeasyPrint
    try:
        logger.info("Starting WeasyPrint PDF generation...")
        pdf = HTML(string=html_out, base_url=request.url_root).write_pdf()
        logger.info("WeasyPrint PDF generation completed.")

        # Create a Flask response to send the PDF
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename="report_{project.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf"'

        # Using call_on_close for cleanup is more robust for various Flask serving setups
        @response.call_on_close
        def cleanup_temp_files():
            logger.info("Initiating cleanup of temporary report images.")
            for temp_file_path in temp_files_to_clean:
                try:
                    os.remove(temp_file_path)
                    logger.info(f"Successfully cleaned up temporary report image: {temp_file_path}")
                except Exception as e:
                    logger.error(f"Error cleaning up temporary report image {temp_file_path}: {e}", exc_info=True)
            try:
                if os.path.exists(temp_report_images_dir) and not os.listdir(temp_report_images_dir):
                    os.rmdir(temp_report_images_dir)
                    logger.info(f"Successfully cleaned up empty temporary report image directory: {temp_report_images_dir}")
                elif os.path.exists(temp_report_images_dir):
                     logger.info(f"Temporary report image directory not empty, not removing: {temp_report_images_dir}")
            except OSError as e:
                 logger.warning(f"Could not remove temporary report image directory {temp_report_images_dir}: {e}", exc_info=True)

        logger.info(f"Successfully prepared PDF response for project {project_id}.")
        return response
    except Exception as e:
        logger.error(f"Fatal error during PDF generation or response creation for project {project_id}: {e}", exc_info=True)
        # Cleanup any files created even if PDF generation failed mid-way
        logger.info("Initiating cleanup due to error during PDF generation.")
        for temp_file_path in temp_files_to_clean:
            try:
                os.remove(temp_file_path)
                logger.info(f"Cleaned up temporary file after error: {temp_file_path}")
            except Exception as cleanup_e:
                logger.error(f"Error during cleanup (after PDF failure) for {temp_file_path}: {cleanup_e}", exc_info=True)
        flash('Error generating PDF report.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))

@app.route('/draw/<int:attachment_id>', methods=['GET', 'POST'])
@login_required
def draw(attachment_id):
    attachment = db.session.get(Attachment, attachment_id)
    if not attachment:
        flash('Attachment not found.', 'error')
        return redirect(url_for('index'))

    # Determine project_id based on attachment type
    if attachment.defect_id:
        defect = db.session.get(Defect, attachment.defect_id)
        project_id = defect.project_id
    elif attachment.checklist_item_id:
        checklist = db.session.get(Checklist, attachment.checklist_item.checklist_id)
        project_id = checklist.project_id
    elif attachment.comment_id:
        comment = db.session.get(Comment, attachment.comment_id)
        project_id = comment.defect.project_id
    else:
        flash('Invalid attachment.', 'error')
        return redirect(url_for('index'))

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access:
        flash('You do not have access to this project.', 'error')
        return redirect(url_for('index'))

    # Permission checks for contractors
    if access.role == 'contractor':
        if attachment.defect_id:
            flash('Contractors cannot edit images attached to defects.', 'error')
            return redirect(url_for('defect_detail', defect_id=attachment.defect_id))
        if attachment.comment_id:
            comment = db.session.get(Comment, attachment.comment_id)
            if comment.user_id != current_user.id:
                flash('You can only edit images attached to your own comments.', 'error')
                return redirect(url_for('defect_detail', defect_id=comment.defect_id))

    next_url = request.args.get('next', '')
    if request.method == 'POST':
        data = request.get_json()
        lines = data.get('lines', [])
        if not lines:
            if next_url:
                return jsonify({'status': 'success', 'message': 'No lines to save', 'redirect': next_url})
            return jsonify({'status': 'success', 'message': 'No lines to save'}), 200

        # Correct Image Path for Opening and Saving:
        # img_path_on_disk represents the full disk path to the image.
        # attachment.file_path is relative to static folder e.g. 'uploads/attachments_img/filename.png'
        img_path_on_disk = os.path.join(app.static_folder, attachment.file_path)
        if not os.path.exists(img_path_on_disk):
            logger.error(f"Image file not found at expected path: {img_path_on_disk}. Attachment file_path: {attachment.file_path}")
            return jsonify({'status': 'error', 'message': f'Original image file not found: {attachment.file_path}'}), 404

        try:
            with PILImage.open(img_path_on_disk) as img:
                img = img.convert('RGB')
                draw_obj = ImageDraw.Draw(img) # Renamed to avoid conflict if 'draw' is used elsewhere
                img_width, img_height = img.size
                for line in lines:
                    points = line.get('points', [])
                    color = line.get('color', '#000000')
                    width = line.get('width', 5)
                    if not isinstance(points, list) or len(points) < 2:
                        continue
                    if not isinstance(color, str) or not color.startswith('#'):
                        color = '#000000' # Default color
                    try:
                        width = int(float(width)) # Ensure width is an integer
                        if width < 1: width = 1 # Minimum width
                    except (ValueError, TypeError):
                        width = 5 # Default width

                    scaled_points = []
                    for point in points:
                        try:
                            x = float(point.get('x', 0)) * img_width
                            y = float(point.get('y', 0)) * img_height
                            scaled_points.append((x, y))
                        except (ValueError, TypeError):
                            continue # Skip malformed point

                    if len(scaled_points) < 2: # Need at least two points to draw a line
                        continue

                    try: # Convert hex color to RGB tuple
                        rgb = tuple(int(color.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
                    except ValueError:
                        rgb = (0, 0, 0) # Default to black if color conversion fails

                    draw_obj.line(scaled_points, fill=rgb, width=width, joint='curve')

                img.save(img_path_on_disk, quality=95, optimize=True)

            # Correct Thumbnail Generation and Path Update:
            # attachment.thumbnail_path is the relative path for DB, e.g., 'uploads/attachments_img/thumbnails/thumb_filename.png'
            # thumbnail_save_path_on_disk is the full disk path for saving the new thumbnail.
            if attachment.thumbnail_path: # Ensure there is a thumbnail path to begin with
                thumbnail_save_path_on_disk = os.path.join(app.static_folder, attachment.thumbnail_path)

                thumbnail_dir_for_saving = os.path.dirname(thumbnail_save_path_on_disk)
                if not os.path.exists(thumbnail_dir_for_saving):
                    os.makedirs(thumbnail_dir_for_saving, exist_ok=True)
                    logger.info(f"Created thumbnail directory during draw operation: {thumbnail_dir_for_saving}")

                create_thumbnail(img_path_on_disk, thumbnail_save_path_on_disk)
                # attachment.thumbnail_path already holds the correct DB relative path.
                # No change needed to attachment.thumbnail_path itself.
            else:
                # This case should ideally not happen if thumbnails are always created upon upload.
                # If it can, decide on a fallback or log a warning.
                logger.warning(f"Attachment {attachment.id} does not have a thumbnail_path. Cannot update thumbnail after drawing.")

            db.session.commit() # Commit any changes to attachment (though thumbnail_path itself isn't changing here)

            if next_url:
                return jsonify({'status': "success", 'message': 'Drawing saved successfully', 'redirect': next_url})
            return jsonify({'status': 'success', 'message': 'Drawing saved successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 500
    return render_template('draw.html', attachment=attachment, next_url=next_url, csrf_token_value=generate_csrf())

@app.route('/view_attachment/<int:attachment_id>')
@login_required
def view_attachment(attachment_id):
    attachment = db.session.get(Attachment, attachment_id)
    if not attachment:
        flash('Attachment not found.', 'error')
        return redirect(url_for('index'))

    project_id = None
    back_url = url_for('index') # Default back URL

    if attachment.defect_id:
        defect = db.session.get(Defect, attachment.defect_id)
        if defect:
            project_id = defect.project_id
            back_url = url_for('defect_detail', defect_id=attachment.defect_id)
    elif attachment.comment_id:
        comment = db.session.get(Comment, attachment.comment_id)
        if comment and comment.defect:
            project_id = comment.defect.project_id
            back_url = url_for('defect_detail', defect_id=comment.defect_id)
    elif attachment.checklist_item_id:
        checklist_item = db.session.get(ChecklistItem, attachment.checklist_item_id)
        if checklist_item and checklist_item.checklist:
            project_id = checklist_item.checklist.project_id
            back_url = url_for('checklist_detail', checklist_id=checklist_item.checklist_id)

    if project_id is None:
        flash('Could not determine project for this attachment.', 'error')
        return redirect(url_for('index'))

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access:
        flash('You do not have access to this project.', 'error')
        return redirect(url_for('index'))

    return render_template('view_attachment.html', attachment=attachment, back_url=back_url)

# --- Product Approval Routes ---
@app.route('/project/<int:project_id>/product_approvals/request', methods=['POST'])
@login_required
def request_product_approval(project_id):
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(request.referrer or url_for('index'))

    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access or access.role not in ['admin', 'supervisor']:
        flash('You do not have permission to request product approvals for this project.', 'error')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

    product_name = request.form.get('product_name', '').strip()
    if not product_name:
        flash('Product name is required.', 'error')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

    new_request = ProductApproval(
        project_id=project_id,
        requester_id=current_user.id,
        product_name=product_name,
        request_date=datetime.utcnow(),
        status='waiting_for_proposal'
    )
    db.session.add(new_request)
    db.session.commit()
    flash('Product approval request created successfully.', 'success')
    return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

@app.route('/product_approval/<int:request_id>/submit_product', methods=['POST'])
@login_required
def submit_product_for_approval(request_id):
    logger.info(f"--- submit_product_for_approval for request_id: {request_id} ---")
    logger.info(f"Request Headers: {request.headers}")
    logger.info(f"Request Form Data: {request.form.to_dict()}")
    logger.info(f"Request Files: {request.files.to_dict()}")
    documentation_files = request.files.getlist('documentation_files[]') # Get list of files
    logger.info(f"Files from getlist('documentation_files[]'): {[(f.filename, f.content_type) for f in documentation_files]}")

    approval_request = db.session.get(ProductApproval, request_id)
    if not approval_request:
        flash('Product approval request not found.', 'error')
        return redirect(request.referrer or url_for('index'))

    project_id = approval_request.project_id
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access or access.role != 'contractor':
        flash('Only contractors can submit products for approval.', 'error')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

    # Allow submission if status is 'waiting_for_proposal', 'product_provided', or 'rejected' (for updates/resubmission)
    if approval_request.status not in ['waiting_for_proposal', 'product_provided', 'rejected']:
        flash('This request cannot be updated at this stage.', 'warning')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

    product_description = request.form.get('product_description', '').strip()
    documentation_files = request.files.getlist('documentation_files[]') # Get list of files

    if not product_description:
        flash('Product description is required.', 'error')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval') + f'#pa-{request_id}')

    files_uploaded_count = 0
    upload_folder = os.path.join(app.static_folder, 'product_documentation')
    os.makedirs(upload_folder, exist_ok=True)

    allowed_doc_extensions = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}

    for doc_file in documentation_files: # documentation_files is already the result of getlist
        if doc_file and doc_file.filename != '':
            logger.info(f"Processing file: {doc_file.filename}, Content-Type: {doc_file.content_type}")
            file_ext = doc_file.filename.rsplit('.', 1)[1].lower() if '.' in doc_file.filename else ''
            if not file_ext or file_ext not in allowed_doc_extensions:
                flash(f"File '{doc_file.filename}' has an unsupported extension and was skipped. Allowed types: PDF, PNG, JPG, JPEG, GIF.", 'warning')
                logger.warning(f"Skipped file with unsupported extension: {doc_file.filename}")
                continue

            original_filename = secure_filename(doc_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S%f')
            unique_filename = f"pa_doc_{approval_request.id}_{timestamp}_{original_filename}"
            file_path_on_disk = os.path.join(upload_folder, unique_filename)
            logger.info(f"Generated unique_filename: {unique_filename}, Disk path: {file_path_on_disk}")

            try:
                doc_file.save(file_path_on_disk)
                os.chmod(file_path_on_disk, 0o644)

                new_document = ProductDocument(
                    product_approval_id=approval_request.id,
                    file_path=unique_filename,
                    original_filename=original_filename,
                    uploader_id=current_user.id,
                    upload_date=datetime.utcnow()
                )
                db.session.add(new_document)
                files_uploaded_count += 1
                logger.info(f"Successfully processed and staged for DB: {unique_filename}")
            except Exception as e:
                logger.error(f"Error saving file {original_filename} for PA request {request_id}: {e}", exc_info=True)
                flash(f"Error saving file {original_filename}. It was skipped.", "error")
                continue

    # Check if files are required for the very first submission
    existing_documents_count = ProductDocument.query.filter_by(product_approval_id=request_id).count()
    if approval_request.status == 'waiting_for_proposal' and files_uploaded_count == 0 and existing_documents_count == 0:
        flash('At least one product documentation PDF is required for the initial submission.', 'error')
        # No rollback needed here as we haven't committed yet for this transaction
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval') + f'#pa-{request_id}')

    approval_request.product_description = product_description
    approval_request.contractor_id = current_user.id # Set/update contractor
    if files_uploaded_count > 0 or (product_description != approval_request.product_description): # Update submission date if new files or changed description
        approval_request.submission_date = datetime.utcnow()

    # Update status:
    # If 'waiting_for_proposal' and docs exist/uploaded, move to 'product_provided'.
    # If 'rejected' and changes made (new files or description change), move to 'product_provided'.
    if approval_request.status == 'waiting_for_proposal' and (files_uploaded_count > 0 or existing_documents_count > 0):
        approval_request.status = 'product_provided'
    elif approval_request.status == 'rejected' and (files_uploaded_count > 0 or product_description != approval_request.product_description or existing_documents_count > 0):
        # If it was rejected, and now new files are added OR description changed OR there are existing documents (implying an edit to a previously populated submission)
        # then it should go back to 'product_provided' for re-review.
        approval_request.status = 'product_provided'
        # Also ensure approver fields are cleared if it's being resubmitted after rejection
        approval_request.approver_id = None
        approval_request.approval_date = None
        approval_request.approver_comments = None


    try:
        db.session.commit()
        if files_uploaded_count > 0:
            flash(f'{files_uploaded_count} document(s) uploaded successfully. Product information updated.', 'success')
            logger.info(f"Successfully committed to DB for request_id: {request_id}. Files uploaded: {files_uploaded_count}. Description updated.")
        elif product_description != approval_request.product_description : # Check if only description was changed
             flash('Product description updated successfully.', 'success')
             logger.info(f"Successfully committed to DB for request_id: {request_id}. Only description updated.")
        else:
            flash('No changes detected or no new files uploaded.', 'info') # If neither files nor description changed
            logger.info(f"No changes to commit for request_id: {request_id}")

    except Exception as e:
        db.session.rollback()
        logger.error(f"Error committing product submission for PA request {request_id}: {e}", exc_info=True)
        flash('An error occurred while saving the product information.', 'error')

    return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

@app.route('/product_approval/<int:request_id>/decide', methods=['POST'])
@login_required
def decide_product_approval(request_id):
    approval_request = db.session.get(ProductApproval, request_id)
    if not approval_request:
        flash('Product approval request not found.', 'error')
        return redirect(request.referrer or url_for('index'))

    project_id = approval_request.project_id
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access or access.role not in ['admin', 'supervisor']:
        flash('You do not have permission to approve or reject this product.', 'error')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

    if approval_request.status != 'product_provided':
        flash('This product submission cannot be decided upon at this stage.', 'warning')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

    decision = request.form.get('decision') # 'approve' or 'reject'
    approver_comments = request.form.get('approver_comments', '').strip()

    if decision not in ['approve', 'reject']:
        flash('Invalid decision submitted.', 'error')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval') + f'#pa-{request_id}')

    approval_request.status = 'approved' if decision == 'approve' else 'rejected'
    approval_request.approver_id = current_user.id
    approval_request.approval_date = datetime.utcnow()
    approval_request.approver_comments = approver_comments

    db.session.commit()
    flash(f'Product submission {decision}d successfully.', 'success')
    return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

@app.route('/product_documentation/<path:filename>')
@login_required # Add login required and further permission checks if needed
def serve_product_documentation(filename):
    # Basic permission check: user must be authenticated.
    # More granular check: user must have access to the project this doc belongs to.
    # This requires finding which ProductApproval request `filename` belongs to.
    # For simplicity, this is omitted here but should be added for production.
    # E.g., query ProductApproval by documentation_path, then check project access.
    documentation_dir = os.path.join(app.static_folder, 'product_documentation')
    return send_from_directory(documentation_dir, filename)

@app.route('/product_document/<int:document_id>/delete', methods=['POST'])
@login_required
def delete_product_document(document_id):
    document = db.session.get(ProductDocument, document_id)
    if not document:
        flash('Document not found.', 'error')
        return redirect(request.referrer or url_for('index'))

    approval_request = document.product_approval
    project_id = approval_request.project_id
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()

    # Permission check: Uploader or Admin/Supervisor of the project
    if not (access and (current_user.id == document.uploader_id or access.role in ['admin', 'supervisor'])) :
        flash('You do not have permission to delete this document.', 'error')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval') + f'#pa-{approval_request.id}')

    file_on_disk_path = os.path.join(app.static_folder, 'product_documentation', document.file_path)

    try:
        if os.path.exists(file_on_disk_path):
            os.remove(file_on_disk_path)
            logger.info(f"Deleted product document file: {file_on_disk_path}")
        else:
            logger.warning(f"Product document file not found on disk for deletion: {file_on_disk_path}")

        db.session.delete(document)
        db.session.commit()
        flash('Document deleted successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting product document {document_id}: {e}")
        flash('An error occurred while deleting the document.', 'error')

    return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval') + f'#pa-{approval_request.id}')

@app.route('/product_approval/<int:request_id>/delete', methods=['POST'])
@login_required
def delete_product_approval_request(request_id):
    approval_request = db.session.get(ProductApproval, request_id)
    if not approval_request:
        flash('Product approval request not found.', 'error')
        return redirect(request.referrer or url_for('index'))

    project_id = approval_request.project_id
    # Permission check: Only the user who created the request can delete it.
    if approval_request.requester_id != current_user.id:
        flash('You do not have permission to delete this product approval request.', 'error')
        return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))

    try:
        # Delete associated documents and their files
        for document in approval_request.documents:
            file_on_disk_path = os.path.join(app.static_folder, 'product_documentation', document.file_path)
            if os.path.exists(file_on_disk_path):
                os.remove(file_on_disk_path)
                logger.info(f"Deleted product document file: {file_on_disk_path}")
            else:
                logger.warning(f"Product document file not found on disk for deletion: {file_on_disk_path}")
            db.session.delete(document)

        # Delete the product approval request itself
        db.session.delete(approval_request)
        db.session.commit()
        flash('Product approval request and associated documents deleted successfully.', 'success')
        logger.info(f"Product approval request {request_id} deleted by user {current_user.id}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting product approval request {request_id}: {e}", exc_info=True)
        flash('An error occurred while deleting the product approval request.', 'error')

    return redirect(url_for('project_detail', project_id=project_id, active_tab_override='products_approval'))
# --- End Product Approval Routes ---

@app.route('/test_login', methods=['POST'])
@csrf.exempt
def test_login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.check_password_hash(user.password, password):
        login_user(user)
        logger.info(f"User '{username}' logged in for testing.")
        return jsonify({"status": "success", "message": f"User {username} logged in."}), 200
    logger.warning(f"Test login failed for user '{username}'.")
    return jsonify({"status": "error", "message": "Invalid credentials."}), 401

# Removed duplicated /test_login route definition that was here.

@app.route('/setup_test_data')
@csrf.exempt # setup_test_data is GET, but exempting is fine.
def setup_test_data():
    with app.app_context():
        try:
            db.drop_all() # Ensure a clean slate
            init_db()    # Recreate tables based on models
            logger.info("Dropped and re-initialized database for test data setup.")

            # 1. Create Users
            admin_user = User.query.filter_by(username='testadmin').first()
            if not admin_user:
                admin_user = User(username='testadmin', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='admin')
                db.session.add(admin_user)
                logger.info("Created admin user 'testadmin'")

            contractor_user = User.query.filter_by(username='testcontractor').first()
            if not contractor_user:
                contractor_user = User(username='testcontractor', password=bcrypt.generate_password_hash('password').decode('utf-8'), role='contractor')
                db.session.add(contractor_user)
                logger.info("Created contractor user 'testcontractor'")

            db.session.commit() # Commit users to get their IDs

            # 2. Create Project
            project = Project.query.filter_by(name="Comprehensive Test Project").first()
            if not project:
                project = Project(name="Comprehensive Test Project")
                db.session.add(project)
                db.session.commit() # Commit project to get its ID
                logger.info(f"Created project: {project.name} (ID: {project.id})")

                # Grant admin access to the project
                admin_access = ProjectAccess(user_id=admin_user.id, project_id=project.id, role='admin')
                db.session.add(admin_access)
                # Grant contractor access to the project (assuming they need it for comments)
                contractor_access = ProjectAccess(user_id=contractor_user.id, project_id=project.id, role='contractor')
                db.session.add(contractor_access)
                db.session.commit()
                logger.info(f"Granted admin and contractor access to project {project.id}")


            # 3. Create Drawing records
            drawing1 = Drawing.query.filter_by(name='Test Drawing 1').first()
            if not drawing1:
                drawing1 = Drawing(project_id=project.id, name='Test Drawing 1', file_path='drawings/test_drawing1.pdf')
                db.session.add(drawing1)

            drawing2 = Drawing.query.filter_by(name='Complex Drawing').first()
            if not drawing2:
                drawing2 = Drawing(project_id=project.id, name='Complex Drawing', file_path='drawings/complex_drawing.pdf')
                db.session.add(drawing2)

            drawing3 = Drawing.query.filter_by(name='Fake Drawing').first()
            if not drawing3:
                drawing3 = Drawing(project_id=project.id, name='Fake Drawing', file_path='drawings/fake_drawing.pdf')
                db.session.add(drawing3)

            db.session.commit() # Commit drawings to get their IDs
            logger.info("Created Drawing records.")


            # 4. Defect Scenarios
            logger.info("Creating Defect Scenarios...")
            # D1
            d1 = Defect(project_id=project.id, description="Open defect with basic details.", status='open', creator_id=admin_user.id, creation_date=datetime.now())
            db.session.add(d1)

            # D2
            d2 = Defect(project_id=project.id, description="Closed defect with a valid JPG image.", status='closed', creator_id=admin_user.id, creation_date=datetime.now(), close_date=datetime.now())
            db.session.add(d2)
            db.session.flush() # Get d2.id before creating attachment
            att_d2 = Attachment(defect_id=d2.id, file_path='images/test_image1.jpg', thumbnail_path='images/thumbnails/thumb_test_image1.jpg')
            db.session.add(att_d2)
            # Simulate thumbnail creation for test_image1.jpg
            thumbnail_dir = ensure_thumbnail_directory()
            test_image1_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_image1.jpg')
            thumb_test_image1_path = os.path.join(thumbnail_dir, 'thumb_test_image1.jpg')
            if not os.path.exists(thumb_test_image1_path):
                 if os.path.exists(test_image1_path):
                    create_thumbnail(test_image1_path, thumb_test_image1_path)
                 else:
                    logger.warning("test_image1.jpg not found for thumbnail creation in test setup.")

            # D3
            d3 = Defect(project_id=project.id, description="Open defect with a marked PDF drawing (test_drawing1.pdf).", status='open', creator_id=admin_user.id, creation_date=datetime.now())
            db.session.add(d3)
            db.session.flush()
            marker_d3 = DefectMarker(defect_id=d3.id, drawing_id=drawing1.id, x=0.5, y=0.5)
            db.session.add(marker_d3)

            # D4
            d4 = Defect(project_id=project.id, description="Open defect with a marked complex PDF (complex_drawing.pdf).", status='open', creator_id=admin_user.id, creation_date=datetime.now())
            db.session.add(d4)
            db.session.flush()
            marker_d4 = DefectMarker(defect_id=d4.id, drawing_id=drawing2.id, x=0.2, y=0.8)
            db.session.add(marker_d4)

            # D5
            d5 = Defect(project_id=project.id, description="Open defect with a PNG image and a contractor comment that also has an image.", status='open', creator_id=admin_user.id, creation_date=datetime.now())
            db.session.add(d5)
            db.session.flush()
            att_d5_defect = Attachment(defect_id=d5.id, file_path='images/test_image2.png', thumbnail_path='images/thumbnails/thumb_test_image2.png')
            db.session.add(att_d5_defect)
            thumbnail_dir = ensure_thumbnail_directory() # ensure_thumbnail_directory already called for att_d2
            test_image2_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_image2.png')
            thumb_test_image2_path = os.path.join(thumbnail_dir, 'thumb_test_image2.png')
            if not os.path.exists(thumb_test_image2_path):
                 if os.path.exists(test_image2_path):
                    create_thumbnail(test_image2_path, thumb_test_image2_path)
                 else:
                    logger.warning("test_image2.png not found for thumbnail creation in test setup.")

            comment_d5 = Comment(defect_id=d5.id, user_id=contractor_user.id, content="Work in progress. See attached photo.", created_at=datetime.now())
            db.session.add(comment_d5)
            db.session.flush()
            att_d5_comment = Attachment(comment_id=comment_d5.id, file_path='images/test_image1.jpg', thumbnail_path='images/thumbnails/thumb_test_image1.jpg') # Reuses test_image1
            db.session.add(att_d5_comment)
            # Thumbnail for test_image1 already handled with D2

            # D6
            d6 = Defect(project_id=project.id, description="Open defect with a corrupt image.", status='open', creator_id=admin_user.id, creation_date=datetime.now())
            db.session.add(d6)
            db.session.flush()
            corrupt_image_filename = 'corrupt_image.jpg'
            corrupt_image_path = os.path.join(app.config['UPLOAD_FOLDER'], corrupt_image_filename)
            thumb_corrupt_image_filename = f'thumb_{corrupt_image_filename}'
            thumb_corrupt_image_path_for_db = os.path.join('images', 'thumbnails', thumb_corrupt_image_filename)
            thumb_corrupt_image_disk_path = os.path.join(ensure_thumbnail_directory(), thumb_corrupt_image_filename)

            if not os.path.exists(corrupt_image_path):
                with open(corrupt_image_path, 'w') as f: f.write("dummy corrupt data") 
            
            att_d6 = Attachment(defect_id=d6.id, file_path=os.path.join('images', corrupt_image_filename), thumbnail_path=thumb_corrupt_image_path_for_db)
            db.session.add(att_d6)
            try:
                create_thumbnail(corrupt_image_path, thumb_corrupt_image_disk_path)
            except Exception as e:
                logger.warning(f"Could not create thumbnail for {corrupt_image_filename} during test setup: {e}")
            
            # D7
            d7 = Defect(project_id=project.id, description="Open defect with a marked non-PDF file (fake_drawing.pdf).", status='open', creator_id=admin_user.id, creation_date=datetime.now())
            db.session.add(d7)
            db.session.flush()
            marker_d7 = DefectMarker(defect_id=d7.id, drawing_id=drawing3.id, x=0.3, y=0.3)
            db.session.add(marker_d7)

            # D8
            long_desc = "This is a very long description designed to test text wrapping within the PDF report. " + "It needs to be sufficiently lengthy to ensure that multiple lines are generated, and ideally, it should push the boundaries of the available column width. " * 5 + "End of long description."
            d8 = Defect(project_id=project.id, description=long_desc, status='open', creator_id=admin_user.id, creation_date=datetime.now())
            db.session.add(d8)
            db.session.flush()
            comment_d8_admin = Comment(defect_id=d8.id, user_id=admin_user.id, content="First comment, checking layout.", created_at=datetime.now())
            db.session.add(comment_d8_admin)
            comment_d8_contractor = Comment(defect_id=d8.id, user_id=contractor_user.id, content="Second comment by contractor, this also needs to be long enough to properly test how text wrapping behaves in the designated comment area of the PDF report. Let's add some more words.", created_at=datetime.now())
            db.session.add(comment_d8_contractor)

            # D9
            d9 = Defect(project_id=project.id, description="Simple closed defect.", status='closed', creator_id=admin_user.id, creation_date=datetime.now(), close_date=datetime.now())
            db.session.add(d9)

            db.session.commit()
            logger.info("Finished creating Defect Scenarios.")

            # 5. Checklist Scenarios
            logger.info("Creating Checklist Scenarios...")
            checklist1 = Checklist(project_id=project.id, name="General Safety Checks", creation_date=datetime.now())
            db.session.add(checklist1)
            db.session.commit() # Get checklist1.id

            # CLI1.1
            cli1_1 = ChecklistItem(checklist_id=checklist1.id, item_text="Verify all safety guards are in place.", is_checked=False)
            db.session.add(cli1_1)

            # CLI1.2
            cli1_2 = ChecklistItem(checklist_id=checklist1.id, item_text="Fire extinguishers inspected.", is_checked=True)
            db.session.add(cli1_2)
            db.session.flush()
            att_cli1_2 = Attachment(checklist_item_id=cli1_2.id, file_path='images/test_image2.png', thumbnail_path='images/thumbnails/thumb_test_image2.png') # Reuses test_image2
            db.session.add(att_cli1_2)
            # Thumbnail for test_image2.png already handled with D5

            # CLI1.3
            cli1_3 = ChecklistItem(checklist_id=checklist1.id, item_text="Emergency exits clear.", is_checked=False, comments="Blocked by temporary storage, needs addressing.")
            db.session.add(cli1_3)

            db.session.commit()
            logger.info("Finished creating Checklist Scenarios.")

            return "Test data setup complete!"
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error setting up test data: {str(e)}", exc_info=True)
            return f"Error setting up test data: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)

# --------------- End Temporary Test Route --------------- # This line (and everything above it including the __main__ guard) should be the end of the file.

@app.cli.command("ensure-user-schema")
def ensure_user_schema_command():
    """Checks and ensures the 'email' and 'status' columns exist in the 'users' table."""
    with app.app_context():
        inspector = inspect(db.engine)

        if 'users' not in inspector.get_table_names():
            print("Error: 'users' table does not exist. Please run init_db or ensure migrations are applied first.")
            return

        columns = [col['name'] for col in inspector.get_columns('users')]
        indexes = inspector.get_indexes('users')
        index_names = [idx['name'] for idx in indexes]

        with db.engine.connect() as connection:
            transaction = connection.begin()
            try:
                if 'email' not in columns:
                    print("Adding 'email' column to 'users' table.")
                    connection.execute(db.text('ALTER TABLE users ADD COLUMN email VARCHAR(255)'))
                    # For PostgreSQL, UNIQUE constraint can be added with the column or separately.
                    # To ensure it's added if the column is new, and to handle existing data,
                    # it's often added separately or checked.
                    if 'ix_users_email' not in index_names: # Check if index already exists
                        print("Adding UNIQUE index 'ix_users_email' for 'email' column.")
                        connection.execute(db.text('CREATE UNIQUE INDEX ix_users_email ON users (email)'))
                    print("Finished 'email' column and index setup.")
                else:
                    print("'email' column already exists in 'users' table.")
                    if 'ix_users_email' not in index_names:
                        try:
                            print("Attempting to add UNIQUE index 'ix_users_email' to existing 'email' column.")
                            connection.execute(db.text('CREATE UNIQUE INDEX ix_users_email ON users (email)'))
                            print("UNIQUE index 'ix_users_email' added.")
                        except Exception as e_index: # Catch if index creation fails (e.g., duplicate data)
                            print(f"Could not create UNIQUE index 'ix_users_email'. It might already exist or there's duplicate data: {e_index}")


                if 'status' not in columns:
                    print("Adding 'status' column to 'users' table.")
                    connection.execute(db.text("ALTER TABLE users ADD COLUMN status VARCHAR(50) NOT NULL DEFAULT 'pending_activation'"))
                    connection.execute(db.text("UPDATE users SET status = 'pending_activation' WHERE status IS NULL"))
                    print("'status' column added and NULLs updated.")
                else:
                    print("'status' column already exists in 'users' table.")

                # Attempt to set existing, non-temporary users to 'active'
                print("Attempting to update status to 'active' for existing non-temporary users.")
                connection.execute(db.text("UPDATE users SET status = 'active' WHERE username NOT LIKE 'temp_%' AND status = 'pending_activation'"))

                # Add 'name' column if it doesn't exist
                if 'name' not in columns:
                    print("Adding 'name' column to 'users' table.")
                    connection.execute(db.text("ALTER TABLE users ADD COLUMN name VARCHAR(255) NOT NULL DEFAULT 'N/A'"))
                    connection.execute(db.text("UPDATE users SET name = 'N/A' WHERE name IS NULL"))
                    print("'name' column added and NULLs updated.")
                else:
                    print("'name' column already exists in 'users' table.")

                # Add 'company' column if it doesn't exist
                if 'company' not in columns:
                    print("Adding 'company' column to 'users' table.")
                    connection.execute(db.text("ALTER TABLE users ADD COLUMN company VARCHAR(255) NOT NULL DEFAULT 'N/A'"))
                    connection.execute(db.text("UPDATE users SET company = 'N/A' WHERE company IS NULL"))
                    print("'company' column added and NULLs updated.")
                else:
                    print("'company' column already exists in 'users' table.")

                transaction.commit()
                print("User schema changes committed successfully.")

            except Exception as e:
                transaction.rollback()
                print(f"Error during user schema check/update: {e}")

            # Verification of UNIQUE constraint on email (optional, as creation attempt was made)
            # This part is more for diagnostics.
            # Re-fetch indexes after potential changes
            final_indexes = inspect(db.engine).get_indexes('users')
            final_index_names = [idx['name'] for idx in final_indexes]
            if 'ix_users_email' in final_index_names:
                print("UNIQUE constraint 'ix_users_email' on 'email' is confirmed to exist.")
            else:
                print("Warning: UNIQUE constraint 'ix_users_email' on 'email' may not have been created or was not detected.")


@app.cli.command("ensure-schema")
def ensure_schema_command():
    """Checks and ensures the 'page_num' column exists in the 'defect_markers' table."""
    with app.app_context():
        inspector = inspect(db.engine)
        with db.engine.connect() as connection:
            try:
                print("Checking for 'page_num' column in 'defect_markers' table...")
                if 'defect_markers' not in inspector.get_table_names():
                    print("Error: 'defect_markers' table does not exist. Please run init_db or ensure migrations are applied first.")
                    return

                columns = [col['name'] for col in inspector.get_columns('defect_markers')]

                if 'page_num' not in columns:
                    print("'page_num' column not found in 'defect_markers'. Adding column...")
                    # For PostgreSQL, the ALTER TABLE syntax is similar for adding a column.
                    # However, using SQLAlchemy Core for DDL is more portable if complex changes are needed.
                    # For this simple case, direct SQL is often fine.
                    connection.execute(db.text("ALTER TABLE defect_markers ADD COLUMN page_num INTEGER NOT NULL DEFAULT 1;"))
                    connection.commit() # Important: commit DDL changes
                    print("'page_num' column added to 'defect_markers' table successfully.")
                else:
                    print("'page_num' column already exists in 'defect_markers' table.")
            except Exception as e:
                print(f"Error during schema check/update: {str(e)}")
                connection.rollback() # Ensure rollback on error
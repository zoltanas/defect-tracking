from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, send_from_directory, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_bcrypt import Bcrypt
import click # For Flask CLI
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

# Set SQLite database URI with absolute path
default_db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'myapp.db')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', f'sqlite:///{default_db_path}')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/images'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['DRAWING_FOLDER'] = 'static/drawings'
app.config['SERIALIZER_SECRET_KEY'] = 'your-serializer-secret-key'
app.config['REPORT_FOLDER'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'reports')



# Create instance directory for SQLite database
db_dir = os.path.dirname(default_db_path)
os.makedirs(db_dir, exist_ok=True)
logger.info(f"Ensured database directory exists: {db_dir}")

# Create report directory
os.makedirs(app.config['REPORT_FOLDER'], exist_ok=True)
logger.info(f"Ensured report directory exists: {app.config['REPORT_FOLDER']}")

# Create drawing folder
os.makedirs(app.config['DRAWING_FOLDER'], exist_ok=True)
logger.info(f"Ensured drawing directory exists: {app.config['DRAWING_FOLDER']}")

# Verify write permissions
if not os.access(db_dir, os.W_OK):
    logger.error(f"No write permissions for database directory: {db_dir}")
    raise PermissionError(f"No write permissions for database directory: {db_dir}")

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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    projects = db.relationship('ProjectAccess', back_populates='user', cascade='all, delete-orphan')

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

class Defect(db.Model):
    __tablename__ = 'defects'
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
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
    defect_id = db.Column(db.Integer, db.ForeignKey('defects.id'), nullable=False)
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
    defect_id = db.Column(db.Integer, db.ForeignKey('defects.id'))
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
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'))
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
                    'drawings', 'defect_markers'
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
    return db.session.get(User, int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def ensure_thumbnail_directory():
    # app refers to the Flask app instance, UPLOAD_FOLDER is 'static/images'
    thumbnail_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'thumbnails')
    if not os.path.exists(thumbnail_dir):
        os.makedirs(thumbnail_dir, exist_ok=True)
        os.chmod(thumbnail_dir, 0o755)  # Ensure correct permissions
    return thumbnail_dir

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
            img.save(thumbnail_save_path, quality=85, optimize=True)
            os.chmod(thumbnail_save_path, 0o644)
        logger.debug(f'Created thumbnail: {thumbnail_save_path}')
    except Exception as e:
        logger.error(f'Thumbnail creation failed for {image_path} to {thumbnail_save_path}: {str(e)}')
        raise

# Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = 'admin'
        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return redirect(url_for('register'))
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/invite', methods=['GET', 'POST'])
@login_required
def invite():
    if current_user.role != 'admin':
        flash('Only admins can invite users.', 'error')
        return redirect(url_for('index'))
    if request.method == 'POST':
        project_id = request.form['project_id']
        role = request.form['role']
        if role not in ['admin', 'expert', 'contractor']:
            return jsonify({'status': 'error', 'message': 'Invalid role selected.'}), 400
        project = db.session.get(Project, project_id)
        if not project:
            return jsonify({'status': 'error', 'message': 'Project not found.'}), 404
        # Create a temporary user with a placeholder username
        temp_username = f"temp_{os.urandom(8).hex()}"
        temp_password = os.urandom(16).hex()
        hashed_password = bcrypt.generate_password_hash(temp_password).decode('utf-8')
        user = User(username=temp_username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        access = ProjectAccess(user_id=user.id, project_id=project_id, role=role)
        db.session.add(access)
        s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
        token = s.dumps({'user_id': user.id, 'project_id': project_id, 'role': role})
        invite_link = url_for('accept_invite', token=token, _external=True)
        db.session.commit()
        return jsonify({'status': 'success', 'invite_link': invite_link})
    projects = Project.query.all()
    return render_template('invite.html', projects=projects)

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
            username = request.form['username'].strip()
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            if password != confirm_password:
                flash('Passwords do not match.', 'error')
                return redirect(url_for('accept_invite', token=token))
            if User.query.filter_by(username=username).first():
                flash('Username already taken.', 'error')
                return redirect(url_for('accept_invite', token=token))
            user.username = username
            user.password = bcrypt.generate_password_hash(password).decode('utf-8')
            db.session.commit()
            login_user(user)
            flash('Invitation accepted! You are now logged in.', 'success')
            return redirect(url_for('index'))
        return render_template('accept_invite.html', token=token)
    except Exception as e:
        flash('Invalid or expired invitation.', 'error')
        return redirect(url_for('login'))

# Application Routes
@app.route('/')
@login_required
def index():
    # Get project IDs where the user has access (either as creator or assigned)
    project_ids = [access.project_id for access in current_user.projects]
    projects = Project.query.filter(Project.id.in_(project_ids)).all()
    return render_template('project_list.html', projects=projects)

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
    defects_query = Defect.query.filter_by(project_id=project_id)
    if filter_status == 'Open':
        defects = defects_query.filter_by(status='open').all()
    elif filter_status == 'Closed':
        defects = defects_query.filter_by(status='closed').all()
    else:
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


    checklists = Checklist.query.filter_by(project_id=project_id).all()
    filtered_checklists = []
    for checklist in checklists:
        items = ChecklistItem.query.filter_by(checklist_id=checklist.id).all()
        has_open_items = any(not item.is_checked for item in items)
        if filter_status == 'Open' and not has_open_items:
            continue
        elif filter_status == 'Closed' and has_open_items:
            continue
        filtered_checklists.append(checklist)
    return render_template('project_detail.html', project=project, defects=defects, checklists=filtered_checklists, filter_status=filter_status, user_role=access.role)

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
    markers = DefectMarker.query.filter_by(drawing_id=drawing_id).all()
    # Serialize markers
    markers_data = [
        {
            'defect_id': marker.defect_id,
            'x': marker.x,
            'y': marker.y,
            'description': marker.defect.description
        } for marker in markers
    ]
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
                if access.role not in ['admin', 'expert']:
                    flash('You do not have permission to edit defects.', 'error')
                    return redirect(url_for('defect_detail', defect_id=defect_id))

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
                                if defect.creator_id != current_user.id and access.role != 'admin':
                                    flash('Only the defect creator or an admin can close this defect.', 'error')
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
                    # page_num_str = request.form.get('page_num') # If page numbers are implemented

                    if drawing_id_str and marker_x_str and marker_y_str:
                        try:
                            drawing_id_val = int(drawing_id_str)
                            marker_x_val = float(marker_x_str)
                            marker_y_val = float(marker_y_str)
                            # page_num = int(page_num_str) if page_num_str and page_num_str.isdigit() else 1

                            if not (0 <= marker_x_val <= 1 and 0 <= marker_y_val <= 1):
                                flash('Marker coordinates must be between 0 and 1.', 'error')
                                error_occurred = True
                            else:
                                # Validate drawing_id_val - ensure it's a valid drawing for the project
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
                                        # page_num is not part of DefectMarker model
                                        logger.info(f"Updated marker for defect {defect_id}")
                                    else:
                                        new_marker = DefectMarker(defect_id=defect_id, drawing_id=drawing_id_val, x=marker_x_val, y=marker_y_val)
                                        db.session.add(new_marker)
                                        logger.info(f"Created new marker for defect {defect_id}")
                        except ValueError:
                            flash('Invalid marker data format (e.g., non-numeric values).', 'error')
                            error_occurred = True
                            logger.warning(f"ValueError for marker data, defect {defect_id}: drawing_id='{drawing_id_str}', x='{marker_x_str}', y='{marker_y_str}'")
                   
                    elif not drawing_id_str: # If drawing_id is empty, remove existing marker
                        existing_marker = DefectMarker.query.filter_by(defect_id=defect_id).first()
                        if existing_marker:
                            db.session.delete(existing_marker)
                            logger.info(f"Deleted marker for defect {defect_id} as no drawing was selected.")
                
                if error_occurred:
                    db.session.rollback()
                else:
                    db.session.commit()
                    flash('Defect updated successfully!', 'success')
                
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
    if not access or access.role != 'admin':
        flash('Only admins can add checklists.', 'error')
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

@app.route('/checklist/<int:checklist_id>', methods=['GET', 'POST'])
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
    if request.method == 'POST':
        logger.debug(f'Received POST for checklist {checklist_id}')
        try:
            for item in items:
                checked_key = f'item_{item.id}_checked'
                comments_key = f'item_{item.id}_comments'
                photos_key = f'item_{item.id}_photos'
                item.is_checked = checked_key in request.form
                item.comments = request.form.get(comments_key, '').strip()
                files = request.files.getlist(photos_key)
                attachment_ids = []
                for file in files:
                    if file and allowed_file(file.filename):
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        filename = secure_filename(f'checklist_{item.id}_{timestamp}_{file.filename}')
                        # Path for storing in DB (relative to static folder)
                        db_file_path = os.path.join('images', filename)
                        disk_save_full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        
                        thumbnail_dir = ensure_thumbnail_directory()
                        thumbnail_filename_base = f'thumb_{filename}'
                        thumbnail_disk_path = os.path.join(thumbnail_dir, thumbnail_filename_base) # Full path for saving
                        db_thumbnail_path = os.path.join('images', 'thumbnails', thumbnail_filename_base) # Relative path for DB

                        try:
                            logger.info(f"Processing file: {file.filename} for checklist item {item.id}")
                            img = PILImage.open(file) 
                            img = ImageOps.exif_transpose(img)
                            img = img.convert('RGB')

                            logger.info(f"Attempting to save original image to: {disk_save_full_path}")
                            img.save(disk_save_full_path, quality=85, optimize=True)
                            os.chmod(disk_save_full_path, 0o644)
                            logger.info(f"Successfully saved original image to: {disk_save_full_path}")

                            logger.info(f"Attempting to create thumbnail: {thumbnail_disk_path} from {disk_save_full_path}")
                            create_thumbnail(disk_save_full_path, thumbnail_disk_path) # create_thumbnail saves to thumbnail_disk_path
                            logger.info(f"Successfully created thumbnail: {thumbnail_disk_path}")

                            logger.info(f"Creating attachment record with db_file_path: {db_file_path}, db_thumbnail_path: {db_thumbnail_path}")
                            attachment = Attachment(
                                checklist_item_id=item.id,
                                file_path=db_file_path, 
                                thumbnail_path=db_thumbnail_path 
                            )
                            db.session.add(attachment)
                            db.session.commit() # Commit for this specific attachment
                            logger.info(f"Successfully committed attachment {attachment.id} for item {item.id}")

                            attachment_ids.append(attachment.id)
                        except Exception as e:
                            flash(f'Error uploading file {file.filename}: {str(e)}', 'error')
                            logger.error(f'Error uploading file {file.filename} for item {item.id}: {str(e)}', exc_info=True)
                            db.session.rollback()
                            continue
                if attachment_ids:
                    # Redirect to draw the first uploaded image
                    # This part remains outside the file loop, but uses the collected attachment_ids
                    return redirect(url_for('draw', attachment_id=attachment_ids[0], next=url_for('checklist_detail', checklist_id=checklist_id)))

            # The main commit for item.is_checked and item.comments happens after processing all files for that item
            db.session.commit()
            flash('Checklist updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating checklist: {str(e)}', 'error')
            logger.error(f'Error updating checklist {checklist_id}: {str(e)}')
            return redirect(url_for('checklist_detail', checklist_id=checklist_id))
        return redirect(url_for('project_detail', project_id=checklist.project.id, _anchor='checklists'))
    project = checklist.project
    return render_template('checklist_detail.html', checklist=checklist, items=items, project=project)

@app.route('/checklist/<int:checklist_id>/delete', methods=['POST'])
@login_required
def delete_checklist(checklist_id):
    checklist = db.session.get(Checklist, checklist_id)
    if not checklist:
        flash('Checklist not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=checklist.project_id).first()
    if not access or access.role != 'admin':
        flash('Only admins can delete checklists.', 'error')
        return redirect(url_for('project_detail', project_id=checklist.project_id))
    project_id = checklist.project_id
    items = ChecklistItem.query.filter_by(checklist_id=checklist_id).all()
    for item in items:
        attachments = Attachment.query.filter_by(checklist_item_id=item.id).all()
        for attachment in attachments:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path))
            thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.thumbnail_path)) if attachment.thumbnail_path else None
            if os.path.exists(file_path):
                os.remove(file_path)
            if thumbnail_path and os.path.exists(thumbnail_path):
                os.remove(thumbnail_path)
            db.session.delete(attachment)
        db.session.delete(item)
    db.session.delete(checklist)
    db.session.commit()
    flash('Checklist deleted successfully!', 'success')
    return redirect(url_for('project_detail', project_id=project_id, _anchor='checklists'))

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
    
    # Permission check: Creator, Admin, or Expert
    # Ensure current_user is available and has role attribute
    if not (current_user.id == defect.creator_id or (hasattr(current_user, 'role') and current_user.role in ['admin', 'expert'])):
        return jsonify(success=False, error="Permission denied."), 403

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
    
    # Permission check: Creator, Admin, or Expert
    if not (current_user.id == defect.creator_id or (hasattr(current_user, 'role') and current_user.role in ['admin', 'expert'])):
        return jsonify(success=False, error="Permission denied."), 403

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

    if not (current_user.id == defect.creator_id or (hasattr(current_user, 'role') and current_user.role in ['admin', 'expert'])):
        return jsonify(success=False, error="Permission denied."), 403

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
    if current_user.role != 'admin':
        flash('Only admins can manage templates.', 'error')
        return redirect(url_for('index'))
    templates = Template.query.all()
    return render_template('template_list.html', templates=templates)

@app.route('/add_template', methods=['GET', 'POST'])
@login_required
def add_template():
    if current_user.role != 'admin':
        flash('Only admins can add templates.', 'error')
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
    if current_user.role != 'admin':
        flash('Only admins can edit templates.', 'error')
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
    if current_user.role != 'admin':
        flash('Only admins can delete templates.', 'error')
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
    defects_query = Defect.query.options(
        db.joinedload(Defect.creator),
        db.joinedload(Defect.attachments),
        db.joinedload(Defect.comments).joinedload(Comment.user),
        db.joinedload(Defect.comments).joinedload(Comment.attachments),
        db.joinedload(Defect.markers).joinedload(DefectMarker.drawing)
    ).filter_by(project_id=project_id)

    if filter_status == 'Open':
        defects = defects_query.filter_by(status='open').order_by(Defect.creation_date.asc()).all()
    elif filter_status == 'Closed':
        defects = defects_query.filter_by(status='closed').order_by(Defect.close_date.desc(), Defect.creation_date.asc()).all()
    else: # All
        all_defects_db = defects_query.order_by(Defect.creation_date.asc()).all()
        defects = sorted([d for d in all_defects_db if d.status == 'open'], key=lambda d: d.creation_date if d.creation_date else datetime.min) + \
                    sorted([d for d in all_defects_db if d.status == 'closed'],
                           key=lambda d: (d.close_date if d.close_date else datetime.min, d.creation_date if d.creation_date else datetime.min), reverse=True)
    logger.info(f"Fetched {len(defects)} defects for the report.")

    for defect in defects:
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
                        logger.info(f"Successfully generated marked drawing for defect {defect.id}: {defect.marked_drawing_image_path}")
                    else:
                        logger.warning(f"convert_from_path returned no images for PDF: {pdf_full_path}, defect {defect.id}")
                except Exception as e:
                    logger.error(f"Error during PDF to image conversion or drawing marker for defect {defect.id}, PDF: {pdf_full_path}. Error: {e}", exc_info=True)
                    defect.marked_drawing_image_path = None # Ensure it's None if conversion failed
            else:
                logger.warning(f"Marked drawing PDF not found at path: {pdf_full_path} for defect {defect.id}")

    # Fetch checklists
    checklists_db = Checklist.query.filter_by(project_id=project_id).order_by(Checklist.name.asc()).all()
    report_checklists = []
    for checklist_obj in checklists_db:
        items_db = ChecklistItem.query.options(
            db.joinedload(ChecklistItem.attachments)
        ).filter_by(checklist_id=checklist_obj.id).order_by(ChecklistItem.id.asc()).all()

        filtered_items = []
        for item_obj in items_db:
            item_status_val = 'closed' if item_obj.is_checked else 'open'
            if filter_status == 'Open' and item_status_val != 'open':
                continue
            elif filter_status == 'Closed' and item_status_val != 'closed':
                continue
            filtered_items.append(item_obj)

        if filtered_items: # Only add checklist if it has items matching the filter
            report_checklists.append({'checklist_info': checklist_obj, 'items': filtered_items})

    html_out = render_template(
        'report_template.html',
        project=project,
        generation_date=generation_date_str,
        defects=defects,
        checklists=report_checklists,
        filter_status=filter_status,
        app_config=app.config
    )

    logger.info(f"Fetched {len(report_checklists)} checklists with items matching filter for the report.")

    logger.info("Rendering HTML template for WeasyPrint...")
    html_out = render_template(
        'report_template.html',
        project=project,
        generation_date=generation_date_str,
        defects=defects,
        checklists=report_checklists,
        filter_status=filter_status,
        app_config=app.config
    )
    logger.info("HTML template rendered.")

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
        img_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path))
        if not os.path.exists(img_path):
            return jsonify({'status': 'error', 'message': f'Image file not found: {attachment.file_path}'}), 404
        try:
            with PILImage.open(img_path) as img:
                img = img.convert('RGB')
                draw = ImageDraw.Draw(img)
                img_width, img_height = img.size
                for line in lines:
                    points = line.get('points', [])
                    color = line.get('color', '#000000')
                    width = line.get('width', 5)
                    if not isinstance(points, list) or len(points) < 2:
                        continue
                    if not isinstance(color, str) or not color.startswith('#'):
                        color = '#000000'
                    try:
                        width = int(float(width))
                        if width < 1:
                            width = 1
                    except (ValueError, TypeError):
                        width = 5
                    scaled_points = []
                    for point in points:
                        try:
                            x = float(point.get('x', 0)) * img_width
                            y = float(point.get('y', 0)) * img_height
                            scaled_points.append((x, y))
                        except (ValueError, TypeError):
                            continue
                    if len(scaled_points) < 2:
                        continue
                    try:
                        rgb = tuple(int(color.lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
                    except ValueError:
                        rgb = (0, 0, 0)
                    draw.line(scaled_points, fill=rgb, width=width, joint='curve')
                img.save(img_path, quality=95, optimize=True)
            thumbnail_filename = f'thumb_{os.path.basename(attachment.file_path)}'
            thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename)
            create_thumbnail(img_path, thumbnail_path)
            attachment.thumbnail_path = f'images/{thumbnail_filename}'
            db.session.commit()
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

@app.cli.command("ensure-schema")
def ensure_schema_command():
    """Checks and ensures the 'page_num' column exists in the 'defect_markers' table."""
    with app.app_context():
        with db.engine.connect() as connection:
            try:
                print("Checking for 'page_num' column in 'defect_markers' table...")
                result = connection.execute(db.text("PRAGMA table_info(defect_markers);"))
                columns = [row[1] for row in result] # column name is at index 1

                if 'defect_markers' not in inspect(db.engine).get_table_names():
                    print("Error: 'defect_markers' table does not exist. Please run init_db or ensure migrations are applied first.")
                    return

                if 'page_num' not in columns:
                    print("'page_num' column not found in 'defect_markers'. Adding column...")
                    connection.execute(db.text("ALTER TABLE defect_markers ADD COLUMN page_num INTEGER NOT NULL DEFAULT 1;"))
                    connection.commit() # Important: commit DDL changes
                    print("'page_num' column added to 'defect_markers' table successfully.")
                else:
                    print("'page_num' column already exists in 'defect_markers' table.")
            except Exception as e:
                print(f"Error during schema check/update: {str(e)}")
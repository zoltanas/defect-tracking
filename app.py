from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_bcrypt import Bcrypt
from threading import Lock
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import shutil
from PIL import Image as PILImage, ImageDraw, ImageOps
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Drawing as ReportLabDrawing, Rect
from reportlab.lib import colors
from reportlab.graphics import renderPDF
import io
from pdf2image import convert_from_path
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
logger.setLevel(logging.INFO) # Restored to INFO
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
    defect = db.relationship('Defect', back_populates='markers')
    drawing = db.relationship('Drawing', back_populates='markers')

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    defect_id = db.Column(db.Integer, db.ForeignKey('defects.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
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
    thumbnail_path = db.Column(db.String(255))
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

def create_thumbnail(image_path, thumbnail_path, size=(300, 300)):
    try:
        with PILImage.open(image_path) as img:
            img = ImageOps.exif_transpose(img) # Apply EXIF orientation
            img.thumbnail(size, PILImage.Resampling.LANCZOS)
            img.save(thumbnail_path, quality=85, optimize=True)
            os.chmod(thumbnail_path, 0o644)
        logger.debug(f'Created thumbnail: {thumbnail_path}')
    except Exception as e:
        logger.error(f'Thumbnail creation failed for {image_path}: {str(e)}')
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
                if file and allowed_file(file.filename):
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    filename = secure_filename(f'defect_{defect.id}_{timestamp}_{file.filename}')
                    file_path = os.path.join('images', filename)
                    full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    thumbnail_filename = f'thumb_{filename}'
                    thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename)
                    try:
                        img = PILImage.open(file)
                        img = ImageOps.exif_transpose(img) # Apply EXIF orientation
                        img = img.convert('RGB')
                        img.save(full_path, quality=85, optimize=True)
                        os.chmod(full_path, 0o644)
                        create_thumbnail(full_path, thumbnail_path)
                        attachment = Attachment(
                            defect_id=defect.id,
                            file_path=file_path,
                            thumbnail_path=f'images/{thumbnail_filename}'
                        )
                        db.session.add(attachment)
                        db.session.commit()
                        attachment_ids.append(attachment.id)
                    except Exception as e:
                        logger.error(f'Error processing file {file.filename}: {str(e)}')
                        flash(f'Error uploading file {file.filename}.', 'error')
                        continue
        if attachment_ids:
            return redirect(url_for('draw', attachment_id=attachment_ids[0], next=url_for('defect_detail', defect_id=defect.id)))
        flash('Defect created successfully!', 'success')
        return redirect(url_for('defect_detail', defect_id=defect.id))
    return render_template('add_defect.html', project=project, drawings=drawings_data, user_role=access.role, csrf_token_value=generate_csrf())

@app.route('/defect/<int:defect_id>', methods=['GET', 'POST'])
@login_required
def defect_detail(defect_id):
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
                    if 'photos' in request.files:
                        files = request.files.getlist('photos')
                        for file in files:
                            if file and allowed_file(file.filename):
                                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                                # Ensure comment.id is available
                                filename = secure_filename(f'comment_{comment.id}_{timestamp}_{file.filename}')
                                file_path_for_db = os.path.join('images', filename) # Relative path for DB
                                full_disk_path = os.path.join(app.config['UPLOAD_FOLDER'], filename) # Full path for saving
                                thumbnail_filename = f'thumb_{filename}'
                                thumbnail_disk_path = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename) # Full path for saving thumb
                                thumbnail_path_for_db = os.path.join('images', thumbnail_filename) # Relative path for DB

                                try:
                                    img = PILImage.open(file)
                                    img = ImageOps.exif_transpose(img) # Apply EXIF orientation
                                    img = img.convert('RGB')
                                    img.save(full_disk_path, quality=85, optimize=True)
                                    os.chmod(full_disk_path, 0o644)
                                    create_thumbnail(full_disk_path, thumbnail_disk_path)
                                    
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
                                existing_marker = DefectMarker.query.filter_by(defect_id=defect_id).first()
                                if existing_marker:
                                    existing_marker.drawing_id = drawing_id_val
                                    existing_marker.x = marker_x_val
                                    existing_marker.y = marker_y_val
                                    # existing_marker.page_num = page_num
                                    logger.info(f"Updated marker for defect {defect_id}")
                                else:
                                    new_marker = DefectMarker(defect_id=defect_id, drawing_id=drawing_id_val, x=marker_x_val, y=marker_y_val) #, page_num=page_num)
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

        # Fetch marker and drawing (already present from previous structure)
        marker = DefectMarker.query.filter_by(defect_id=defect_id).first()
        drawing = None # drawing object itself is not explicitly passed, marker_data contains path
        marker_data = None
        if marker:
            # Ensure drawing is loaded if marker exists, to get file_path
            # The original code already does Drawing.query.get(marker.drawing_id)
            # So, if marker.drawing is accessed, it should be loaded or an error would occur.
            # For safety, explicitly load if needed, though current structure seems okay.
            drawing_obj = db.session.get(Drawing, marker.drawing_id) # Use db.session.get for PK lookup
            if drawing_obj:
                marker_data = {
                    'drawing_id': marker.drawing_id,
                    'x': marker.x,
                    'y': marker.y,
                    'file_path': drawing_obj.file_path # Use path from the fetched drawing object
                    # 'page_num': getattr(marker, 'page_num', 1) # If page_num is implemented
                }
                logger.debug(f"Defect {defect_id} - Marker data for display: {marker_data}")
            else:
                logger.warning(f"Drawing with ID {marker.drawing_id} not found for marker on defect {defect_id}. Marker will not be displayed correctly.")
        else:
            logger.debug(f"No marker found for defect {defect_id}")

        logger.info(f"Rendering defect_detail for defect {defect_id} (GET request or after POST error without redirect)")
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
        return redirect(url_for('project_detail', project_id=project_id))
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
                        # Full disk path for saving the original file
                        disk_save_full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        thumbnail_filename = f'thumb_{filename}'
                        # Full disk path for saving the thumbnail
                        disk_save_thumbnail_full_path = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename)
                        # Path for storing thumbnail in DB (relative to static folder)
                        db_thumbnail_path = os.path.join('images', thumbnail_filename)

                        try:
                            logger.info(f"Processing file: {file.filename} for checklist item {item.id}")
                            img = PILImage.open(file) # Changed from file.stream
                            img = ImageOps.exif_transpose(img)
                            img = img.convert('RGB')

                            logger.info(f"Attempting to save original image to: {disk_save_full_path}")
                            img.save(disk_save_full_path, quality=85, optimize=True)
                            os.chmod(disk_save_full_path, 0o644)
                            logger.info(f"Successfully saved original image to: {disk_save_full_path}")

                            logger.info(f"Attempting to create thumbnail: {disk_save_thumbnail_full_path} from {disk_save_full_path}")
                            create_thumbnail(disk_save_full_path, disk_save_thumbnail_full_path)
                            logger.info(f"Successfully created thumbnail: {disk_save_thumbnail_full_path}")

                            logger.info(f"Creating attachment record with db_file_path: {db_file_path}, db_thumbnail_path: {db_thumbnail_path}")
                            attachment = Attachment(
                                checklist_item_id=item.id,
                                file_path=db_file_path, # Use db specific path
                                thumbnail_path=db_thumbnail_path # Use db specific thumbnail path
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
    return redirect(url_for('project_detail', project_id=project_id))

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

@app.route('/project/<int:project_id>/report')
@login_required # Restored decorator
def generate_report(project_id): # Restored original signature
    filter_status = request.args.get('filter', 'All') # Use request.args for filter_status
    logger.info(f"Generating report with filter_status: {filter_status}")
    logger.info(f"Generating PDF report for project ID: {project_id} with filter: {filter_status}")

    # Original project fetching logic restored
    project = db.session.get(Project, project_id)
    if not project:
        flash('Project not found.', 'error')
        return redirect(url_for('index'))
    access = ProjectAccess.query.filter_by(user_id=current_user.id, project_id=project_id).first()
    if not access:
        flash('You do not have access to this project.', 'error')
        return redirect(url_for('index'))

    # Fetch defects with creator eagerly loaded
    defects_query = Defect.query.options(db.joinedload(Defect.creator)).filter_by(project_id=project_id)
    if filter_status == 'Open':
        # Sort open defects by creation date ascending
        defects_db = defects_query.filter_by(status='open').order_by(Defect.creation_date.asc()).all()
    elif filter_status == 'Closed':
        # Sort closed defects by close date descending, then creation date ascending
        defects_db = defects_query.filter_by(status='closed').order_by(Defect.close_date.desc(), Defect.creation_date.asc()).all()
    else: # All
        # Fetch all, then sort in Python to group open first (by creation asc), then closed (by close date desc)
        all_defects_db = defects_query.order_by(Defect.creation_date.asc()).all()
        defects_db = sorted([d for d in all_defects_db if d.status == 'open'], key=lambda d: d.creation_date if d.creation_date else datetime.min) + \
                     sorted([d for d in all_defects_db if d.status == 'closed'],
                            key=lambda d: (d.close_date if d.close_date else datetime.min, d.creation_date if d.creation_date else datetime.min), reverse=True)

    if defects_db:
        logger.info(f"Fetched {len(defects_db)} defects from DB. Sample: {[(d.id, d.status) for d in defects_db[:3]]}")
    else:
        logger.info(f"Fetched {len(defects_db)} defects from DB.")

    checklists_db = Checklist.query.filter_by(project_id=project_id).order_by(Checklist.name.asc()).all()
    checklist_items_to_report = []
    for checklist_obj in checklists_db: # Renamed variable
        # Sort checklist items by their text/ID for consistent order within a checklist
        items_db = ChecklistItem.query.filter_by(checklist_id=checklist_obj.id).order_by(ChecklistItem.id.asc()).all()
        for item_obj in items_db: # Renamed variable
            item_status_val = 'closed' if item_obj.is_checked else 'open'
            if filter_status == 'Open' and item_status_val != 'open':
                continue
            elif filter_status == 'Closed' and item_status_val != 'closed':
                continue
            # Ensure checklist_obj has creation_date for sorting later if needed
            if not hasattr(checklist_obj, 'creation_date') or not checklist_obj.creation_date:
                 logger.warning(f"Checklist {checklist_obj.name} (ID: {checklist_obj.id}) missing creation_date, using fallback for report sorting.")
                 # Provide a fallback if necessary, though Checklist model has default=datetime.now
                 # checklist_obj.creation_date = datetime.min # Or some other default
            checklist_items_to_report.append((checklist_obj, item_obj, item_status_val))

    if not defects_db and not checklist_items_to_report: # Use fetched defect list
        flash('No defects or checklist items found to generate a report.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))

    open_items_for_report = []
    closed_items_for_report = []

    # Process Defects from defects_db
    for defect_item_obj in defects_db: # Renamed variable
        # Eagerly load contractor comments with their users and attachments
        contractor_comments_list_db = Comment.query.options(
            db.joinedload(Comment.user), # Eager load the User who made the comment
            db.joinedload(Comment.attachments) # Eager load attachments for that comment
        ).filter(
            Comment.defect_id == defect_item_obj.id,
            User.role == 'contractor' # Filter by User role
        ).join(User).order_by(Comment.created_at.asc()).all() # Join User table to filter by role

        if defect_item_obj.status == 'open':
            open_items_for_report.append(('defect', defect_item_obj, contractor_comments_list_db))
        else: # closed
            closed_items_for_report.append(('defect', defect_item_obj, contractor_comments_list_db))

    # Process Checklist Items from checklist_items_to_report
    for checklist_obj, item_obj, item_status_val in checklist_items_to_report:
        # Checklist items don't have contractor comments in the same way defects do for the report
        # The last element of the tuple is a placeholder for contractor_comments_list
        if item_status_val == 'open':
            open_items_for_report.append(('checklist_item', checklist_obj, item_obj, []))
        else: # closed
            closed_items_for_report.append(('checklist_item', checklist_obj, item_obj, []))

    # Define sort keys
    # Sort order: Defect (0) then ChecklistItem (1)
    # Then by date (creation for open, close_date then creation for closed)
    def sort_key_open_items(item_tuple):
        item_type_sort_order = 0 if item_tuple[0] == 'defect' else 1
        date_val = datetime.min
        if item_tuple[0] == 'defect': # Defect object is item_tuple[1]
            date_val = item_tuple[1].creation_date if item_tuple[1].creation_date else datetime.min
        elif item_tuple[0] == 'checklist_item': # Checklist object is item_tuple[1]
            # Checklist Items use their parent Checklist's creation_date for sorting purposes here.
            date_val = item_tuple[1].creation_date if hasattr(item_tuple[1], 'creation_date') and item_tuple[1].creation_date else datetime.min
        return (item_type_sort_order, date_val)

    def sort_key_closed_items(item_tuple):
        item_type_sort_order = 0 if item_tuple[0] == 'defect' else 1
        primary_date_val = datetime.min # For defects: close_date (newest first, so use as is for sort then reverse)
                                       # For checklist items: checklist creation_date
        secondary_date_val = datetime.min # For defects: creation_date (oldest first if close_dates match)

        if item_tuple[0] == 'defect': # Defect object is item_tuple[1]
            primary_date_val = item_tuple[1].close_date if item_tuple[1].close_date else datetime.min # Newest closed date first
            secondary_date_val = item_tuple[1].creation_date if item_tuple[1].creation_date else datetime.min
            return (item_type_sort_order, primary_date_val, secondary_date_val) # Sort by close_date (primary), then creation_date (secondary)
        elif item_tuple[0] == 'checklist_item': # Checklist object is item_tuple[1]
            # For checklist items, "closing" is analogous to checking them off.
            # We don't have a specific "close_date" for items.
            # Sorting them by their checklist's creation date is a reasonable default.
            # If a specific "checked_date" were available on ChecklistItem, it could be used.
            primary_date_val = item_tuple[1].creation_date if hasattr(item_tuple[1], 'creation_date') and item_tuple[1].creation_date else datetime.min
            return (item_type_sort_order, primary_date_val)


    # Sort the lists
    open_items_for_report.sort(key=sort_key_open_items)
    # For closed items, sort by primary_date_val (close_date for defects) descending (newest first),
    # then by secondary_date_val (creation_date for defects) ascending (oldest first for tie-break).
    # Checklist items will be sorted by their checklist's creation date.
    closed_items_for_report.sort(key=lambda x: (
        sort_key_closed_items(x)[0], # item type
        sort_key_closed_items(x)[1] if x[0] == 'defect' else (datetime.max - sort_key_closed_items(x)[1].replace(tzinfo=None) if sort_key_closed_items(x)[1] else datetime.min), # close_date desc for defects, checklist creation asc
        sort_key_closed_items(x)[2] if x[0] == 'defect' else datetime.min # creation_date asc for defects
    ), reverse=True if any(item[0] == 'defect' for item in closed_items_for_report) else False)

    logger.info(f"Number of 'defect' type items in open_items_for_report: {sum(1 for item in open_items_for_report if item[0] == 'defect')}")
    logger.info(f"Number of 'defect' type items in closed_items_for_report: {sum(1 for item in closed_items_for_report if item[0] == 'defect')}")

    logger.info(f"Found {len(open_items_for_report)} open items and {len(closed_items_for_report)} closed items for the report.")

    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter # page width and height
    left_margin = 50
    right_margin = width - 50
    center_x = width / 2
    column_width = (width - left_margin - (width - right_margin)) / 2

    # Define standard padding/spacing values
    PADDING_SM = 5    # Small padding
    PADDING_MD = 10   # Medium padding
    PADDING_LG = 15   # Large padding
    LINE_HEIGHT_STD = 15 # Standard line height for body text (e.g., description)
    LINE_HEIGHT_SM = 12  # Smaller line height for metadata (status, creator, dates, labels)
    IMAGE_MAX_HEIGHT = 150 # Max height for displayed images
    SPACE_AFTER_IMAGE = PADDING_MD # Space after an image
    PLACEHOLDER_TEXT_HEIGHT = LINE_HEIGHT_STD # Assumed height for "[Image not available...]"

    def draw_text_wrapped(c, text, x, y, max_width, line_height=LINE_HEIGHT_STD, font='Helvetica', font_size=12):
        if text is None:
            text = ""
        c.setFont(font, font_size)
        words = text.split()
        lines = []
        current_line = []
        current_width = 0
        for word in words:
            word_width = c.stringWidth(word + ' ', font, font_size)
            if current_width + word_width <= max_width:
                current_line.append(word)
                current_width += word_width
            else:
                lines.append(' '.join(current_line))
                current_line = [word]
                current_width = word_width
        if current_line:
            lines.append(' '.join(current_line))
        for line_text in lines: # Renamed loop variable
            c.drawString(x, y, line_text)
            y -= line_height
        return y, len(lines) * line_height

    def add_image_to_pdf(c, img_path, x, y, max_width, max_height):
        logger.debug(f"Attempting to add image to PDF: {img_path}")
        temp_img_path = None # Initialize to prevent UnboundLocalError
        try:
            img = PILImage.open(img_path)
            if img.mode in ('RGBA', 'LA') or (img.mode == 'P' and 'transparency' in img.info):
                background = PILImage.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3] if img.mode == 'RGBA' else None)
                img = background
            else:
                img = img.convert('RGB')
            temp_img_path = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_img_{os.urandom(8).hex()}.jpg')
            img.save(temp_img_path, 'JPEG')
            img_width_pil, img_height_pil = img.size
            aspect_ratio = img_width_pil / img_height_pil

            img_width_draw_final = max_width # Use a new variable for final drawing dimensions
            img_height_draw_final = img_width_draw_final / aspect_ratio

            if img_height_draw_final > max_height:
                img_height_draw_final = max_height
                img_width_draw_final = img_height_draw_final * aspect_ratio

            img_reader = ImageReader(temp_img_path) # This can also fail
            c.drawImage(img_reader, x, y - img_height_draw_final, width=img_width_draw_final, height=img_height_draw_final)
            actual_drawn_height = img_height_draw_final
            logger.debug(f"Successfully added image {img_path} to PDF. Drawn size: {img_width_draw_final}x{img_height_draw_final}")

        except FileNotFoundError:
            logger.error(f"Image file not found: {img_path}", exc_info=True)
            placeholder_text = f"[Image not available: {os.path.basename(img_path)} (File Not Found)]"
            c.setFillColorRGB(0.5, 0.5, 0.5) # Grey text for placeholder
            c.drawString(x, y - 12, placeholder_text)
            c.setFillColorRGB(0, 0, 0) # Reset to black
            actual_drawn_height = 15 # Height of the placeholder text line
            logger.debug(f"Drawing placeholder for missing image: {img_path}")
        except (PILImage.UnidentifiedImageError, ValueError) as pil_e: # Catch PIL specific errors and general ValueErrors from PIL
            logger.error(f"PIL Error processing image {img_path}: {pil_e}", exc_info=True)
            placeholder_text = f"[Image not available: {os.path.basename(img_path)} (Format Error)]"
            c.setFillColorRGB(0.5, 0.5, 0.5)
            c.drawString(x, y - 12, placeholder_text)
            c.setFillColorRGB(0, 0, 0)
            actual_drawn_height = 15
            logger.debug(f"Drawing placeholder for unidentifiable image: {img_path}")
        except Exception as e: # Catch other errors (e.g., from ReportLab ImageReader or drawImage)
            logger.error(f"General failure to add image {img_path} to PDF: {e}", exc_info=True)
            placeholder_text = f"[Image not available: {os.path.basename(img_path)} (Load Error)]"
            c.setFillColorRGB(0.5, 0.5, 0.5)
            c.drawString(x, y - 12, placeholder_text)
            c.setFillColorRGB(0, 0, 0)
            actual_drawn_height = 15
            logger.debug(f"Drawing placeholder due to general image load error: {img_path}")
        finally:
            if temp_img_path and os.path.exists(temp_img_path):
                try:
                    os.remove(temp_img_path)
                    logger.debug(f"Successfully removed temporary image file: {temp_img_path}")
                except Exception as e_remove:
                    logger.error(f"Failed to remove temporary image file {temp_img_path}: {e_remove}")
            # Return the y-position after drawing the image/placeholder and the actual height used.
            return y - actual_drawn_height - 10, actual_drawn_height

    def draw_rounded_rect(c, x, y, width, height, radius=10):
        drawing = ReportLabDrawing()
        fill_color = colors.Color(*colors.lightgrey.rgb(), alpha=0.2)
        rect = Rect(0, 0, width, height, strokeColor=colors.darkgrey, fillColor=fill_color, strokeWidth=1)
        rect.rx = radius
        rect.ry = radius
        drawing.add(rect)
        c.saveState()
        c.translate(x, y - height)
        renderPDF.draw(drawing, c, 0, 0)
        c.restoreState()

    def estimate_space_needed(entry, is_left=True):
        # This function estimates the vertical space needed for an entry in the PDF.
        # It should mirror the drawing logic of add_defect_to_pdf as closely as possible.
        max_width_est = column_width - 20 if is_left else (width - center_x - 30)
        padding_est = 10
        font_size_desc_est = 12
        font_size_comment_est = 10
        font_size_label_est = 9
        line_height_regular_est = 15 # For description, standard text
        line_height_small_est = 12   # For status, creator, item comments, date lines
        image_height_cap_est = 150
        placeholder_height_est = 15 + 10 # Placeholder text + spacing
        label_height_est = 12 + 5 # Label for images/attachments + spacing

        total_y_needed = 0

        # Data extraction from entry (defect or checklist_item)
        entry_type = entry[0]
        description_text = ""
        item_internal_comments = "" # Checklist item's own comments
        marker_data_obj = None
        attachments_list = []
        contractor_reply_list = []

        # Heights for Status/Creator lines (fixed)
        if is_left:
            if entry_type == 'defect':
                total_y_needed += (line_height_small_est * 2) # Status & Creator
                defect_obj_est = entry[1]
                description_text = defect_obj_est.description or ""
                marker_data_obj = DefectMarker.query.filter_by(defect_id=defect_obj_est.id).first() if isinstance(defect_obj_est, Defect) else (defect_obj_est.markers[0] if hasattr(defect_obj_est, 'markers') and defect_obj_est.markers else None)
                attachments_list = Attachment.query.filter_by(defect_id=defect_obj_est.id, checklist_item_id=None, comment_id=None).all() if isinstance(defect_obj_est, Defect) else (defect_obj_est.attachments if hasattr(defect_obj_est, 'attachments') else [])
                contractor_reply_list = entry[2] # This is for the right column, but needed for context if is_left is false
            elif entry_type == 'checklist_item':
                total_y_needed += line_height_small_est # Status
                _, item_obj_est = entry[1], entry[2]
                description_text = item_obj_est.item_text or ""
                item_internal_comments = item_obj_est.comments or ""
                attachments_list = Attachment.query.filter_by(checklist_item_id=item_obj_est.id).all() if isinstance(item_obj_est, ChecklistItem) else (item_obj_est.attachments if hasattr(item_obj_est, 'attachments') else [])

            total_y_needed += padding_est # Top padding inside rect

            # Description height
            _, desc_lines = draw_text_wrapped(c, description_text, 0, 0, max_width_est, line_height=line_height_regular_est, font_size=font_size_desc_est)
            description_block_height = desc_lines * line_height_regular_est
            if desc_lines > 0:
                description_block_height += 7.5 # Add spacing only if there's a description
            total_y_needed += description_block_height

            # Checklist Item's own comments height
            if item_internal_comments:
                total_y_needed += label_height_est # "Comments:" label
                _, item_comment_lines = draw_text_wrapped(c, item_internal_comments, 0, 0, max_width_est, line_height=line_height_small_est, font_size=font_size_comment_est)
                total_y_needed += item_comment_lines * line_height_small_est + padding_est # Spacing after item comments

            # Image/Marker Estimation
            marked_drawing_shown_est = False
            if entry_type == 'defect' and marker_data_obj and marker_data_obj.drawing and marker_data_obj.drawing.file_path:
                drawing_basename_est = os.path.basename(marker_data_obj.drawing.file_path)
                drawing_full_path_est = os.path.join(app.config['DRAWING_FOLDER'], drawing_basename_est)
                if os.path.exists(drawing_full_path_est):
                    total_y_needed += label_height_est # "Marked Drawing View/Image:"
                    if drawing_full_path_est.lower().endswith('.pdf'):
                        total_y_needed += image_height_cap_est + 10 # Assumed height for converted PDF
                    else: # Image marker
                        try:
                            img = PILImage.open(drawing_full_path_est)
                            img_w, img_h = img.size
                            est_h = min(img_h, image_height_cap_est) * (max_width_est / img_w) if img_w > 0 else min(img_h, image_height_cap_est)
                            total_y_needed += min(est_h, image_height_cap_est) + 10
                        except: total_y_needed += placeholder_height_est
                    marked_drawing_shown_est = True
                # If marked drawing file doesn't exist, we just fall through to regular attachments.

            if not marked_drawing_shown_est and attachments_list:
                total_y_needed += label_height_est # "Attached Images:" or "Attachments:"
                for att in attachments_list:
                    if att.file_path:
                        att_basename_est = os.path.basename(att.file_path)
                        att_full_path_est = os.path.join(app.config['UPLOAD_FOLDER'], att_basename_est)
                        if os.path.exists(att_full_path_est):
                            try:
                                img = PILImage.open(att_full_path_est)
                                img_w, img_h = img.size
                                est_h = min(img_h, image_height_cap_est) * (max_width_est / img_w) if img_w > 0 else min(img_h, image_height_cap_est)
                                total_y_needed += min(est_h, image_height_cap_est) + 10
                            except: total_y_needed += placeholder_height_est
                        else: total_y_needed += placeholder_height_est # File not found
                    else: total_y_needed += placeholder_height_est # No path

            # Date lines at the bottom of the content block
            total_y_needed += line_height_small_est # Creation Date
            if entry_type == 'defect' and (entry[1].close_date if isinstance(entry[1], Defect) else getattr(entry[1], 'close_date', None)): # Check actual close_date
                total_y_needed += line_height_small_est # Close Date

            total_y_needed += padding_est # Bottom padding inside rect
            total_y_needed += line_height_regular_est # Spacing below the entire rect for this item
            return total_y_needed

        else: # is_left is False (Contractor Comments for a defect)
            if entry_type == 'defect' and contractor_reply_list:
                total_y_needed = 15 # "Contractor Replies:" title height
                for comment_obj_est in contractor_reply_list:
                    comment_rect_h_est = padding_est * 2 # Top/bottom padding for this comment's rect
                    comment_rect_h_est += (line_height_small_est + 7.5) # "By: username" + spacing

                    content_est = comment_obj_est.content or ""
                    _, content_lines = draw_text_wrapped(c, content_est, 0, 0, max_width_est, line_height=line_height_small_est, font_size=font_size_comment_est)
                    comment_rect_h_est += content_lines * line_height_small_est + 7.5

                    comment_attachments_est = comment_obj_est.attachments if hasattr(comment_obj_est, 'attachments') else []
                    if comment_attachments_est:
                        # No separate label for comment attachments, they just appear.
                        for att in comment_attachments_est:
                            if att.file_path:
                                att_basename_est = os.path.basename(att.file_path)
                                att_full_path_est = os.path.join(app.config['UPLOAD_FOLDER'], att_basename_est)
                                if os.path.exists(att_full_path_est):
                                    try:
                                        img = PILImage.open(att_full_path_est)
                                        img_w, img_h = img.size
                                        est_h = min(img_h, image_height_cap_est) * (max_width_est / img_w) if img_w > 0 else min(img_h, image_height_cap_est)
                                        comment_rect_h_est += min(est_h, image_height_cap_est) + 10
                                    except: comment_rect_h_est += placeholder_height_est
                                else: comment_rect_h_est += placeholder_height_est
                            else: comment_rect_h_est += placeholder_height_est

                    comment_rect_h_est += line_height_small_est + 7.5 # Comment date line + spacing
                    total_y_needed += comment_rect_h_est + 10 # Add this comment block's height + spacing after it
                return total_y_needed
            return 0 # No contractor comments or not a defect

    # Fully revised add_defect_to_pdf function (from previous turn's report)
    def add_defect_to_pdf(entry, is_left=True, y_position=None, defect_number=1):
        nonlocal c
        x_position = left_margin if is_left else center_x + PADDING_MD
        max_width_content = column_width - (2 * PADDING_SM) if is_left else (width - center_x - PADDING_MD - PADDING_SM)
        # padding refers to internal padding for rounded_rects
        rect_internal_padding = PADDING_MD


        attachments_to_draw = []
        entry_type_for_log = entry[0]
        id_for_log = None
        defect_obj = None
        item_obj = None
        checklist_obj_for_item = None
        description_content = "" # Renamed from description_draw
        creation_date_content = datetime.now()  # Renamed from creation_date_draw
        close_date_content = None # Renamed from close_date_draw
        item_comments_content = ""  # Renamed from comments_text_field_draw (for checklist item's own comments)
        defect_contractor_comments = [] # Renamed from contractor_comments_list
        marker_obj_data = None # Renamed from marker_obj
        creator_username_content = "N/A" # Renamed from creator_username_draw
        item_status_content = "N/A" # Renamed from item_status_draw

        if entry[0] == 'defect':
            defect_obj = entry[1]
            id_for_log = defect_obj.id
            description_content = defect_obj.description or ""
            creation_date_content = defect_obj.creation_date
            close_date_content = defect_obj.close_date
            defect_contractor_comments = entry[2]
            if defect_obj.creator:
                creator_username_content = defect_obj.creator.username
            else: # Fallback if creator not eagerly loaded
                fetched_creator = db.session.get(User, defect_obj.creator_id) if defect_obj.creator_id else None
                if fetched_creator:
                    creator_username_content = fetched_creator.username

            logger.info(f"add_defect_to_pdf: Processing Defect ID {defect_obj.id}, Desc: '{description_content[:30] if description_content else 'Empty Description'}...', Status: {defect_obj.status}, Creator: {creator_username_content}")

            if isinstance(defect_obj, Defect):
                marker_obj_data = DefectMarker.query.filter_by(defect_id=defect_obj.id).first()
                attachments_to_draw = Attachment.query.filter_by(defect_id=defect_obj.id, checklist_item_id=None, comment_id=None).all()
            else: # Mock object case
                marker_obj_data = defect_obj.markers[0] if hasattr(defect_obj, 'markers') and defect_obj.markers else None
                attachments_to_draw = defect_obj.attachments if hasattr(defect_obj, 'attachments') else []

        elif entry[0] == 'checklist_item':
            checklist_obj_for_item, item_obj = entry[1], entry[2]
            id_for_log = item_obj.id
            item_text = item_obj.item_text or ""
            # The title will indicate it's a checklist item, so description can be just the text.
            description_content = f"{item_text}"
            creation_date_content = checklist_obj_for_item.creation_date if hasattr(checklist_obj_for_item, 'creation_date') else datetime.now()
            item_comments_content = item_obj.comments if hasattr(item_obj, 'comments') else ""
            item_status_content = "Closed" if item_obj.is_checked else "Open"
            logger.info(f"Processing PDF: Type=Checklist Item, ID={id_for_log}, Checklist='{checklist_obj_for_item.name}', Status='{item_status_content}', Desc='{description_content[:30]}...'")

            if isinstance(item_obj, ChecklistItem):
                attachments_to_draw = Attachment.query.filter_by(checklist_item_id=item_obj.id).all()
            else: # Mock object case
                attachments_to_draw = item_obj.attachments if hasattr(item_obj, 'attachments') else []
        else:
            logger.error(f"Unknown entry type: {entry[0]} in add_defect_to_pdf")
            return y_position

        if is_left:
            logger.info(f"add_defect_to_pdf (left col): Defect ID {id_for_log}, initial y_position: {y_position}")
            c.setFont('Helvetica-Bold', 12)
            # Title changes for checklist items
            title_text_display = ""
            if entry[0] == 'defect':
                title_text_display = f'Defect {defect_number}:'
            elif entry[0] == 'checklist_item':
                title_text_display = f'Item {defect_number} (Checklist: {checklist_obj_for_item.name}):'
            c.drawString(x_position, y_position, title_text_display)
            y_position -= PADDING_LG # Space after main title

            rect_content_top_y = y_position # Y where the top border of the rounded rect will be
            
            current_draw_y = rect_content_top_y - rect_internal_padding # Starting Y for content INSIDE the rect
            logger.debug(f"Defect ID {id_for_log}, current_draw_y before status: {current_draw_y}")
            # Draw Status, Creator (for defects) / Status (for checklist items)
            c.setFont('Helvetica', 10) # Font size for these metadata lines
            if entry[0] == 'defect':
                defect_status_display = defect_obj.status.capitalize() if hasattr(defect_obj, 'status') else "N/A"
                c.drawString(x_position + rect_internal_padding, current_draw_y, f'Status: {defect_status_display}')
                current_draw_y -= LINE_HEIGHT_SM
                c.drawString(x_position + rect_internal_padding, current_draw_y, f'Creator: {creator_username_content}')
                current_draw_y -= LINE_HEIGHT_SM
            elif entry[0] == 'checklist_item':
                c.drawString(x_position + rect_internal_padding, current_draw_y, f'Status: {item_status_content}')
                current_draw_y -= LINE_HEIGHT_SM

            # Now estimate space *after* these initial lines are accounted for.
            # The estimate_space_needed function should ideally account for these fixed lines.
            # For now, we draw them, then the description, then other variable content.
            # The rounded rectangle's height will be based on estimate_space_needed.

            # Recalculate rect_content_top_y to be the actual top of the rectangle based on content that *precedes* description
            # The `current_draw_y` is now correctly positioned for the description.
            # The `rect_content_top_y` should be `y_position` (which is after title).
            # The estimated_rect_height needs to encompass all content starting from Status/Creator.

            estimated_rect_height = estimate_space_needed(entry, is_left=True)
            draw_rounded_rect(c, x_position, rect_content_top_y, column_width - PADDING_SM, estimated_rect_height, radius=PADDING_MD)

            current_draw_y -= PADDING_SM # Space before main description text
            logger.debug(f"Defect ID {id_for_log}, current_draw_y before description: {current_draw_y}")
            c.setFont('Helvetica', 12)
            # Modify description_content if it's empty or None
            drawable_description = description_content if description_content else "[No description]"
            y_after_desc, _ = draw_text_wrapped(c, drawable_description, x_position + rect_internal_padding, current_draw_y, max_width_content, line_height=LINE_HEIGHT_STD)
            current_draw_y = y_after_desc

            if item_comments_content: # For checklist item's own comments (not contractor replies)
                current_draw_y -= PADDING_MD # Space before "Comments:" label
                c.setFont('Helvetica-Oblique', 10)
                c.drawString(x_position + rect_internal_padding, current_draw_y, "Comments:")
                current_draw_y -= LINE_HEIGHT_SM # Move down past label

                c.setFont('Helvetica', 10)
                y_after_item_comments, _ = draw_text_wrapped(c, item_comments_content, x_position + rect_internal_padding, current_draw_y, max_width_content, line_height=LINE_HEIGHT_SM, font_size=10)
                current_draw_y = y_after_item_comments

            logger.debug(f"Defect ID {id_for_log}, current_draw_y before attachments/markers: {current_draw_y}")
            y_position_before_image_processing = current_draw_y # Save Y before images/markers start
            marked_drawing_processed_successfully = False
            process_regular_attachments = True # Assume we'll process regular attachments unless a marked drawing is successful

            if entry[0] == 'defect' and marker_obj_data and marker_obj_data.drawing and marker_obj_data.drawing.file_path:
                # Construct full path for the drawing file
                drawing_basename = os.path.basename(marker_obj_data.drawing.file_path)
                drawing_full_path = os.path.join(app.config['DRAWING_FOLDER'], drawing_basename)
                logger.info(f"Defect {id_for_log} has a marker. Drawing path: {drawing_full_path} (Original: {marker_obj_data.drawing.file_path})")

                if not os.path.exists(drawing_full_path):
                    logger.error(f"Marked drawing file NOT FOUND: {drawing_full_path}")
                    # Fallback to regular attachments will occur as marked_drawing_processed_successfully remains False
                elif marker_obj_data.drawing.file_path.lower().endswith('.pdf'):
                    logger.info(f"Attempting to process marked PDF: {drawing_full_path}")
                    temp_marked_png_path = None # Path for the PNG image generated from PDF page + marker
                    try:
                        # Log poppler path (even if None, pdf2image handles it)
                        poppler_path_env = os.environ.get('POPPLER_PATH')
                        logger.debug(f"Using Poppler path from env (if any): {poppler_path_env}")

                        images_from_path = convert_from_path(drawing_full_path, first_page=1, last_page=1, poppler_path=poppler_path_env)
                        if images_from_path:
                            pil_image_from_pdf = images_from_path[0].convert('RGB')
                            draw_on_image = ImageDraw.Draw(pil_image_from_pdf)
                            img_w, img_h = pil_image_from_pdf.size

                            # Apply marker
                            abs_marker_x = marker_obj_data.x * img_w
                            abs_marker_y = marker_obj_data.y * img_h
                            radius = max(5, int(min(img_w, img_h) * 0.02)) # Dynamic radius
                            draw_on_image.ellipse(
                                (abs_marker_x - radius, abs_marker_y - radius, abs_marker_x + radius, abs_marker_y + radius),
                                fill='red', outline='red'
                            )

                            temp_marked_png_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_marked_{id_for_log}_{os.urandom(4).hex()}.png")
                            pil_image_from_pdf.save(temp_marked_png_path, 'PNG')
                            logger.info(f"Saved marked PDF page as PNG: {temp_marked_png_path}")

                            current_draw_y -= PADDING_SM # Space before "Marked Drawing" label
                            c.setFont('Helvetica-Oblique', 9)
                            c.drawString(x_position + rect_internal_padding, current_draw_y, "Marked Drawing View:")
                            current_draw_y -= LINE_HEIGHT_SM # Move past label

                            current_draw_y, _ = add_image_to_pdf(c, temp_marked_png_path, x_position + rect_internal_padding, current_draw_y, max_width_content, IMAGE_MAX_HEIGHT)
                            marked_drawing_processed_successfully = True
                            process_regular_attachments = False
                        else:
                            logger.error(f"pdf2image conversion of {drawing_full_path} for defect {id_for_log} yielded no images.")
                    except Exception as e_pdf_process:
                        logger.error(f"Error processing marked PDF {drawing_full_path} for defect {id_for_log}: {e_pdf_process}", exc_info=True)
                    finally:
                        if temp_marked_png_path and os.path.exists(temp_marked_png_path):
                            try:
                                os.remove(temp_marked_png_path)
                                logger.debug(f"Cleaned up temporary marked PNG: {temp_marked_png_path}")
                            except Exception as e_remove_tmp_png:
                                logger.error(f"Failed to remove temp marked PNG {temp_marked_png_path}: {e_remove_tmp_png}")
                else: # Marker drawing is not a PDF (e.g., an image with a marker - currently not supported by this flow, but path exists)
                    logger.info(f"Marker drawing {drawing_full_path} for defect {id_for_log} is an image, not a PDF. Displaying this image as is (marker not dynamically drawn on it here).")
                    current_draw_y -= PADDING_SM # Space before label
                    c.setFont('Helvetica-Oblique', 9)
                    c.drawString(x_position + rect_internal_padding, current_draw_y, "Marked Drawing (Image):")
                    current_draw_y -= LINE_HEIGHT_SM # Move past label
                    current_draw_y, _ = add_image_to_pdf(c, drawing_full_path, x_position + rect_internal_padding, current_draw_y, max_width_content, IMAGE_MAX_HEIGHT)
                    marked_drawing_processed_successfully = True
                    process_regular_attachments = False
            else: # No marker, or marker drawing path is missing
                logger.debug(f"No marker or valid drawing path for defect {id_for_log}. Will proceed to regular attachments if any.")
                current_draw_y = y_position_before_image_processing # Ensure current_draw_y is reset if no marker processing attempted

            # Fallback or standard display of regular attachments
            if process_regular_attachments:
                if not marked_drawing_processed_successfully and entry[0] == 'defect': # Log only if it's a fallback for defects
                    logger.info(f"Falling back to regular attachments for defect {id_for_log} as marked drawing processing was not successful or applicable.")

                current_draw_y = y_position_before_image_processing # Reset Y to before any potential (failed) marked drawing attempt

                if attachments_to_draw:
                    current_draw_y -= PADDING_SM # Space before label
                    c.setFont('Helvetica-Oblique', 9)
                    label_text = "Attached Images:" if entry[0] == 'defect' else "Attachments:"
                    c.drawString(x_position + rect_internal_padding, current_draw_y, label_text)
                    current_draw_y -= LINE_HEIGHT_SM # Move past label

                    for attachment_item in attachments_to_draw:
                        if not attachment_item.file_path:
                            logger.warning(f"Attachment ID {getattr(attachment_item, 'id', 'N/A')} for {entry_type_for_log} {id_for_log} has a missing file path.")
                            # Draw placeholder for missing path directly or let add_image_to_pdf handle it if path was empty string
                            current_draw_y, _ = add_image_to_pdf(c, "", x_position + rect_internal_padding, current_draw_y, max_width_content, IMAGE_MAX_HEIGHT) # Pass empty path
                            continue

                        attachment_basename = os.path.basename(attachment_item.file_path)
                        attachment_full_path = os.path.join(app.config['UPLOAD_FOLDER'], attachment_basename)
                        # logger.info already in add_image_to_pdf if path is valid

                        current_draw_y, _ = add_image_to_pdf(c, attachment_full_path, x_position + rect_internal_padding, current_draw_y, max_width_content, IMAGE_MAX_HEIGHT)
                elif entry[0] == 'defect' and not marker_obj_data :
                     logger.debug(f"Defect {id_for_log} has no marked drawing and no regular attachments.")
                elif entry[0] == 'checklist_item' and not attachments_to_draw:
                     logger.debug(f"Checklist item {id_for_log} has no attachments.")
                     # current_draw_y remains y_position_before_image_processing


            final_content_y_in_rect = current_draw_y # This is y after all content *inside* the rect, before dates

            current_draw_y -= PADDING_MD # Space before date lines
            logger.debug(f"Defect ID {id_for_log}, current_draw_y before date lines: {current_draw_y}")
            date_y_position = current_draw_y
            c.setFont('Helvetica', 8) # Font size for dates
            if entry[0] == 'defect' and close_date_content:
                close_date_str = close_date_content.strftime("%Y-%m-%d %H:%M:%S") if isinstance(close_date_content, datetime) else "N/A"
                c.drawString(x_position + rect_internal_padding, date_y_position, f'Close Date: {close_date_str}')
                date_y_position -= LINE_HEIGHT_SM

            creation_date_str = creation_date_content.strftime("%Y-%m-%d %H:%M:%S") if isinstance(creation_date_content, datetime) else str(creation_date_content)
            c.drawString(x_position + rect_internal_padding, date_y_position, f'Creation Date: {creation_date_str}')
            # current_draw_y is now at the baseline of the last date line.
            # y_left is the Y coordinate for the bottom of the drawn rectangle border for the left column item.
            # This value is used by process_defects to position the next item.
            # It represents the line just below the rounded rectangle.
            # The new return value should be the y-coordinate that marks the bottom of all drawn content for the current item.
            y_left = current_draw_y - rect_internal_padding # current_draw_y is at baseline of last content

        else: # not is_left (right column, for defect contractor comments only)
            y_right = y_position # Default if no comments or not a defect
            if entry[0] == 'defect' and defect_contractor_comments:
                c.setFont('Helvetica-Bold', 12)
                contractor_reply_y_start = y_position
                c.drawString(x_position, contractor_reply_y_start, 'Contractor Replies:')
                contractor_reply_y_start -= PADDING_LG

                current_comment_block_y = contractor_reply_y_start

                for comment_obj in defect_contractor_comments:
                    # Calculate height for THIS comment block, mirroring estimate_space_needed's logic for a single comment block
                    # This ensures that the drawn rounded rectangle matches the estimated space.
                    single_comment_block_height = rect_internal_padding * 2 # Top & bottom internal padding
                    single_comment_block_height += (LINE_HEIGHT_SM + PADDING_SM) # "By: username" line + its bottom spacing

                    _, comment_content_lines = draw_text_wrapped(c, comment_obj.content or "", 0, 0, max_width_content, line_height=LINE_HEIGHT_SM, font_size=10)
                    single_comment_block_height += comment_content_lines * LINE_HEIGHT_SM + PADDING_SM # Content height + its bottom spacing

                    # Attachments for this specific comment
                    comment_attachments = comment_obj.attachments if hasattr(comment_obj, 'attachments') else []
                    if comment_attachments:
                        for att in comment_attachments:
                            # Note: add_image_to_pdf returns y_coord_after_image, actual_drawn_height
                            # Here, we use a simplified estimation consistent with estimate_space_needed
                            if att.file_path:
                                att_basename = os.path.basename(att.file_path)
                                att_full_path = os.path.join(app.config['UPLOAD_FOLDER'], att_basename)
                                if os.path.exists(att_full_path):
                                    try:
                                        # Try to get actual image dimensions for a slightly better estimate if possible
                                        img_temp = PILImage.open(att_full_path)
                                        img_w_temp, img_h_temp = img_temp.size
                                        est_h_temp = min(img_h_temp, IMAGE_MAX_HEIGHT) * (max_width_content / img_w_temp) if img_w_temp > 0 else min(img_h_temp, IMAGE_MAX_HEIGHT)
                                        single_comment_block_height += min(est_h_temp, IMAGE_MAX_HEIGHT) + SPACE_AFTER_IMAGE
                                    except:
                                        single_comment_block_height += PLACEHOLDER_TEXT_HEIGHT # Placeholder if image fails
                                else:
                                    single_comment_block_height += PLACEHOLDER_TEXT_HEIGHT # File not found
                            else:
                                single_comment_block_height += PLACEHOLDER_TEXT_HEIGHT # No path

                    single_comment_block_height += LINE_HEIGHT_SM + PADDING_SM # Date line + its bottom spacing

                    # Draw the rounded rect for this specific comment using the calculated height
                    draw_rounded_rect(c, x_position, current_comment_block_y, width - center_x - PADDING_MD - PADDING_SM, single_comment_block_height, radius=PADDING_MD)

                    # --- Drawing content inside this comment block ---
                    y_draw_in_comment_rect = current_comment_block_y - rect_internal_padding # Start Y inside rect

                    comment_creator_name = comment_obj.user.username if comment_obj.user else "Unknown User"
                    c.setFont('Helvetica-Bold', 9)
                    c.drawString(x_position + rect_internal_padding, y_draw_in_comment_rect, f'By: {comment_creator_name}')
                    y_draw_in_comment_rect -= (LINE_HEIGHT_SM + PADDING_SM)

                    c.setFont('Helvetica', 10)
                    y_after_comment_text, _ = draw_text_wrapped(c, comment_obj.content or "", x_position + rect_internal_padding, y_draw_in_comment_rect, max_width_content, line_height=LINE_HEIGHT_SM, font_size=10)
                    y_draw_in_comment_rect = y_after_comment_text

                    if comment_attachments:
                        for attachment_item in comment_attachments:
                            y_draw_in_comment_rect -= PADDING_SM # Space before image
                            attachment_full_path = os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment_item.file_path)) if attachment_item.file_path else ""
                            # Actual drawing of image, add_image_to_pdf handles its own spacing after image via return value
                            y_draw_in_comment_rect, _ = add_image_to_pdf(c, attachment_full_path, x_position + rect_internal_padding, y_draw_in_comment_rect, max_width_content, IMAGE_MAX_HEIGHT)

                    y_draw_in_comment_rect -= PADDING_SM # Space before date line
                    c.setFont('Helvetica', 8)
                    comment_date = comment_obj.created_at if hasattr(comment_obj, 'created_at') else datetime.now()
                    comment_date_str = comment_date.strftime("%Y-%m-%d %H:%M:%S") if isinstance(comment_date, datetime) else "N/A"
                    c.drawString(x_position + rect_internal_padding, y_draw_in_comment_rect, f'Date: {comment_date_str}')
                    # --- End of drawing content inside this comment block ---

                    current_comment_block_y = current_comment_block_y - single_comment_block_height - PADDING_MD # Space to next comment block

                y_right = current_comment_block_y
            elif entry[0] == 'checklist_item':
                 y_right = y_position # No contractor comments for checklist items

        return y_left if is_left else y_right

    c.setFont('Helvetica-Bold', 16)
    y_position = height - 50
    c.drawString(left_margin, y_position, f'Project: {project.name}')
    y_position -= 30

    def process_defects(items_list, title, y_position, initial_item_number=1):
        current_item_number = initial_item_number
        if items_list:
            c.setFont('Helvetica-Bold', 14)
            c.drawString(left_margin, y_position, f'{title}: {len(items_list)}')
            y_position -= 20

            for entry_data in items_list: # Renamed 'entry' to 'entry_data'
                entry_description_for_log = ""
                try:
                    # Determine entry description for logging based on type
                    if entry_data[0] == 'defect':
                        defect_id_log = entry_data[1].id
                        entry_description_for_log = f"Defect ID {defect_id_log}"
                    elif entry_data[0] == 'checklist_item':
                        checklist_name_log = entry_data[1].name
                        item_id_log = entry_data[2].id
                        entry_description_for_log = f"Checklist Item ID {item_id_log} from Checklist '{checklist_name_log}'"
                    else:
                        entry_description_for_log = "Unknown entry type"

                    logger.debug(f"process_defects: Estimating space for item: Type {entry_data[0]}, ID {(entry_data[1].id if entry_data[0] == 'defect' else entry_data[2].id if entry_data[0] == 'checklist_item' else 'N/A')}")
                    space_needed_left_col = estimate_space_needed(entry_data, is_left=True)
                    logger.info(f"process_defects: Estimated_rect_height (space_needed_left_col) for item Type {entry_data[0]}, ID {(entry_data[1].id if entry_data[0] == 'defect' else entry_data[2].id if entry_data[0] == 'checklist_item' else 'N/A')}: {space_needed_left_col}")
                    space_needed_right_col = 0 # Default for checklist items
                    if entry_data[0] == 'defect': # Contractor comments only for defects
                        space_needed_right_col = estimate_space_needed(entry_data, is_left=False)

                    required_space_for_item = max(space_needed_left_col, space_needed_right_col)

                    SPACE_BETWEEN_ITEMS = 20 # Define a clear constant for spacing
                    required_space_for_item_with_buffer = required_space_for_item + SPACE_BETWEEN_ITEMS

                    logger.debug(f"Page break check for item '{entry_description_for_log}': y_pos={y_position}, req_item_space={required_space_for_item}, req_with_buffer={required_space_for_item_with_buffer}, left_h_est={space_needed_left_col}, right_h_est={space_needed_right_col}, item_num_in_section={current_item_number - initial_item_number + 1}")

                    if y_position - required_space_for_item_with_buffer < 50: # Check if enough space for current item + buffer (50 is bottom margin)
                        logger.info(f"Performing page break before item '{entry_description_for_log}' (Space needed: {required_space_for_item_with_buffer}, Space available: {y_position - 50})")
                        c.showPage()
                        y_position = height - 50 # Reset y_position to top of new page
                        # Reset font after page break, if needed, though add_defect_to_pdf sets its own fonts.
                        c.setFont('Helvetica-Bold', 14) # Re-set title font for new page section if needed
                        c.drawString(left_margin, y_position, f'{title} (continued): {len(items_list) - (current_item_number - initial_item_number)}')
                        y_position -=20


                    # Add left column (defect/checklist item details)
                    # Pass current_item_number which is the sequential number for this report part
                    y_after_left_col = add_defect_to_pdf(entry_data, is_left=True, y_position=y_position, defect_number=current_item_number)

                    if entry_data[0] == 'defect': # Only draw right column for defects
                        # Contractor comments (right column) start at the same y_position as the defect's left column content
                        # The return value of add_defect_to_pdf for the right column (y_right) is not currently used to adjust y_position further,
                        # as the primary layout driver is the left column's content height.
                        _ = add_defect_to_pdf(entry_data, is_left=False, y_position=y_position)

                    # The next item should start based on the lowest point reached by the left column,
                    # y_after_left_col is now the actual bottom of the drawn content in the left column (adjusted for padding).
                    y_position = y_after_left_col - SPACE_BETWEEN_ITEMS # Apply the defined inter-item spacing
                    current_item_number += 1

                except Exception as e:
                    logger.error(f"Error processing entry {entry_description_for_log} for PDF report: {e}", exc_info=True)
                    y_position -= 20 # Advance y_position to avoid overlap if error in drawing
                    current_item_number +=1
                    continue
        return y_position, current_item_number

    # Initialize item numbering
    item_counter = 1 # Overall item counter for the entire report
    SPACE_BETWEEN_SECTIONS = 30 # Space between "Open Items" and "Closed Items" sections

    if filter_status == 'All':
        y_position, item_counter = process_defects(open_items_for_report, 'Open Items', y_position, initial_item_number=item_counter)
        if open_items_for_report and closed_items_for_report:
            y_position -= SPACE_BETWEEN_SECTIONS
            if y_position < 100: # If space is very tight after a section, force new page for next section
                logger.info("Performing page break between Open and Closed sections.")
                c.showPage()
                y_position = height - 50
        y_position, item_counter = process_defects(closed_items_for_report, 'Closed Items', y_position, initial_item_number=item_counter)
    elif filter_status == 'Open':
        y_position, item_counter = process_defects(open_items_for_report, 'Open Items', y_position, initial_item_number=item_counter)
    elif filter_status == 'Closed':
        y_position, item_counter = process_defects(closed_items_for_report, 'Closed Items', y_position, initial_item_number=item_counter)

    c.save()
    pdf_buffer.seek(0)
    filename = secure_filename(f'report_project_{project.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
    temp_path = os.path.join(app.config['REPORT_FOLDER'], filename)

    try:
        # Save PDF to temporary file
        with open(temp_path, 'wb') as f:
            f.write(pdf_buffer.read())
        pdf_buffer.close()
        logger.info(f"Saving PDF report to: {temp_path}")

        # Serve the PDF, forcing download prompt
        response = send_file(
            temp_path,
            mimetype='application/pdf',
            as_attachment=True,         
            download_name=filename      
        )

        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'

        # Log the headers for debugging
        logger.info(f"Sending PDF for project {project_id} with headers: {dict(response.headers)}")

        # Cleanup function
        def cleanup():
            try:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                    # Ensure this log is consistent and clear about context
                    logger.info(f'Cleaned up temporary report file after serving: {temp_path}')
            except Exception as e:
                logger.error(f'Error cleaning up temporary report file {temp_path} after serving: {str(e)}')

        response.call_on_close(cleanup)
        return response
    except Exception as e:
        logger.error(f'Error generating or serving PDF report for project {project_id}: {str(e)}', exc_info=True)
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logger.info(f'Cleaned up temporary report file after error during generation/serving: {temp_path}')
            except Exception as ex:
                logger.error(f'Error cleaning up temporary report file {temp_path} after error: {str(ex)}')
        flash(f'Error generating report: {str(e)}', 'error')
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
            att_d2 = Attachment(defect_id=d2.id, file_path='images/test_image1.jpg', thumbnail_path='images/thumb_test_image1.jpg') # Assume thumbnail created elsewhere for test
            db.session.add(att_d2)
            # Simulate thumbnail creation for test_image1.jpg
            if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], 'thumb_test_image1.jpg')):
                 if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], 'test_image1.jpg')):
                    create_thumbnail(os.path.join(app.config['UPLOAD_FOLDER'], 'test_image1.jpg'), os.path.join(app.config['UPLOAD_FOLDER'], 'thumb_test_image1.jpg'))
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
            att_d5_defect = Attachment(defect_id=d5.id, file_path='images/test_image2.png', thumbnail_path='images/thumb_test_image2.png')
            db.session.add(att_d5_defect)
            if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], 'thumb_test_image2.png')):
                 if os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], 'test_image2.png')):
                    create_thumbnail(os.path.join(app.config['UPLOAD_FOLDER'], 'test_image2.png'), os.path.join(app.config['UPLOAD_FOLDER'], 'thumb_test_image2.png'))
                 else:
                    logger.warning("test_image2.png not found for thumbnail creation in test setup.")


            comment_d5 = Comment(defect_id=d5.id, user_id=contractor_user.id, content="Work in progress. See attached photo.", created_at=datetime.now())
            db.session.add(comment_d5)
            db.session.flush()
            att_d5_comment = Attachment(comment_id=comment_d5.id, file_path='images/test_image1.jpg', thumbnail_path='images/thumb_test_image1.jpg')
            db.session.add(att_d5_comment)

            # D6
            d6 = Defect(project_id=project.id, description="Open defect with a corrupt image.", status='open', creator_id=admin_user.id, creation_date=datetime.now())
            db.session.add(d6)
            db.session.flush()
            att_d6 = Attachment(defect_id=d6.id, file_path='images/corrupt_image.jpg', thumbnail_path='images/thumb_corrupt_image.jpg') # Thumbnail might not exist or also be corrupt
            db.session.add(att_d6)
            # No thumbnail creation for corrupt_image.jpg to ensure it's handled

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
            att_cli1_2 = Attachment(checklist_item_id=cli1_2.id, file_path='images/test_image2.png', thumbnail_path='images/thumb_test_image2.png')
            db.session.add(att_cli1_2)
            # Thumbnail for test_image2.png already created with D5

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
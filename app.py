from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from flask_bcrypt import Bcrypt
from threading import Lock
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime
from werkzeug.utils import secure_filename
import os
import shutil
from PIL import Image as PILImage, ImageDraw
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.graphics.shapes import Drawing, Rect
from reportlab.lib import colors
from reportlab.graphics import renderPDF
import io
import logging
from sqlalchemy import inspect
import tempfile

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    return render_template('add_defect.html', project=project, drawings=drawings_data, user_role=access.role)

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
            if 'delete' in request.form:
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

            if 'comment' in request.form:
                content = request.form['comment'].strip()
                if content:
                    comment = Comment(defect_id=defect_id, user_id=current_user.id, content=content)
                    db.session.add(comment)
                    db.session.commit()
                    attachment_ids = []
                    if 'photos' in request.files:
                        files = request.files.getlist('photos')
                        for file in files:
                            if file and allowed_file(file.filename):
                                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                                filename = secure_filename(f'comment_{comment.id}_{timestamp}_{file.filename}')
                                file_path = os.path.join('images', filename)
                                full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                                thumbnail_filename = f'thumb_{filename}'
                                thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename)
                                try:
                                    img = PILImage.open(file)
                                    img = img.convert('RGB')
                                    img.save(full_path, quality=85, optimize=True)
                                    os.chmod(full_path, 0o644)
                                    create_thumbnail(full_path, thumbnail_path)
                                    attachment = Attachment(comment_id=comment.id, file_path=file_path, thumbnail_path=f'images/{thumbnail_filename}')
                                    db.session.add(attachment)
                                    db.session.commit()
                                    attachment_ids.append(attachment.id)
                                except Exception as e:
                                    logger.error(f'Error processing file {file.filename}: {str(e)}')
                                    flash(f'Error uploading file {file.filename}: {str(e)}', 'error')
                                    db.session.rollback()
                                    continue
                    if attachment_ids:
                        logger.info(f"Comment with attachments added to defect {defect_id}")
                        return redirect(url_for('draw', attachment_id=attachment_ids[0], next=url_for('defect_detail', defect_id=defect_id)))
                    logger.info(f"Comment added to defect {defect_id}")
                    flash('Comment added successfully!', 'success')
                else:
                    logger.warning(f"Empty comment submitted for defect {defect_id}")
                    flash('Comment cannot be empty.', 'error')

            elif 'description' in request.form:
                if access.role not in ['admin', 'expert']:
                    logger.warning(f"User {current_user.id} attempted to edit defect {defect_id} without permission")
                    flash('You do not have permission to edit defects.', 'error')
                    return redirect(url_for('defect_detail', defect_id=defect_id))
                description = request.form.get('description', '').strip()
                status = request.form.get('status', '').lower()
                if not description:
                    logger.warning(f"Empty description submitted for defect {defect_id}")
                    flash('Description is required!', 'error')
                    return redirect(url_for('defect_detail', defect_id=defect_id))
                defect.description = description
                if status in ['open', 'closed']:
                    if status == 'closed' and defect.creator_id != current_user.id and access.role != 'admin':
                        logger.warning(f"User {current_user.id} attempted to close defect {defect_id} without permission")
                        flash('You can only close defects you created.', 'error')
                        return redirect(url_for('defect_detail', defect_id=defect_id))
                    defect.status = status
                    if status == 'closed' and not defect.close_date:
                        defect.close_date = datetime.now()
                    elif status == 'open':
                        defect.close_date = None
                db.session.commit()
                logger.info(f"Defect {defect_id} updated: description={description}, status={status}")
                flash('Defect updated successfully!', 'success')

            return redirect(url_for('defect_detail', defect_id=defect_id))

        # Fetch attachments and comments
        attachments = Attachment.query.filter_by(defect_id=defect_id, checklist_item_id=None, comment_id=None).all()
        comments = Comment.query.filter_by(defect_id=defect_id).order_by(Comment.created_at.asc()).all()

        # Fetch marker and drawing
        marker = DefectMarker.query.filter_by(defect_id=defect_id).first()
        drawing = None
        marker_data = None
        if marker:
            drawing = Drawing.query.get(marker.drawing_id)
            if drawing:
                marker_data = {
                    'drawing_id': marker.drawing_id,
                    'x': marker.x,
                    'y': marker.y,
                    'file_path': drawing.file_path
                }
                logger.debug(f"Defect {defect_id} - Marker data: {marker_data}")
            else:
                logger.warning(f"Drawing {marker.drawing_id} not found for defect {defect_id}")
        else:
            logger.debug(f"No marker found for defect {defect_id}")

        logger.info(f"Rendering defect_detail for defect {defect_id}")
        return render_template(
            'defect_detail.html',
            defect=defect,
            attachments=attachments,
            comments=comments,
            user_role=access.role,
            marker=marker_data,
            project=defect.project
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
                        file_path = os.path.join('images', filename)
                        full_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        thumbnail_filename = f'thumb_{filename}'
                        thumbnail_path = os.path.join(app.config['UPLOAD_FOLDER'], thumbnail_filename)
                        try:
                            file.save(full_path)
                            os.chmod(full_path, 0o644)
                            create_thumbnail(full_path, thumbnail_path)
                            attachment = Attachment(checklist_item_id=item.id, file_path=file_path, thumbnail_path=f'images/{thumbnail_filename}')
                            db.session.add(attachment)
                            db.session.commit()
                            attachment_ids.append(attachment.id)
                        except Exception as e:
                            flash(f'Error uploading file {file.filename}: {str(e)}', 'error')
                            logger.error(f'Error uploading file {file.filename}: {str(e)}')
                            db.session.rollback()
                            continue
                if attachment_ids:
                    # Redirect to draw the first uploaded image
                    return redirect(url_for('draw', attachment_id=attachment_ids[0], next=url_for('checklist_detail', checklist_id=checklist_id)))
            db.session.commit()
            flash('Checklist updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating checklist: {str(e)}', 'error')
            logger.error(f'Error updating checklist {checklist_id}: {str(e)}')
            return redirect(url_for('checklist_detail', checklist_id=checklist_id))
        return redirect(url_for('project_detail', project_id=checklist.project_id))
    return render_template('checklist_detail.html', checklist=checklist, items=items)

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
@login_required
def generate_report(project_id):
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

    checklists = Checklist.query.filter_by(project_id=project_id).all()
    checklist_items_to_report = []
    for checklist in checklists:
        items = ChecklistItem.query.filter_by(checklist_id=checklist.id).all()
        for item in items:
            item_status = 'closed' if item.is_checked else 'open'
            if filter_status == 'Open' and item_status != 'open':
                continue
            elif filter_status == 'Closed' and item_status != 'closed':
                continue
            checklist_items_to_report.append((checklist, item, item_status))

    if not defects and not checklist_items_to_report:
        flash('No defects or checklist items found to generate a report.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))

    open_defects = []
    closed_defects = []
    for defect in defects:
        contractor_comments = Comment.query.filter_by(defect_id=defect.id).join(User).filter(User.role == 'contractor').all()
        if defect.status == 'open':
            open_defects.append(('defect', defect, contractor_comments))
        else:
            closed_defects.append(('defect', defect, contractor_comments))
    for checklist, item, item_status in checklist_items_to_report:
        if item_status == 'open':
            open_defects.append(('checklist_item', checklist, item, []))
        else:
            closed_defects.append(('checklist_item', checklist, item, []))

    open_defects.sort(key=lambda x: x[1].creation_date if x[0] == 'defect' else x[1].creation_date)
    closed_defects.sort(key=lambda x: (x[1].close_date if x[1].close_date else x[1].creation_date) if x[0] == 'defect' else x[1].creation_date, reverse=True)

    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer, pagesize=letter)
    width, height = letter
    left_margin = 50
    right_margin = width - 50
    center_x = width / 2
    column_width = (width - left_margin - (width - right_margin)) / 2

    def draw_text_wrapped(c, text, x, y, max_width, line_height=15, font='Helvetica', font_size=12):
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
        for line in lines:
            c.drawString(x, y, line)
            y -= line_height
        return y, len(lines) * line_height

    def add_image_to_pdf(c, img_path, x, y, max_width, max_height):
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
            img_width, img_height = img.size
            aspect_ratio = img_width / img_height
            # Scale image to fit max_width
            img_width = max_width
            img_height = img_width / aspect_ratio
            # If height exceeds max_height, scale down
            if img_height > max_height:
                img_height = max_height
                img_width = img_height * aspect_ratio
            img_reader = ImageReader(temp_img_path)
            c.drawImage(img_reader, x, y - img_height, width=img_width, height=img_height)
            os.remove(temp_img_path)
            return y - img_height - 10, img_height
        except Exception as e:
            c.drawString(x, y, f'Error loading image: {str(e)}')
            return y - 20, 0

    def draw_rounded_rect(c, x, y, width, height, radius=10):
        drawing = Drawing(width, height)
        fill_color = colors.Color(*colors.lightgrey.rgb(), alpha=0.2)
        rect = Rect(0, -height, width, height, strokeColor=colors.darkgrey, fillColor=fill_color, strokeWidth=1)
        rect.rx = radius
        rect.ry = radius
        drawing.add(rect)
        c.saveState()
        c.translate(x, y)
        renderPDF.draw(drawing, c, 0, 0)
        c.restoreState()

    def estimate_space_needed(entry, is_left=True):
        max_width = column_width - 20 if is_left else (width - center_x - 30)
        space_needed = 30  # Base padding and title
        font_size = 12
        date_font_size = 8
        line_height = 15
        date_line_height = 10

        if entry[0] == 'defect':
            defect = entry[1]
            description = defect.description
            close_date = defect.close_date
            attachments = Attachment.query.filter_by(defect_id=defect.id, checklist_item_id=None, comment_id=None).all()
            comments = None
            contractor_comments = entry[2]
        else:
            checklist, item = entry[1], entry[2]
            description = f"Checkpoint: {item.item_text}"
            close_date = None
            attachments = Attachment.query.filter_by(checklist_item_id=item.id).all()
            comments = item.comments if item.comments and item.comments.strip() else None
            contractor_comments = []

        if is_left:
            # Estimate description height
            words = description.split()
            lines = []
            current_line = []
            current_width = 0
            for word in words:
                word_width = c.stringWidth(word + ' ', 'Helvetica', font_size)
                if current_width + word_width <= max_width:
                    current_line.append(word)
                    current_width += word_width
                else:
                    lines.append(' '.join(current_line))
                    current_line = [word]
                    current_width = word_width
            if current_line:
                lines.append(' '.join(current_line))
            space_needed += len(lines) * line_height + 7.5  # Half line offset for description
            # Comments for checklist items
            if comments:
                words = comments.split()
                lines = []
                current_line = []
                current_width = 0
                for word in words:
                    word_width = c.stringWidth(word + ' ', 'Helvetica', font_size)
                    if current_width + word_width <= max_width:
                        current_line.append(word)
                        current_width += word_width
                    else:
                        lines.append(' '.join(current_line))
                        current_line = [word]
                        current_width = word_width
                if current_line:
                    lines.append(' '.join(current_line))
                space_needed += len(lines) * line_height + 10
            # Attachments
            for attachment in attachments:
                try:
                    img = PILImage.open(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path)))
                    img_width, img_height = img.size
                    max_img_width = max_width
                    max_img_height = 150
                    aspect_ratio = img_width / img_height
                    img_width = max_img_width
                    img_height = img_width / aspect_ratio
                    if img_height > max_img_height:
                        img_height = max_img_height
                        img_width = img_height * aspect_ratio
                    space_needed += img_height + 10
                except:
                    space_needed += 20
            # Close date
            if close_date:
                space_needed += date_line_height
            # Creation date (outside rectangle) and spacing to next defect
            space_needed += date_line_height + 7.5 + (2 * line_height)  # Creation date + half line below + two line spaces
            space_needed += 20  # Padding inside rectangle
        else:
            # Contractor comments
            for comment in contractor_comments:
                words = comment.content.split()
                lines = []
                current_line = []
                current_width = 0
                for word in words:
                    word_width = c.stringWidth(word + ' ', 'Helvetica', font_size)
                    if current_width + word_width <= max_width:
                        current_line.append(word)
                        current_width += word_width
                    else:
                        lines.append(' '.join(current_line))
                        current_line = [word]
                        current_width = word_width
                if current_line:
                    lines.append(' '.join(current_line))
                space_needed += len(lines) * line_height + 17.5  # Content + padding + half line offset
                for attachment in comment.attachments:
                    try:
                        img = PILImage.open(os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path)))
                        img_width, img_height = img.size
                        max_img_width = max_width
                        max_img_height = 150
                        aspect_ratio = img_width / img_height
                        img_width = max_img_width
                        img_height = img_width / aspect_ratio
                        if img_height > max_img_height:
                            img_height = max_img_height
                            img_width = img_height * aspect_ratio
                        space_needed += img_height + 10
                    except:
                        space_needed += 20
                # Creation date (outside rectangle)
                space_needed += date_line_height + 7.5  # Creation date + half line below
                space_needed += 20  # Padding inside rectangle
        return space_needed

    def add_defect_to_pdf(entry, is_left=True, y_position=None, defect_number=1):
        nonlocal c
        x_position = left_margin if is_left else center_x + 10
        max_width = column_width - 20 if is_left else (width - center_x - 30)
        padding = 10
        line_height = 15  # Define line_height for single line spacing

        if entry[0] == 'defect':
            defect = entry[1]
            description = defect.description
            creation_date = defect.creation_date
            close_date = defect.close_date
            attachments = Attachment.query.filter_by(defect_id=defect.id, checklist_item_id=None, comment_id=None).all()
            comments = None
            contractor_comments = entry[2]
        else:
            checklist, item = entry[1], entry[2]
            description = f"Checkpoint: {item.item_text}"
            creation_date = checklist.creation_date
            close_date = None
            attachments = Attachment.query.filter_by(checklist_item_id=item.id).all()
            comments = item.comments if item.comments and item.comments.strip() else None
            contractor_comments = []

        if is_left:
            # Draw "Defect N:" title
            c.setFont('Helvetica-Bold', 12)
            c.drawString(x_position, y_position, f'Defect {defect_number}:')
            y_position -= 15

            # Calculate rectangle height
            rect_height = 0
            y_temp = y_position
            y_temp -= (padding + 7.5)  # Top padding + half line for description
            y_temp, desc_height = draw_text_wrapped(c, description, x_position + padding, y_temp, max_width, font='Helvetica', font_size=12)
            rect_height += desc_height + padding + 7.5
            if comments:
                y_temp, comment_height = draw_text_wrapped(c, comments, x_position + padding, y_temp - padding, max_width, font='Helvetica', font_size=12)
                rect_height += comment_height + padding
            for attachment in attachments:
                y_temp, img_height = add_image_to_pdf(c, os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path)), x_position + padding, y_temp - 10, max_width, 150)
                rect_height += img_height + 10
            if close_date:
                rect_height += 10
                y_temp -= 10
            rect_height += padding  # Bottom padding

            # Draw rounded rectangle
            draw_rounded_rect(c, x_position, y_position, column_width - 10, rect_height, radius=10)

            # Draw description (half line lower)
            y_position -= (padding + 7.5)
            y_position, _ = draw_text_wrapped(c, description, x_position + padding, y_position, max_width, font='Helvetica', font_size=12)
            if comments:
                y_position, _ = draw_text_wrapped(c, comments, x_position + padding, y_position - padding, max_width, font='Helvetica', font_size=12)
            for attachment in attachments:
                y_position, img_height = add_image_to_pdf(c, os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path)), x_position + padding, y_position - 10, max_width, 150)
            if close_date:
                c.setFont('Helvetica', 8)
                c.drawString(x_position + padding, y_position - 10, f'Close Date: {close_date.strftime("%Y-%m-%d %H:%M:%S")}')
                y_position -= 10
            y_position -= padding
            # Draw creation date below rectangle
            c.setFont('Helvetica', 8)
            creation_date_y = y_position - 7.5
            c.drawString(x_position + padding, creation_date_y, f'Creation Date: {creation_date.strftime("%Y-%m-%d %H:%M:%S")}')
            # Store the y_position of the creation date to calculate the next defect's position
            y_left = creation_date_y - (2 * line_height)  # Two line spaces (30 points) below creation date
        else:
            if contractor_comments:
                c.setFont('Helvetica-Bold', 12)
                c.drawString(x_position, y_position, 'Contractors Reply:')
                y_position -= 15
                for comment in contractor_comments:
                    # Calculate rectangle height
                    rect_height = 0
                    y_temp = y_position
                    y_temp -= (padding + 7.5)  # Top padding + half line for comment
                    y_temp, content_height = draw_text_wrapped(c, comment.content, x_position + padding, y_temp, max_width, font='Helvetica', font_size=12)
                    rect_height += content_height + padding + 7.5
                    for attachment in comment.attachments:
                        y_temp, img_height = add_image_to_pdf(c, os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path)), x_position + padding, y_temp - 10, max_width, 150)
                        rect_height += img_height + 10
                    rect_height += padding

                    # Draw rounded rectangle
                    draw_rounded_rect(c, x_position, y_position, width - center_x - 20, rect_height, radius=10)

                    # Draw content
                    y_position -= (padding + 7.5)
                    y_position, _ = draw_text_wrapped(c, comment.content, x_position + padding, y_position, max_width, font='Helvetica', font_size=12)
                    for attachment in comment.attachments:
                        y_position, img_height = add_image_to_pdf(c, os.path.join(app.config['UPLOAD_FOLDER'], os.path.basename(attachment.file_path)), x_position + padding, y_position - 10, max_width, 150)
                    y_position -= padding
                    # Draw creation date below rectangle
                    c.setFont('Helvetica', 8)
                    c.drawString(x_position + padding, y_position - 7.5, f'Creation Date: {comment.created_at.strftime("%Y-%m-%d %H:%M:%S")}')
                    y_position -= (10 + 7.5)  # Creation date height + half line
            else:
                y_position -= rect_height if 'rect_height' in locals() else 0
            y_right = y_position
        # Return the y_position for the next defect, ensuring two line spaces from the left column's creation date
        return y_left if is_left else y_right

    c.setFont('Helvetica-Bold', 16)
    y_position = height - 50
    c.drawString(left_margin, y_position, f'Project: {project.name}')
    y_position -= 30

    def process_defects(defect_list, title, y_position):
        if defect_list:
            c.setFont('Helvetica-Bold', 14)
            c.drawString(left_margin, y_position, f'{title}: {len(defect_list)}')
            y_position -= 20
            for idx, entry in enumerate(defect_list, 1):
                space_needed_left = estimate_space_needed(entry, is_left=True)
                space_needed_right = estimate_space_needed(entry, is_left=False)
                total_space_needed = max(space_needed_left, space_needed_right)
                if y_position - total_space_needed < 50:
                    c.showPage()
                    y_position = height - 50
                    c.setFont('Helvetica', 12)
                # Add left column (defect details)
                y_left = add_defect_to_pdf(entry, is_left=True, y_position=y_position, defect_number=idx)
                # Add right column (contractor comments)
                y_right = add_defect_to_pdf(entry, is_left=False, y_position=y_position)
                # Use y_left for the next defect to ensure two line spaces from creation date
                y_position = y_left
        return y_position

    if filter_status == 'All':
        y_position = process_defects(open_defects, 'Open defects', y_position)
        y_position = process_defects(closed_defects, 'Closed defects', y_position)
    elif filter_status == 'Open':
        y_position = process_defects(open_defects, 'Open defects', y_position)
    elif filter_status == 'Closed':
        y_position = process_defects(closed_defects, 'Closed defects', y_position)

    c.save()
    pdf_buffer.seek(0)
    filename = secure_filename(f'report_project_{project.name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
    temp_path = os.path.join(app.config['REPORT_FOLDER'], filename)

    try:
        # Save PDF to temporary file
        with open(temp_path, 'wb') as f:
            f.write(pdf_buffer.read())
        pdf_buffer.close()

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
                    logger.info(f'Cleaned up temporary report file: {temp_path}')
            except Exception as e:
                logger.error(f'Error cleaning up temporary report file {temp_path}: {str(e)}')

        response.call_on_close(cleanup)
        return response
    except Exception as e:
        logger.error(f'Error generating or serving PDF report for project {project_id}: {str(e)}')
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logger.info(f'Cleaned up temporary report file after error: {temp_path}')
            except Exception as ex:
                logger.error(f'Error cleaning up temporary report file {temp_path}: {str(ex)}')
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
    return render_template('draw.html', attachment=attachment, next_url=next_url)

if __name__ == '__main__':
    app.run(debug=True)
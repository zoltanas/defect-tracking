from flask import Flask, render_template, request, redirect, url_for, flash, send_file, jsonify, Response, send_from_directory, make_response, session
import firebase_admin
from firebase_admin import credentials, firestore, storage as firebase_storage
from google.cloud import storage
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import click # For Flask CLI
from threading import Lock
from itsdangerous import URLSafeTimedSerializer
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import os
import shutil
from PIL import Image as PILImage, ImageDraw, ImageOps
import io
from weasyprint import HTML
from pdf2image import convert_from_path # Ensure this is present
import logging
import tempfile
import zipfile
import glob
from dotenv import load_dotenv
load_dotenv()

# Initialize Firebase
cred = credentials.ApplicationDefault()
firebase_admin.initialize_app(cred)
db = firestore.client()

# Initialize Google Cloud Storage
storage_client = storage.Client()
# TODO: Make sure to set GCS_BUCKET_NAME in your environment variables
BUCKET_NAME = os.environ.get('GCS_BUCKET_NAME')
if not BUCKET_NAME:
    raise ValueError("GCS_BUCKET_NAME environment variable not set.")
bucket = storage_client.bucket(BUCKET_NAME)


# Helper function to find Poppler path
def get_poppler_path():
    """
    Checks for Poppler installation via POPPLER_PATH environment variable
    or in the system PATH.
    Returns the path to Poppler binaries if found, otherwise None.
    """
    poppler_path_env = os.environ.get('POPPLER_PATH')
    if poppler_path_env:
        if os.path.exists(os.path.join(poppler_path_env, 'pdftoppm')) or \
           os.path.exists(os.path.join(poppler_path_env, 'pdftoppm.exe')):
            return poppler_path_env

    pdftoppm_executable = shutil.which('pdftoppm')
    if pdftoppm_executable:
        found_path = os.path.dirname(pdftoppm_executable)
        return found_path

    return None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if not logger.handlers:
    handler = logging.StreamHandler() # Defaults to stderr
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.DEBUG)
logger.info("Flask application logger explicitly configured for checklist debugging.")

# Initialize Flask app
app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['SECRET_KEY'] = 'your-secret-key'


app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf'}
app.config['SERIALIZER_SECRET_KEY'] = 'your-serializer-secret-key'


# --- Flask-Mail Configuration ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.example.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', '587'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'your-email@example.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'your-email-password')
app.config['MAIL_SENDER_NAME'] = os.environ.get('MAIL_SENDER_NAME', 'Defect Tracker')
app.config['MAIL_DEFAULT_SENDER_EMAIL'] = os.environ.get('MAIL_DEFAULT_SENDER_EMAIL', 'noreply@defect-tracker.com')
app.config['MAIL_DEBUG'] = True

print("--- MAIL CONFIGURATION ---")
print(f"MAIL_SERVER: {app.config['MAIL_SERVER']}")
print(f"MAIL_PORT: {app.config['MAIL_PORT']}")
print(f"MAIL_USE_TLS: {app.config['MAIL_USE_TLS']}")
print(f"MAIL_USERNAME: {app.config['MAIL_USERNAME']}")
print(f"MAIL_PASSWORD loaded: {'Yes' if app.config['MAIL_PASSWORD'] else 'No'}")
print("--------------------------")

mail = Mail(app)


# Initialize extensions
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Refactored User class for Firestore
class User(UserMixin):
    def __init__(self, id, username, password, role='user', email=None, name=None, company=None, status='pending_activation', projects=None):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.email = email or username
        self.name = name
        self.company = company
        self.status = status
        self.projects = projects if projects is not None else []

    @staticmethod
    def get(user_id):
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            return User(
                id=user_doc.id,
                username=user_data.get('username'),
                password=user_data.get('password'),
                role=user_data.get('role'),
                email=user_data.get('email'),
                name=user_data.get('name'),
                company=user_data.get('company'),
                status=user_data.get('status'),
                projects=user_data.get('projects', [])
            )
        return None



@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Custom decorator to require email confirmation
from functools import wraps

def email_confirmed_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('login', next=request.url))
        if current_user.status != 'active':
            flash('Please confirm your email address to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.context_processor
def utility_processor():
    def get_gcs_signed_url(blob_name):
        if not blob_name:
            return None
        try:
            blob = bucket.blob(blob_name)
            # Generate a signed URL that is valid for 1 hour
            signed_url = blob.generate_signed_url(expiration=timedelta(hours=1))
            return signed_url
        except Exception as e:
            logger.error(f"Error generating signed URL for {blob_name}: {e}")
            return None
    return dict(get_gcs_signed_url=get_gcs_signed_url)

@app.context_processor
def inject_accessible_projects():
    user_for_projects = get_effective_current_user()

    if user_for_projects and user_for_projects.is_authenticated:
        project_ids = [p['project_id'] for p in user_for_projects.projects]

        if project_ids:
            projects_ref = db.collection('projects')
            accessible_project_objects = [doc.to_dict() for doc in projects_ref.where('id', 'in', project_ids).stream()]

            return dict(accessible_projects=accessible_project_objects)

    return dict(accessible_projects=[])



def create_thumbnail_from_gcs(bucket, source_blob_name, destination_blob_name, size=(300, 300)):
    try:
        source_blob = bucket.blob(source_blob_name)

        with tempfile.NamedTemporaryFile(delete=False) as temp_image_file:
            source_blob.download_to_file(temp_image_file)
            temp_image_path = temp_image_file.name

        with PILImage.open(temp_image_path) as img:
            img = ImageOps.exif_transpose(img)
            img.thumbnail(size, PILImage.Resampling.LANCZOS)
            if img.mode == 'RGBA' or img.mode == 'P':
                img = img.convert('RGB')

            with tempfile.NamedTemporaryFile(suffix='.jpg', delete=False) as temp_thumb_file:
                img.save(temp_thumb_file, 'JPEG', quality=85, optimize=True)
                temp_thumb_path = temp_thumb_file.name

        destination_blob = bucket.blob(destination_blob_name)
        destination_blob.upload_from_filename(temp_thumb_path)

        logger.debug(f'Created and uploaded thumbnail: {destination_blob_name}')
    except Exception as e:
        logger.error(f'Thumbnail creation from GCS failed for {source_blob_name}: {str(e)}')
        raise
    finally:
        if 'temp_image_path' in locals() and os.path.exists(temp_image_path):
            os.remove(temp_image_path)
        if 'temp_thumb_path' in locals() and os.path.exists(temp_thumb_path):
            os.remove(temp_thumb_path)


import json



# --- Helper functions for Substitution ---
def get_actual_current_user():
    """Always returns the user who is actually logged in."""
    return current_user

def get_effective_current_user():
    """
    Returns the user object the current session is effectively acting as.
    If substituting, this is the original user. Otherwise, it's the logged-in user.
    """
    actual_user = get_actual_current_user()
    if not actual_user or not actual_user.is_authenticated:
        return actual_user # Return anonymous user or None

    acting_as_original_user_id = session.get('acting_as_original_user_id')
    logger.debug(f"GET_EFFECTIVE_USER: actual_user_id={actual_user.id if actual_user and actual_user.is_authenticated else 'None'}, acting_as_original_user_id={acting_as_original_user_id}")
    if acting_as_original_user_id:
        original_user = User.get(acting_as_original_user_id)
        if original_user:
            logger.debug(f"GET_EFFECTIVE_USER: Found original_user.id={original_user.id}, original_user.username={original_user.username}")
            if hasattr(original_user, 'projects'):
                 logger.debug(f"GET_EFFECTIVE_USER: original_user.projects count: {len(original_user.projects if original_user.projects else [])}")
                 for pa_log in original_user.projects:
                     logger.debug(f"GET_EFFECTIVE_USER: Original user ProjectAccess: user_id={pa_log['user_id']}, project_id={pa_log['project_id']}")

            else:
                logger.debug("GET_EFFECTIVE_USER: original_user does not have 'projects' attribute immediately after query.")
            return original_user
        else:
            session.pop('acting_as_original_user_id', None)
            session.pop('actual_substitute_user_id', None)
            logger.error(f"User ID {acting_as_original_user_id} from session 'acting_as_original_user_id' not found. Cleared substitution session.")
            return actual_user
    return actual_user

@app.before_request
def before_request_checks():
    pass

@app.context_processor
def inject_effective_user():
    """Injects effective_current_user and actual_current_user into template contexts."""
    effective_user = get_effective_current_user()
    actual_user = get_actual_current_user()

    is_substitute_session = False
    if actual_user and actual_user.is_authenticated and session.get('acting_as_original_user_id'):
        if effective_user and effective_user.id == session.get('acting_as_original_user_id'):
            is_substitute_session = True

    original_user_to_act_as_directly = None
    if actual_user and actual_user.is_authenticated and not is_substitute_session:
        active_sub_relations_docs = db.collection('user_substitutes').where('substitute_user_id', '==', actual_user.id).where('is_active', '==', True).stream()
        active_sub_relations = [doc.to_dict() for doc in active_sub_relations_docs]

        if len(active_sub_relations) == 1:
            original_user_to_act_as_directly = User.get(active_sub_relations[0]['original_user_id'])


    return dict(
        effective_current_user=effective_user,
        actual_current_user=actual_user,
        is_substitute_session=is_substitute_session,
        original_user_to_act_as_directly=original_user_to_act_as_directly
    )

# --- End Helper functions for Substitution ---


# Authentication Routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name'].strip()
        company = request.form['company'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = 'admin'

        if not name or not company:
            flash('Name and Company are required.', 'error')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')

        import re
        if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            flash('Invalid email format.', 'error')
            return render_template('register.html')

        users_ref = db.collection('users')
        if users_ref.where('email', '==', email).limit(1).get():
            flash('This email is already registered. Please log in or use a different email.', 'error')
            return render_template('register.html')



        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {
            'username': email,
            'email': email,
            'password': hashed_password,
            'role': role,
            'name': name,
            'company': company,
            'status': 'pending_activation'
        }

        update_time, user_ref = db.collection('users').add(user_data)


        s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
        token = s.dumps(email, salt='email-confirm-salt')

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
                      recipients=[email],
                      html=html_body)
        try:
            mail.send(msg)
            flash('Registration successful! A confirmation email has been sent to your email address. Please verify your email to activate your account.', 'info')
        except Exception as e:
            logger.error(f"Failed to send confirmation email to {email}: {str(e)}", exc_info=True)
            flash('Registration successful, but failed to send confirmation email. Please contact support.', 'warning')

        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/confirm_email/<token>')
def confirm_email(token):
    s = URLSafeTimedSerializer(app.config['SERIALIZER_SECRET_KEY'])
    try:
        email = s.loads(token, salt='email-confirm-salt', max_age=3600)
    except Exception as e:
        logger.warning(f"Email confirmation token validation failed. Token: {token}, Error: {str(e)}")
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))

    users_ref = db.collection('users')
    user_query = users_ref.where('email', '==', email).limit(1).stream()
    user_doc = next(user_query, None)

    if not user_doc:
        flash('User not found for this confirmation link.', 'danger')
        return redirect(url_for('login'))

    user_data = user_doc.to_dict()

    if user_data.get('status') == 'active':
        flash('Your account is already active. Please log in.', 'info')
        return redirect(url_for('login'))

    user_doc.reference.update({'status': 'active'})

    user = User(
        id=user_doc.id,
        username=user_data.get('username'),
        password=user_data.get('password'),
        role=user_data.get('role'),
        email=user_data.get('email'),
        name=user_data.get('name'),
        company=user_data.get('company'),
        status='active',
        projects=user_data.get('projects', [])
    )

    login_user(user)
    flash('Email confirmed! Your account is now active and you have been logged in.', 'success')
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    actual_current_user_obj = get_actual_current_user()
    if actual_current_user_obj.is_authenticated:
        if session.get('acting_as_original_user_id'):
            return redirect(url_for('index'))
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']

        users_ref = db.collection('users')
        user_query = users_ref.where('email', '==', email).limit(1).stream()
        user_doc = next(user_query, None)
        user_data = user_doc.to_dict() if user_doc else None

        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            if user_data['status'] == 'pending_activation':
                flash('Please verify your email address before logging in. A confirmation email was sent to you upon registration.', 'warning')
                return redirect(url_for('login'))
            elif user_data['status'] == 'active':
                user = User(
                    id=user_doc.id,
                    username=user_data.get('username'),
                    password=user_data.get('password'),
                    role=user_data.get('role'),
                    email=user_data.get('email'),
                    name=user_data.get('name'),
                    company=user_data.get('company'),
                    status=user_data.get('status'),
                    projects=user_data.get('projects', [])
                )
                login_user(user)
                flash('Logged in successfully!', 'success')

                session.pop('acting_as_original_user_id', None)
                session.pop('actual_substitute_user_id', None)

                user_doc.reference.update({'is_substituting': False})


                return redirect(url_for('index'))
            elif user_data['status'] == 'deleted':
                flash('This account has been removed. Please register a new account or contact support.', 'error')
                return redirect(url_for('login'))
            else:
                flash('Your account is not active. Please contact support.', 'error')
                return redirect(url_for('login'))

        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    actual_user = get_actual_current_user()
    if actual_user and actual_user.is_authenticated:
        if session.get('acting_as_original_user_id'):

            substituting_user_doc = db.collection('users').document(actual_user.id).get()
            if substituting_user_doc.exists:
                substituting_user_doc.reference.update({'is_substituting': False})

            session.pop('acting_as_original_user_id', None)
            session.pop('actual_substitute_user_id', None)
            flash('Substitute session ended.', 'info')

    logout_user()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

# ... (the rest of the file)

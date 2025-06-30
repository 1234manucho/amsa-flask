import os
import traceback
import logging
import locale
import json # <--- Ensure this import is present

from flask import Flask, flash
from dotenv import load_dotenv
import click
import firebase_admin
from firebase_admin import credentials, firestore, auth
from firebase_admin import exceptions as fb_exceptions
from werkzeug.security import generate_password_hash
# from flask_wtf.csrf import CSRFProtect  # ✅ Import CSRF

# Load environment variables from .env file
load_dotenv()

# --- Configure Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Import DB and Migrate from extensions ---
from .extensions import db, migrate

# --- Custom Jinja2 Filter: intcomma ---
def intcomma_filter(value):
    try:
        locale.setlocale(locale.LC_ALL, '')
    except locale.Error:
        pass

    if isinstance(value, (int, float)):
        if isinstance(value, int):
            return locale.format_string("%d", value, grouping=True)
        else:
            return locale.format_string("%.2f", value, grouping=True)
    return value

# --- Custom Jinja2 Filter: floatformat ---
def floatformat_filter(value, precision=2):
    try:
        return f"{float(value):.{precision}f}"
    except (ValueError, TypeError):
        return value

# --- App Factory ---
def create_app():
    app = Flask(__name__)

    # --- Flask Config ---
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secure_fallback_secret_key_change_me_in_prod')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

   

    # --- M-Pesa Configuration ---
    app.config['MPESA_CONSUMER_KEY'] = os.getenv('MPESA_CONSUMER_KEY')
    app.config['MPESA_CONSUMER_SECRET'] = os.getenv('MPESA_CONSUMER_SECRET')
    app.config['MPESA_API_BASE_URL'] = os.getenv('MPESA_API_BASE_URL', 'https://sandbox.safaricom.co.ke')
    app.config['MPESA_BUSINESS_SHORTCODE'] = os.getenv('MPESA_BUSINESS_SHORTCODE')
    app.config['MPESA_PASSKEY'] = os.getenv('MPESA_PASSKEY')
    app.config['MPESA_CALLBACK_URL'] = os.getenv('MPESA_CALLBACK_URL')

    # --- Firebase Configuration ---
    app.config['FIREBASE_WEB_API_KEY'] = os.getenv('FIREBASE_WEB_API_KEY')


    # --- File Upload Config ---
    upload_path = os.path.join(os.path.dirname(__file__), 'static', 'uploads', 'land_images')
    os.makedirs(upload_path, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_path
    app.allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}

    def allowed_file_checker(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.allowed_extensions
    app.allowed_file = allowed_file_checker

    # --- Register Jinja2 Filters ---
    app.jinja_env.filters['intcomma'] = intcomma_filter
    app.jinja_env.filters['floatformat'] = floatformat_filter
    logger.info("Jinja2 'intcomma' and 'floatformat' filters registered.")

    # --- Initialize DB ---
    db.init_app(app)
    migrate.init_app(app, db)

    # --- Firebase Admin SDK Init ---
    # Retrieve the entire JSON content from the environment variable
    firebase_service_account_json_str = os.environ.get('FIREBASE_SERVICE_ACCOUNT_JSON') # <--- NEW VARIABLE NAME

    try:
        # Check if Firebase Admin SDK is already initialized (e.g., in a development environment)
        try:
            firebase_admin.get_app()
            logger.info("ℹ️ Firebase Admin SDK already initialized.")
        except ValueError:
            # If not initialized, proceed to initialize it
            if firebase_service_account_json_str: # <--- CHECK IF ENV VAR IS SET
                try:
                    # Parse the JSON string into a dictionary
                    cred_dict = json.loads(firebase_service_account_json_str)
                    cred = credentials.Certificate(cred_dict) # <--- Initialize with dictionary
                    firebase_admin.initialize_app(cred)
                    logger.info("✅ Firebase Admin SDK initialized from environment variable.")
                except json.JSONDecodeError as e:
                    logger.error(f"❌ Error decoding Firebase service account JSON from environment variable: {e}")
                    flash("Firebase service account JSON is malformed.", "error")
                except Exception as e:
                    logger.error(f"❌ Firebase Admin SDK initialization failed with provided JSON: {e}")
                    flash("Firebase service account could not be initialized from provided data.", "error")
            else:
                logger.error("❌ FIREBASE_SERVICE_ACCOUNT_JSON environment variable is missing. Firebase Admin SDK will not be initialized.")
                flash("Firebase service account key is not configured.", "error")

        # After initialization (or if already initialized), get clients
        # These lines MUST be after firebase_admin.initialize_app()
        app.firebase_db = firestore.client()
        app.firebase_auth = auth
        logger.info("Firebase Firestore and Auth clients assigned to app.")

    except Exception as e:
        logger.exception(f"🔥 Firebase init error: {e}")
        app.firebase_db = None
        app.firebase_auth = None
        flash("Firebase services could not be initialized.", "error")

    # --- Register CLI Commands ---
    with app.app_context():
        from . import models
        inspector = db.inspect(db.engine)
        if not inspector.has_table("user"):
            db.create_all()
            logger.info("Database tables created.")

    @app.cli.command("create-admin")
    @click.argument("email")
    @click.argument("password")
    @click.argument("full_name")
    def create_admin_command(email, password, full_name):
        from .models import User, UserRole
        with app.app_context():
            try:
                inspector = db.inspect(db.engine)
                if not inspector.has_table("user"):
                    db.create_all()
                    logger.info("Database tables created during create-admin command.")

                if not User.query.filter_by(email=email).first():
                    hashed_pw = generate_password_hash(password)
                    admin = User(full_name=full_name, email=email, password=hashed_pw, role=UserRole.ADMIN)
                    db.session.add(admin)
                    db.session.commit()
                    logger.info(f"✅ Admin '{email}' created.")
                else:
                    logger.info(f"ℹ️ Admin '{email}' already exists.")
            except Exception as e:
                logger.error(f"❌ Error creating admin: {e}")
                traceback.print_exc()

    @app.cli.command("init-db")
    def init_db_command():
        with app.app_context():
            try:
                db.create_all()
                logger.info("✅ Database initialized.")
            except Exception as e:
                logger.error(f"❌ Failed to init DB: {e}")
                traceback.print_exc()

    # --- Register Blueprints ---
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    logger.info("Main blueprint registered.")

    return app

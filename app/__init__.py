import os
import traceback
import logging
import locale
import json
import requests
from flask import Flask, flash, current_app
from dotenv import load_dotenv
import click
import firebase_admin
from firebase_admin import credentials, firestore, auth
from firebase_admin import exceptions as fb_exceptions
from werkzeug.security import generate_password_hash

# Load environment variables
load_dotenv()

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Jinja Filters ---
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

def floatformat_filter(value, precision=2):
    try:
        return f"{float(value):.{precision}f}"
    except (ValueError, TypeError):
        return value

# --- M-Pesa Helpers ---
def get_mpesa_token():
    try:
        key = current_app.config['MPESA_CONSUMER_KEY']
        secret = current_app.config['MPESA_CONSUMER_SECRET']
        token_url = f"{current_app.config['MPESA_API_BASE_URL']}/oauth/v1/generate?grant_type=client_credentials"
        response = requests.get(token_url, auth=(key, secret))
        response.raise_for_status()
        return response.json().get('access_token')
    except Exception as e:
        current_app.logger.exception("[M-PESA ERROR] Failed to fetch token:")
        return None

def register_c2b_urls():
    access_token = get_mpesa_token()
    if not access_token:
        current_app.logger.error("[M-PESA] Token missing. Cannot register URLs.")
        return

    url = f"{current_app.config['MPESA_API_BASE_URL']}/mpesa/c2b/v1/registerurl"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    payload = {
        "ShortCode": current_app.config['MPESA_BUSINESS_SHORTCODE'],
        "ResponseType": "Completed",
        "ConfirmationURL": current_app.config['MPESA_CALLBACK_URL'],
        "ValidationURL": current_app.config['MPESA_CALLBACK_URL']
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        current_app.logger.info("[M-PESA] C2B URLs registered: %s", response.json())
    except Exception as e:
        current_app.logger.exception("[M-PESA ERROR] C2B registration failed:")

# --- App Factory ---
def create_app():
    app = Flask(__name__)

    # Flask config
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secure_fallback_secret_key_change_me_in_prod')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # M-Pesa config
    app.config['MPESA_CONSUMER_KEY'] = os.getenv('MPESA_CONSUMER_KEY')
    app.config['MPESA_CONSUMER_SECRET'] = os.getenv('MPESA_CONSUMER_SECRET')
    app.config['MPESA_API_BASE_URL'] = os.getenv('MPESA_API_BASE_URL', 'https://api.safaricom.co.ke')
    app.config['MPESA_BUSINESS_SHORTCODE'] = os.getenv('MPESA_BUSINESS_SHORTCODE')
    app.config['MPESA_PASSKEY'] = os.getenv('MPESA_PASSKEY')
    app.config['MPESA_CALLBACK_URL'] = os.getenv('MPESA_CALLBACK_URL')
    app.config['MPESA_ACCOUNT_NUMBER'] = os.getenv('MPESA_ACCOUNT_NUMBER', 'AMSA')

    # Firebase config
    app.config['FIREBASE_WEB_API_KEY'] = os.getenv('FIREBASE_WEB_API_KEY')

    # Uploads
    upload_path = os.path.join(os.path.dirname(__file__), 'static', 'uploads', 'land_images')
    os.makedirs(upload_path, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_path
    app.allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}

    def allowed_file_checker(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.allowed_extensions
    app.allowed_file = allowed_file_checker

    # Jinja filters
    app.jinja_env.filters['intcomma'] = intcomma_filter
    app.jinja_env.filters['floatformat'] = floatformat_filter
    logger.info("Jinja2 filters registered.")

    # DB init
    from .models import db, migrate
    db.init_app(app)
    migrate.init_app(app, db)

    # Firebase init
    firebase_service_account_json_str = os.environ.get('FIREBASE_SERVICE_ACCOUNT_JSON')
    try:
        try:
            firebase_admin.get_app()
            logger.info("Firebase Admin already initialized.")
        except ValueError:
            if firebase_service_account_json_str:
                cred_dict = json.loads(firebase_service_account_json_str)
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred)
                logger.info("Firebase initialized from JSON env variable.")
            else:
                logger.error("Missing FIREBASE_SERVICE_ACCOUNT_JSON.")
        app.firebase_db = firestore.client()
        app.firebase_auth = auth
    except Exception as e:
        logger.exception("Firebase init error:")
        app.firebase_db = None
        app.firebase_auth = None

    with app.app_context():
        from . import models
        inspector = db.inspect(db.engine)
        if not inspector.has_table("user"):
            db.create_all()
            logger.info("Database initialized.")
        try:
            register_c2b_urls()
        except Exception as e:
            logger.warning("Skipping C2B URL registration.")

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
                if not User.query.filter_by(email=email).first():
                    hashed_pw = generate_password_hash(password)
                    admin = User(full_name=full_name, email=email, password=hashed_pw, role=UserRole.ADMIN)
                    db.session.add(admin)
                    db.session.commit()
                    logger.info(f"Admin '{email}' created.")
                else:
                    logger.info(f"Admin '{email}' already exists.")
            except Exception as e:
                logger.error(f"Error creating admin: {e}")
                traceback.print_exc()

    @app.cli.command("init-db")
    def init_db_command():
        with app.app_context():
            try:
                db.create_all()
                logger.info("Database initialized.")
            except Exception as e:
                logger.error(f"Failed to init DB: {e}")
                traceback.print_exc()

    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    logger.info("Blueprint registered.")

    return app

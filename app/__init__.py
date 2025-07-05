import os
import traceback
import logging
import locale
import json
import base64
import datetime
import requests

from flask import Flask, current_app, jsonify, request
from dotenv import load_dotenv
import click
import firebase_admin
from firebase_admin import credentials, firestore, auth
from firebase_admin import exceptions as fb_exceptions
from werkzeug.security import generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from requests.auth import HTTPBasicAuth

# -----------------------------------------------------------
# Load environment variables
# -----------------------------------------------------------
load_dotenv()

# -----------------------------------------------------------
# Logging
# -----------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# -----------------------------------------------------------
# Initialize DB and Migrate
# -----------------------------------------------------------
db = SQLAlchemy()
migrate = Migrate()

# -----------------------------------------------------------
# Jinja Filters
# -----------------------------------------------------------
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

# -----------------------------------------------------------
# M-Pesa Helpers
# -----------------------------------------------------------
def get_mpesa_token():
    try:
        key = current_app.config['MPESA_CONSUMER_KEY']
        secret = current_app.config['MPESA_CONSUMER_SECRET']
        token_url = f"{current_app.config['MPESA_API_BASE_URL']}/oauth/v1/generate?grant_type=client_credentials"

        response = requests.get(token_url, auth=HTTPBasicAuth(key, secret))
        response.raise_for_status()

        token_data = response.json()
        token = token_data.get('access_token')

        if not token:
            current_app.logger.error("[M-PESA ERROR] No access token returned in response: %s", token_data)
            return None

        current_app.logger.info("[M-PESA] Successfully obtained access token.")
        return token

    except requests.exceptions.HTTPError as http_err:
        current_app.logger.error("[M-PESA ERROR] Token request failed with HTTP error: %s", http_err)
        if http_err.response is not None:
            current_app.logger.error("[M-PESA ERROR] Response content: %s", http_err.response.text)
        return None

    except Exception as e:
        current_app.logger.exception("[M-PESA ERROR] Failed to fetch token due to unexpected error:")
        return None

def lipa_na_mpesa(phone_number, amount):
    access_token = get_mpesa_token()
    if not access_token:
        current_app.logger.error("[M-PESA] Access token missing. Cannot proceed with STK Push.")
        return {"error": "Failed to obtain access token."}

    try:
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        shortcode = current_app.config['MPESA_BUSINESS_SHORTCODE']
        passkey = current_app.config['MPESA_PASSKEY']

        raw_password = f"{shortcode}{passkey}{timestamp}"
        encoded_password = base64.b64encode(raw_password.encode()).decode()

        url = f"{current_app.config['MPESA_API_BASE_URL']}/mpesa/stkpush/v1/processrequest"

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        payload = {
            "BusinessShortCode": shortcode,
            "Password": encoded_password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(amount),
            "PartyA": phone_number,
            "PartyB": shortcode,
            "PhoneNumber": phone_number,
            "CallBackURL": current_app.config['MPESA_CALLBACK_URL'],
            "AccountReference": current_app.config['MPESA_ACCOUNT_NUMBER'],
            "TransactionDesc": "Payment to AMSA DEVELOPERS LIMITED"
        }

        current_app.logger.info("[M-PESA] Initiating STK Push with payload: %s", payload)
        response = requests.post(url, json=payload, headers=headers)
        response.raise_for_status()

        current_app.logger.info("[M-PESA] STK Push request successful. Response: %s", response.json())
        return response.json()

    except requests.exceptions.HTTPError as http_err:
        current_app.logger.error("[M-PESA ERROR] STK Push failed with HTTP error: %s", http_err)
        if http_err.response is not None:
            current_app.logger.error("[M-PESA ERROR] Response content: %s", http_err.response.text)
        return {"error": str(http_err)}

    except Exception as e:
        current_app.logger.exception("[M-PESA ERROR] STK Push failed due to unexpected error:")
        return {"error": str(e)}

# -----------------------------------------------------------
# App Factory
# -----------------------------------------------------------
def create_app():
    app = Flask(__name__)

    # ------------------------
    # Flask config
    # ------------------------
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'a_very_secure_fallback_secret_key_change_me_in_prod')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///database.db')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # ------------------------
    # M-Pesa config
    # ------------------------
    app.config['MPESA_CONSUMER_KEY'] = os.getenv('MPESA_CONSUMER_KEY')
    app.config['MPESA_CONSUMER_SECRET'] = os.getenv('MPESA_CONSUMER_SECRET')
    app.config['MPESA_API_BASE_URL'] = os.getenv('MPESA_API_BASE_URL', 'https://api.safaricom.co.ke')
    app.config['MPESA_BUSINESS_SHORTCODE'] = os.getenv('MPESA_BUSINESS_SHORTCODE', '4167953')
    app.config['MPESA_PASSKEY'] = os.getenv('MPESA_PASSKEY')
    app.config['MPESA_CALLBACK_URL'] = os.getenv('MPESA_CALLBACK_URL')
    app.config['MPESA_ACCOUNT_NUMBER'] = os.getenv('MPESA_ACCOUNT_NUMBER', 'AMSADEVELOPERS LIMITED')

    # ------------------------
    # Firebase config
    # ------------------------
    app.config['FIREBASE_WEB_API_KEY'] = os.getenv('FIREBASE_WEB_API_KEY')

    # ------------------------
    # Uploads
    # ------------------------
    upload_path = os.path.join(os.path.dirname(__file__), 'static', 'uploads', 'land_images')
    os.makedirs(upload_path, exist_ok=True)
    app.config['UPLOAD_FOLDER'] = upload_path
    app.allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}

    def allowed_file_checker(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.allowed_extensions
    app.allowed_file = allowed_file_checker

    # ------------------------
    # Jinja filters
    # ------------------------
    app.jinja_env.filters['intcomma'] = intcomma_filter
    app.jinja_env.filters['floatformat'] = floatformat_filter
    logger.info("Jinja2 filters registered.")

    # ------------------------
    # DB init
    # ------------------------
    db.init_app(app)
    migrate.init_app(app, db)

    # ------------------------
    # Firebase init
    # ------------------------
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

    # ------------------------
    # CLI commands
    # ------------------------
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

    # ------------------------
    # Register blueprints
    # ------------------------
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint, url_prefix="/main")
    logger.info("Blueprint registered with prefix '/main'.")

    # Add a root route that redirects to login (or dashboard) to avoid empty '/'
    @app.route("/")
    def index():
        from flask import redirect, url_for
        return redirect(url_for("main.login"))

    return app


# Make db and migrate available for external import
__all__ = ["create_app", "db", "migrate"]

# functions/app/routes.py

# --- STANDARD LIBRARIES ---
import os
import io
import json
import base64
from secrets import token_hex
import traceback
import smtplib
from datetime import datetime
from urllib.parse import urlparse, urljoin
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging # Import the logging module

# --- THIRD-PARTY LIBRARIES ---
import requests
from fpdf import FPDF
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash,
    session, send_file, send_from_directory, jsonify, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import extract, func

# Import Firebase auth and firestore from firebase_admin
from firebase_admin import auth, firestore

# --- LOCAL MODULES (using relative imports for package structure) ---
from .extensions import db
from .models import User, UserRole, Investment, Land, LandPurchase, Transaction
from .utils import allowed_file, is_safe_url
from .decorators import login_required, role_required, redirect_by_role



from .forms import LoginForm

from .models import User



# --- Define Blueprint ---
main = Blueprint('main', __name__)

# --- Routes ---
#for index page
@main.route('/')
def index():
    user_id = session.get('user_id')
    if not user_id:
        return render_template('index.html')

    try:
        user_doc = current_app.firebase_db.collection('users').document(user_id).get()
        if not user_doc.exists:
            session.clear()
            flash("Session invalid. Please log in again.", "warning")
            return redirect(url_for('main.login'))

        user_data = user_doc.to_dict()
        role = user_data.get('role', '').lower()

        if role == 'investor':
            return redirect(url_for('main.dashboard_investor'))
        elif role == 'land_buyer':
            return redirect(url_for('main.dashboard_landbuyer'))
        elif role == 'admin':
            return redirect(url_for('main.dashboard_admin'))
        else:
            flash("Unrecognized user role. Please contact support.", "danger")
            session.clear()
            return redirect(url_for('main.login'))

    except Exception as e:
        current_app.logger.error("⚠️ Error in index route: %s", str(e), exc_info=True)
        flash("An error occurred. Please try again.", "danger")
        session.clear()
        return render_template('index.html')

@main.route('/register')
def register():
    return render_template('register.html')

@main.route('/api/signup', methods=['POST'])
def signup_api():
    if not current_app.firebase_db or not current_app.firebase_auth:
        return jsonify({"status": "error", "message": "Backend service not ready. Please contact support."}), 500

    data = request.get_json()
    full_name = data.get('full_name')
    email = data.get('email')
    password = data.get('password')
    id_number = data.get('id_number')
    phone_number = data.get('phone_number')
    role_str = data.get('role')
    next_of_kin_name = data.get('next_of_kin_name')
    next_of_kin_phone = data.get('next_of_kin_phone')

    required_fields = {
        'Full name': full_name,
        'Email': email,
        'Password': password,
        'ID number': id_number,
        'Phone number': phone_number,
        'Role': role_str
    }

    for field, value in required_fields.items():
        if not value:
            return jsonify({"status": "error", "message": f"{field} is required."}), 400

    if len(password) < 6:
        return jsonify({"status": "error", "message": "Password must be at least 6 characters."}), 400

    try:
        user_role = UserRole(role_str)
    except ValueError:
        return jsonify({"status": "error", "message": f"Invalid user role: {role_str}"}), 400

    def format_phone_local(phone):
        if phone:
            phone = phone.strip()
            if not phone.startswith('+'):
                if phone.startswith('07'):
                    phone = '+254' + phone[1:]
                elif phone.startswith('254'):
                    phone = '+' + phone
                else:
                    return None
            if len(phone) >= 10:
                return phone
        return None

    formatted_phone = format_phone_local(phone_number)
    if not formatted_phone:
        return jsonify({"status": "error", "message": "Invalid or missing primary phone number."}), 400

    formatted_nok_phone = format_phone_local(next_of_kin_phone) if next_of_kin_phone else None

    user_data = {
        'full_name': full_name,
        'email': email,
        'id_number': id_number,
        'phone_number': formatted_phone,
        'role': user_role.value,
        'created_at': firestore.SERVER_TIMESTAMP,
        'next_of_kin': {
            'name': next_of_kin_name or None,
            'phone': formatted_nok_phone or None
        }
    }

    if not any(user_data['next_of_kin'].values()):
        user_data['next_of_kin'] = None

    try:
        existing = current_app.firebase_db.collection('users')\
            .where(filter=firestore.FieldFilter('id_number', '==', id_number))\
            .limit(1).get()

        if existing:
            return jsonify({"status": "error", "message": "This ID Number is already registered."}), 409

        user_record = current_app.firebase_auth.create_user(
            email=email,
            password=password,
            display_name=full_name,
            phone_number=formatted_phone,
            disabled=False
        )
        uid = user_record.uid
        user_data['id'] = uid
        user_data['firebase_uid'] = uid

        current_app.firebase_db.collection('users').document(uid).set(user_data)

        new_user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(password),
            id_number=id_number,
            phone_number=formatted_phone,
            role=user_role
        )
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = uid
        session['user_role'] = user_role.value

        return jsonify({"status": "success", "message": "Registration successful! Redirecting..."}), 201

    except auth.EmailAlreadyExistsError:
        return jsonify({"status": "error", "message": "Email already in use."}), 409
    except auth.PhoneNumberAlreadyExistsError:
        return jsonify({"status": "error", "message": "Phone number already in use."}), 409
    except Exception as e:
        current_app.logger.exception("Registration failed:")
        return jsonify({"status": "error", "message": f"Registration failed: {str(e)}"}), 500



@main.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect_by_role(session.get('user_role'))

    form = LoginForm()
    next_page = request.args.get('next') or request.form.get('next')

    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        try:
            # Firebase sign-in attempt
            firebase_api_key = current_app.config['FIREBASE_WEB_API_KEY']
            login_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={firebase_api_key}"
            payload = {
                "email": email,
                "password": password,
                "returnSecureToken": True
            }

            response = requests.post(login_url, json=payload)
            result = response.json()

            if "error" not in result:
                local_id = result['localId']
                user_doc = current_app.firebase_db.collection('users').document(local_id).get()

                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    session['user_id'] = local_id
                    session['user_role'] = user_data.get('role', '').lower()

                    flash("Login successful!", "success")

                    if next_page and is_safe_url(next_page):
                        return redirect(next_page)
                    return redirect_by_role(session['user_role'])
                else:
                    current_app.logger.warning(
                        f"Firebase Auth success, but no Firestore profile for UID: {local_id}")
                    flash("Login failed. User profile not found. Please contact support.", "danger")
            else:
                error_code = result['error']['message']
                if error_code in ["EMAIL_NOT_FOUND", "INVALID_PASSWORD"]:
                    flash("Invalid email or password.", "danger")
                elif error_code == "USER_DISABLED":
                    flash("Your account has been disabled. Please contact support.", "danger")
                else:
                    current_app.logger.error("Firebase login API error: %s", error_code)
                    flash("An unexpected error occurred during login. Please try again.", "danger")

        except Exception as e:
            current_app.logger.exception("[Firebase login error]")
            flash("An error occurred during login. Please try again.", "danger")

        # Attempt local DB login fallback
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = str(user.id)
            session['user_role'] = user.role.lower() if isinstance(user.role, str) else user.role.value.lower()

            flash("Login successful!", "success")
            if next_page and is_safe_url(next_page):
                return redirect(next_page)
            return redirect_by_role(session['user_role'])
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html", form=form, next=next_page)

#for logout
@main.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('main.login'))
#for dashboard
@main.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    user_role = session.get('user_role')

    if not user_id or not user_role:
        flash("Invalid session. Please log in again.", "danger")
        session.clear()
        return redirect(url_for('main.login'))

    if user_role == 'investor':
        return redirect(url_for('main.dashboard_investor'))
    elif user_role == 'landbuyer':
        return redirect(url_for('main.dashboard_landbuyer'))
    elif user_role == 'admin':
        return redirect(url_for('main.dashboard_admin'))
    else:
        flash("Unrecognized user role.", "danger")
        session.clear()
        return redirect(url_for('main.login'))


# --- NEW: Role-Specific Dashboard Routes ---
@main.route('/dashboard/investor')
@login_required
@role_required('investor')
def dashboard_investor():
    user_id = session.get('user_id')
    user_doc = current_app.firebase_db.collection('users').document(user_id).get()
    user_data = user_doc.to_dict() if user_doc.exists else {}

    investments = Investment.query.filter_by(user_id=user_id).all()

    total_invested = sum(inv.amount for inv in investments)

    dashboard_stats = {
        'total_invested': total_invested,
    }

    return render_template(
        'dashboard_investor.html',
        user=user_data,
        investments=investments,
        dashboard_stats=dashboard_stats
    )

@main.route('/dashboard/landbuyer')
@login_required
@role_required('landbuyer')
def dashboard_landbuyer():
    user_id = session.get('user_id')
    user_doc = current_app.firebase_db.collection('users').document(user_id).get()
    user_data = user_doc.to_dict() if user_doc.exists else {}

    # Fetch user's land purchases
    land_purchases = LandPurchase.query.filter_by(user_id=user_id).all()

    # Stats Calculation
    total_invested = sum(lp.total_paid for lp in land_purchases)
    total_plots = len(land_purchases)
    pending_payments = sum(lp.balance_remaining for lp in land_purchases if lp.balance_remaining > 0)

    stats = {
        'total_invested': total_invested,
        'total_plots': total_plots,
        'pending_payments': pending_payments
    }

    # Build Monthly Payment Data
    monthly_totals = {}
    for lp in land_purchases:
        if lp.purchase_date and lp.total_paid:
            month = lp.purchase_date.strftime('%b %Y')  # e.g., 'Jun 2025'
            monthly_totals[month] = monthly_totals.get(month, 0) + lp.total_paid

    # Sort by date key
    sorted_months = sorted(monthly_totals.items(), key=lambda x: datetime.strptime(x[0], '%b %Y'))
    payment_data = {
        'labels': [item[0] for item in sorted_months],
        'amounts': [item[1] for item in sorted_months]
    }

    # Prepare recent purchases list with display fields
    recent_purchases = sorted(land_purchases, key=lambda x: x.purchase_date, reverse=True)[:5]
    enriched_purchases = []
    for lp in recent_purchases:
        enriched_purchases.append({
            'plot_name': lp.plot_name,
            'purchase_date': lp.purchase_date.strftime('%Y-%m-%d') if lp.purchase_date else 'N/A',
            'total_paid': lp.total_paid,
            'balance_remaining': lp.balance_remaining,
            'progress_percentage': round((lp.total_paid / (lp.total_paid + lp.balance_remaining)) * 100) if lp.balance_remaining + lp.total_paid > 0 else 0,
            'status': 'Paid' if lp.balance_remaining == 0 else 'Ongoing'
        })

    return render_template(
        'dashboard_landbuyer.html',
        user=user_data,
        stats=stats,
        payment_data=payment_data,
        recent_purchases=enriched_purchases
    )


@main.route('/dashboard/admin')
@login_required
@role_required('admin')
def dashboard_admin():
    all_users = User.query.all()
    recent_transactions = Transaction.query.order_by(Transaction.date.desc()).limit(10).all()

    total_investments_all_users = db.session.query(func.sum(Investment.amount)).scalar() or 0

    dashboard_stats = {
        'total_users': len(all_users),
        'total_investments_all_users': total_investments_all_users,
        'recent_transactions': recent_transactions,
    }

    return render_template(
        'dashboard_admin.html',
        all_users=all_users,
        recent_transactions=recent_transactions,
        dashboard_stats=dashboard_stats
    )
# --- END NEW: Role-Specific Dashboard Routes ---

 
@main.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password_page():
    if request.method == 'POST':
        # This route expects form data (e.g., from an HTML form without JS)
        email = request.form.get('email')
        if not email:
            flash("Please provide your email.", "warning")
            return redirect(url_for('main.forgot_password_page'))

        try:
            firebase_api_key = current_app.config.get('FIREBASE_WEB_API_KEY')
            if not firebase_api_key:
                current_app.logger.error("[ERROR] FIREBASE_WEB_API_KEY is not configured.")
                flash("Server configuration error. Please try again later.", "danger")
                return redirect(url_for('main.forgot_password_page'))

            reset_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={firebase_api_key}"
            payload = {
                "requestType": "PASSWORD_RESET",
                "email": email
            }

            response = requests.post(reset_url, json=payload)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            current_app.logger.info("[DEBUG] Firebase reset password response: %s", response.json())

            flash("If the email is registered, a password reset link has been sent.", "info")
            return redirect(url_for('main.login'))

        except requests.exceptions.HTTPError as http_e:
            # Handle Firebase specific errors more gracefully if possible
            error_data = http_e.response.json()
            error_message = error_data.get('error', {}).get('message', 'An unknown error occurred with Firebase.')
            current_app.logger.exception(f"[ERROR] Firebase API HTTP error: {error_message}")
            if "EMAIL_NOT_FOUND" in error_message:
                flash("If the email is registered, a password reset link has been sent.", "info") # Firebase's standard message for security
            else:
                flash(f"Error: {error_message}", "danger")
            return redirect(url_for('main.forgot_password_page'))
        except requests.exceptions.ConnectionError as conn_e:
            current_app.logger.exception(f"[ERROR] Network connection error to Firebase: {conn_e}")
            flash("A network error occurred. Please check your internet connection.", "danger")
            return redirect(url_for('main.forgot_password_page'))
        except requests.exceptions.Timeout as timeout_e:
            current_app.logger.exception(f"[ERROR] Firebase request timed out: {timeout_e}")
            flash("The request to the server timed out. Please try again.", "danger")
            return redirect(url_for('main.forgot_password_page'))
        except requests.exceptions.RequestException as req_e:
            current_app.logger.exception(f"[ERROR] Generic RequestException to Firebase: {req_e}")
            flash("A network error occurred. Please try again later.", "danger")
            return redirect(url_for('main.forgot_password_page'))
        except Exception as e:
            current_app.logger.exception(f"[ERROR] Unexpected error in forgot_password_page: {e}")
            flash("An unexpected error occurred. Please try again later.", "danger")
            return redirect(url_for('main.forgot_password_page'))

    return render_template('forgot_password.html')


# --- Forgot Password API Route (used by JavaScript, recommended) ---
@main.route('/api/forgot-password', methods=['POST'])
# <-- ONLY use this if you intentionally removed CSRF (consider adding CSRF for security)
def forgot_password_api():
    # It's good practice to ensure firebase_auth is initialized if it's a dependency
    # However, this specific route uses the API key directly, not a firebase_admin instance.
    # So, the `if not current_app.firebase_auth:` check might be slightly misplaced
    # if `sendOobCode` is the only action. Let's ensure the API key is present.
    firebase_api_key = current_app.config.get("FIREBASE_WEB_API_KEY")
    if not firebase_api_key:
        current_app.logger.error("[ERROR] FIREBASE_WEB_API_KEY is not configured for API route.")
        return jsonify({"status": "error", "message": "Server configuration error."}), 500

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"status": "error", "message": "Email is required."}), 400

    try:
        reset_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={firebase_api_key}"
        payload = {
            "requestType": "PASSWORD_RESET",
            "email": email
        }

        response = requests.post(reset_url, json=payload)
        response.raise_for_status() # This will catch 4xx and 5xx responses
        current_app.logger.info("[DEBUG] API Reset Response: %s", response.json())

        # Firebase's recommended behavior for security: always return a success message
        # even if the email isn't registered, to prevent user enumeration.
        return jsonify({
            'status': 'success',
            'message': 'If the email is registered, a password reset link has been sent.'
        }), 200

    except requests.exceptions.HTTPError as http_e:
        # Extract specific error message from Firebase if available
        error_data = {}
        try:
            error_data = http_e.response.json()
        except ValueError: # JSON decoding failed
            pass
        
        firebase_error_message = error_data.get('error', {}).get('message', 'An unknown error occurred with Firebase.')
        current_app.logger.exception(f"[ERROR] API Firebase HTTP error: {firebase_error_message}")

        # Specific Firebase error handling for API endpoint
        if "EMAIL_NOT_FOUND" in firebase_error_message:
            # Still return success for security, as per Firebase's recommendation
            return jsonify({"status": "success", "message": "If the email is registered, a password reset link has been sent."}), 200
        elif "INVALID_EMAIL" in firebase_error_message:
            return jsonify({"status": "error", "message": "Invalid email format."}), 400
        else:
            return jsonify({"status": "error", "message": f"Firebase error: {firebase_error_message}"}), http_e.response.status_code

    except requests.exceptions.ConnectionError as conn_e:
        current_app.logger.exception(f"[ERROR] API network connection error to Firebase: {conn_e}")
        return jsonify({"status": "error", "message": "Network error occurred. Please check your internet connection."}), 500
    except requests.exceptions.Timeout as timeout_e:
        current_app.logger.exception(f"[ERROR] API Firebase request timed out: {timeout_e}")
        return jsonify({"status": "error", "message": "The request to the server timed out. Please try again."}), 500
    except requests.exceptions.RequestException as req_e:
        current_app.logger.exception(f"[ERROR] API Generic RequestException to Firebase: {req_e}")
        return jsonify({"status": "error", "message": "A network error occurred. Please try again later."}), 500
    except Exception as e:
        current_app.logger.exception("API Reset failed with unexpected error:")
        return jsonify({"status": "error", "message": f"An unexpected error occurred: {str(e)}"}), 500



# --- Confirmation Page Route ---
@main.route('/reset-request-confirmation')
def reset_request_confirmation():
    return render_template('reset_confirmation.html')
@main.route('/pay', methods=['POST'])
def pay_api_endpoint():
    data = request.get_json()
    phone = data.get('phone')
    amount = data.get('amount')

    if not phone or amount is None:
        return jsonify({"error": "Phone and amount required"}), 400

    try:
        amount = float(amount)
    except ValueError:
        return jsonify({"error": "Invalid amount"}), 400

    current_app.logger.info(f"Received generic payment request for phone: {phone}, amount: {amount}")
    return jsonify({"status": "success", "message": "Generic payment request received."})

@main.route('/mpesa_callback', methods=['POST'])
def mpesa_callback():
    data = request.json
    current_app.logger.info("--- M-Pesa Callback Received ---")
    current_app.logger.info(json.dumps(data, indent=2))
    current_app.logger.info("---------------------------------")

    try:
        result_code = data['Body']['stkCallback']['ResultCode']
        checkout_request_id = data['Body']['stkCallback']['CheckoutRequestID']

        transaction_status = 'FAILED'
        mpesa_receipt_number = None
        amount_from_callback = None
        phone_number_from_callback = None

        if result_code == 0:
            transaction_status = 'COMPLETED'
            if 'CallbackMetadata' in data['Body']['stkCallback'] and 'Item' in data['Body']['stkCallback']['CallbackMetadata']:
                for item in data['Body']['stkCallback']['CallbackMetadata']['Item']:
                    if item['Name'] == 'MpesaReceiptNumber':
                        mpesa_receipt_number = item['Value']
                    elif item['Name'] == 'Amount':
                        amount_from_callback = item['Value']
                    elif item['Name'] == 'PhoneNumber':
                        phone_number_from_callback = item['Value']
        else:
            current_app.logger.warning(f"M-Pesa transaction failed/cancelled: ResultCode {result_code}. Desc: {data['Body']['stkCallback'].get('ResultDesc')}")

        transaction = Transaction.query.filter_by(
            checkout_request_id=checkout_request_id,
            status='PENDING'
        ).first()

        if transaction:
            transaction.status = transaction_status
            transaction.mpesa_receipt_number = mpesa_receipt_number
            if amount_from_callback:
                transaction.amount = float(amount_from_callback)
            if phone_number_from_callback:
                transaction.phone_number = phone_number_from_callback

            db.session.commit()
            current_app.logger.info(f"Transaction {transaction.id} updated to {transaction_status}. MpesaReceipt: {mpesa_receipt_number}")
        else:
            current_app.logger.warning(f"No matching PENDING transaction found for CheckoutRequestID: {checkout_request_id}. This might be a duplicate callback or a transaction that failed initial logging.")

        return jsonify({"ResultCode": 0, "ResultDesc": "Callback received successfully"}), 200

    except Exception as e:
        current_app.logger.exception(f"Error processing M-Pesa callback: {e}")
        return jsonify({"ResultCode": 1, "ResultDesc": "Error processing callback"}), 200

@main.route('/invest', methods=['GET'])
@login_required
@role_required('investor')
def invest_tiers_page():
    try:
        user_id = session.get('user_id')
        if not user_id:
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for('main.login'))

        user_doc_ref = current_app.firebase_db.collection('users').document(str(user_id))
        user_doc = user_doc_ref.get()

        if not user_doc.exists:
            flash("User not found in database. Please log in again.", "danger")
            session.clear()
            return redirect(url_for('main.login'))

        user_data = user_doc.to_dict()
        role = user_data.get('role', '')

        if role != 'investor':
            flash("Unauthorized access. Investor role required.", "danger")
            session.clear()
            return redirect(url_for('main.login'))

        return render_template('invest.html', user=user_data)

    except Exception as e:
        current_app.logger.exception(f"[ERROR] Failed to load investment tiers: {e}")
        flash("An error occurred while loading your investment options.", "danger")
        session.clear()
        return redirect(url_for('main.login'))


@main.route('/invest_form', methods=['GET', 'POST'])
@login_required
@role_required('investor')
def invest_form():
    user_id = session.get('user_id')

    if not user_id:
        session.clear()
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('main.login'))

    user_doc_ref = current_app.firebase_db.collection('users').document(str(user_id))
    user_doc = user_doc_ref.get()

    if not user_doc.exists:
        session.clear()
        flash("User not found. Please log in again.", "danger")
        return redirect(url_for('main.login'))

    user_data = user_doc.to_dict()
    phone_number = user_data.get("phone_number", "").strip()

    VALID_TIERS = ['Seed', 'Sprout', 'Harvest', 'Orchard', 'Legacy', 'Summit', 'Pinacle']

    if request.method == 'GET':
        tier = request.args.get('tier', '').strip()
        if tier not in VALID_TIERS:
            flash('Invalid or missing investment tier selected.', 'danger')
            return redirect(url_for('main.invest_tiers_page'))
        current_app.logger.info(f"[DEBUG] User {user_id} accessed tier: {tier}")
        return render_template('invest_form.html', user=user_data, tier=tier)

    if request.method == 'POST':
        try:
            data = request.get_json(force=True)
            if not data:
                return jsonify({'status': 'error', 'message': 'No data received.'}), 400

            amount_str = data.get('amount')
            tier = data.get('tier', 'Custom').strip()
            purpose = data.get('investment_purpose', '').strip()
            target_amount_str = data.get('target_amount')

            errors = []

            if tier not in VALID_TIERS:
                errors.append('Invalid investment tier selected.')

            try:
                amount = float(amount_str)
                if amount <= 0:
                    errors.append("Investment amount must be greater than zero.")
            except (ValueError, TypeError):
                errors.append("Invalid amount format.")

            target_amount = None
            if target_amount_str:
                try:
                    target_amount = float(target_amount_str)
                    if target_amount < 0:
                        errors.append("Target amount must be positive.")
                except (ValueError, TypeError):
                    errors.append("Invalid target amount format.")

            if not phone_number:
                errors.append("No phone number found in your profile.")
            else:
                if phone_number.startswith('0'):
                    phone_number = '254' + phone_number[1:]
                elif phone_number.startswith('+254'):
                    phone_number = phone_number[1:]

                if not (phone_number.startswith('2547') or phone_number.startswith('2541')) or len(phone_number) != 12:
                    errors.append("Invalid Safaricom phone number format. Must be 2547xxxxxxxxx or 2541xxxxxxxxx.")


            if errors:
                return jsonify({'status': 'error', 'errors': errors}), 400

            investment = Investment(
                user_id=user_id,
                amount=amount,
                tier=tier,
                purpose=purpose,
                date_invested=datetime.utcnow(),
                target_amount=target_amount
            )
            db.session.add(investment)
            db.session.commit()

            def get_mpesa_token():
                try:
                    key = current_app.config['MPESA_CONSUMER_KEY']
                    secret = current_app.config['MPESA_CONSUMER_SECRET']
                    token_url = f"{current_app.config['MPESA_API_BASE_URL']}/oauth/v1/generate?grant_type=client_credentials"
                    r = requests.get(token_url, auth=(key, secret))
                    r.raise_for_status()
                    return r.json().get('access_token')
                except Exception as e:
                    current_app.logger.exception("[M-PESA ERROR] Token Fetch Failed:")
                    return None

            access_token = get_mpesa_token()
            if not access_token:
                db.session.rollback()
                return jsonify({'status': 'error', 'message': 'M-Pesa access token generation failed.'}), 500

            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            shortcode = current_app.config['MPESA_BUSINESS_SHORTCODE']
            passkey = current_app.config['MPESA_PASSKEY']
            password = base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()

            stk_url = f"{current_app.config['MPESA_API_BASE_URL']}/mpesa/stkpush/v1/processrequest"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            payload = {
                "BusinessShortCode": shortcode,
                "Password": password,
                "Timestamp": timestamp,
                "TransactionType": "CustomerPayBillOnline",
                "Amount": int(amount),
                "PartyA": phone_number,
                "PartyB": shortcode,
                "PhoneNumber": phone_number,
                "CallBackURL": current_app.config['MPESA_CALLBACK_URL'],
                "AccountReference": f"AmsaInvest_{investment.id}",
                "TransactionDesc": f"Investment for {tier}"
            }

            response = requests.post(stk_url, headers=headers, json=payload)
            response.raise_for_status()
            stk_response = response.json()

            transaction = Transaction(
                user_id=user_id,
                investment_id=investment.id,
                amount=amount,
                date=datetime.utcnow(),
                description=f"STK Push for {tier} Tier",
                status="PENDING",
                phone_number=phone_number,
                merchant_request_id=stk_response.get('MerchantRequestID'),
                checkout_request_id=stk_response.get('CheckoutRequestID')
            )
            db.session.add(transaction)
            db.session.commit()

            if stk_response.get('ResponseCode') == '0':
                return jsonify({
                    'status': 'success',
                    'message': 'STK Push sent. Check your phone to complete payment.',
                    'transaction_id': transaction.id
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': stk_response.get('ResponseDescription', 'Unknown M-Pesa response.'),
                    'safaricom_response': stk_response
                }), 500

        except Exception as e:
            current_app.logger.exception("Unexpected server error during investment:")
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'Unexpected server error during investment.'}), 500


@main.route('/check_payment_status/<int:transaction_id>', methods=['GET'])
def check_payment_status(transaction_id):
    user_id = session.get('user_id')
    transaction = Transaction.query.filter_by(id=transaction_id, user_id=user_id).first()

    if not transaction:
        return jsonify({"status": "error", "message": "Transaction not found or unauthorized."}), 404

    return jsonify({"status": transaction.status})
#invest_land
@main.route('/invest_land', methods=['GET'])
@login_required
def invest_land():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)

    if not user:
        session.clear()
        flash('User session expired or invalid. Please log in again.', 'danger')
        return redirect(url_for('main.login'))

    plan_id = request.args.get('plan_id')
    if plan_id:
        return redirect(url_for('main.land_purchase_form', plan_id=plan_id))

    return render_template('invest_land.html', user=user)


@main.route('/land_purchase_form', methods=['GET', 'POST'])
@login_required
def land_purchase_form():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)

    if not user:
        session.clear()
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data received.'}), 400

        plot_location = data.get('plot_location', '').strip()
        purchase_price_str = data.get('purchase_price')
        purpose = data.get('purchase_purpose', '').strip()
        plan_id_post = data.get('plan_id', '').strip()

        errors = []

        try:
            purchase_price = float(purchase_price_str)
            if purchase_price <= 0:
                errors.append("Purchase price must be greater than zero.")
        except (ValueError, TypeError):
            errors.append("Invalid purchase price format.")

        phone_number = user.phone_number
        if not phone_number:
            errors.append("No phone number found in your profile.")
        else:
            if phone_number.startswith('0'):
                phone_number = '254' + phone_number[1:]
            elif phone_number.startswith('+254'):
                phone_number = phone_number[1:]

            if not (phone_number.startswith('2547') or phone_number.startswith('2541')) or len(phone_number) != 12:
                errors.append("Invalid Safaricom phone number format. Must be 2547xxxxxxxxx or 2541xxxxxxxxx.")

        if errors:
            return jsonify({'status': 'error', 'errors': errors}), 400

        new_purchase = LandPurchase(
            user_id=user.id,
            plot_location=plot_location,
            purchase_price=purchase_price,
            purpose=purpose
        )
        db.session.add(new_purchase)
        db.session.commit()

        def get_mpesa_access_token():
            try:
                token_url = f"{current_app.config['MPESA_API_BASE_URL']}/oauth/v1/generate?grant_type=client_credentials"
                res = requests.get(token_url, auth=(current_app.config['MPESA_CONSUMER_KEY'], current_app.config['MPESA_CONSUMER_SECRET']))
                res.raise_for_status()
                return res.json().get('access_token')
            except Exception as e:
                current_app.logger.exception("[M-PESA TOKEN ERROR]")
                return None

        access_token = get_mpesa_access_token()
        if not access_token:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'Failed to retrieve M-Pesa token.'}), 500

        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        shortcode = current_app.config['MPESA_BUSINESS_SHORTCODE']
        passkey = current_app.config['MPESA_PASSKEY']
        password = base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()

        payload = {
            "BusinessShortCode": shortcode,
            "Password": password,
            "Timestamp": timestamp,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": int(purchase_price),
            "PartyA": phone_number,
            "PartyB": shortcode,
            "PhoneNumber": phone_number,
            "CallBackURL": current_app.config['MPESA_CALLBACK_URL'],
            "AccountReference": f"LAND_{new_purchase.id}",
            "TransactionDesc": f"Land Purchase at {plot_location}"
        }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(
                f"{current_app.config['MPESA_API_BASE_URL']}/mpesa/stkpush/v1/processrequest",
                headers=headers,
                json=payload
            )
            response.raise_for_status()
            mpesa_response = response.json()

            transaction = Transaction(
                user_id=user.id,
                land_purchase_id=new_purchase.id,
                amount=purchase_price,
                date=datetime.utcnow(),
                description=f"STK Push for Land Purchase at {plot_location}",
                status="PENDING",
                phone_number=phone_number,
                merchant_request_id=mpesa_response.get('MerchantRequestID'),
                checkout_request_id=mpesa_response.get('CheckoutRequestID')
            )
            db.session.add(transaction)
            db.session.commit()

            if mpesa_response.get('ResponseCode') == '0':
                return jsonify({
                    'status': 'success',
                    'message': 'STK Push sent. Check your phone to complete payment.',
                    'transaction_id': transaction.id
                }), 200
            else:
                return jsonify({'status': 'error', 'message': mpesa_response.get('ResponseDescription')}), 500

        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("[M-PESA ERROR] STK Push failed:")
            return jsonify({'status': 'error', 'message': f'STK Push failed: {str(e)}'}), 500

    selected_plan_id = request.args.get('plan_id', '').strip()
    plan_details = {
        'daily-500': {
            'name': 'Daily Installment Plan',
            'rate': 'KES 500/day',
            'period': '36 months',
            'description': 'Daily installments for 36 months.',
            'suggested_price': 500 * 30 * 36
        },
        '90-day-5000': {
            'name': 'Short-Term Installment',
            'rate': 'KES 5,000/month',
            'period': '3 months',
            'description': 'Monthly for 3 months.',
            'suggested_price': 5000 * 3
        }
    }
    return render_template('land_purchase_form.html', user=user, selected_plan=plan_details.get(selected_plan_id))

# --- Admin Panel Routes ---
# --- Unified Admin User Management (Firebase + Local) ---
@main.route('/admin/users')
@login_required
@role_required('admin')
def manage_users():
    users = []

    # --- Local Users ---
    local_users = User.query.all()
    for user in local_users:
        users.append({
            'id': user.id,
            'full_name': user.full_name,
            'email': user.email,
            'role': user.role.value if isinstance(user.role, UserRole) else user.role, # Ensure enum is converted
            'phone_number': user.phone_number,
            'source': 'local'
        })

    # --- Firebase Users ---
    try:
        users_ref = current_app.firebase_db.collection('users')
        docs = users_ref.stream()
        for doc in docs:
            data = doc.to_dict()
            users.append({
                'id': doc.id,
                'full_name': data.get('full_name'),
                'email': data.get('email'),
                'role': data.get('role'),
                'phone_number': data.get('phone_number'),
                'source': 'firebase'
            })
    except Exception as e:
        current_app.logger.warning("⚠️ Failed to fetch Firebase users: %s", e) # Use current_app.logger
        current_app.logger.exception("Firebase Error - Manage Users:") # Log exception for full traceback

    return render_template('manage_users.html', users=users)


# --- Admin: Edit User (Local or Firebase) ---
@main.route('/admin/users/edit/<source>/<user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(source, user_id):
    current_admin_id = str(session.get('user_id')) # Ensure comparison is consistent (string)

    if source == 'local':
        user = db.session.get(User, int(user_id)) # Use db.session.get for primary key lookup
        if not user:
            flash("❌ Local user not found.", "danger")
            return redirect(url_for('main.manage_users'))

        if request.method == 'POST':
            # Convert role from form string back to UserRole enum if applicable
            requested_role = request.form.get('role')
            if requested_role:
                try:
                    requested_role_enum = UserRole(requested_role)
                except ValueError:
                    flash(f"Invalid role provided: {requested_role}", 'danger')
                    return redirect(url_for('main.edit_user', source='local', user_id=user_id))

            if str(user.id) == current_admin_id and requested_role_enum != user.role: # Compare enum values
                flash("❌ You can't change your own role.", 'danger')
                return redirect(url_for('main.edit_user', source='local', user_id=user_id))

            user.full_name = request.form.get('full_name')
            user.email = request.form.get('email')
            user.role = requested_role_enum # Assign the enum value
            user.phone_number = request.form.get('phone_number')
            user.id_number = request.form.get('id_number')
            
            # Handling next_of_kin (assuming these are direct attributes on User model)
            user.next_of_kin_name = request.form.get('next_of_kin_name')
            user.next_of_kin_phone = request.form.get('next_of_kin_phone')

            new_password = request.form.get('password')
            if new_password:
                if len(new_password) < 6:
                    flash("Password must be at least 6 characters.", "danger")
                    return redirect(url_for('main.edit_user', source='local', user_id=user_id))
                user.password = generate_password_hash(new_password)

            try:
                db.session.commit()
                flash(f'✅ {user.full_name} updated.', 'success')
                return redirect(url_for('main.manage_users'))
            except Exception as e:
                db.session.rollback()
                current_app.logger.exception("Error updating local user:") # Use current_app.logger
                flash("Error updating local user.", 'danger')

        return render_template('edit_user.html', user=user, source='local')

    elif source == 'firebase':
        doc_ref = current_app.firebase_db.collection('users').document(user_id)
        user_doc = doc_ref.get()

        if not user_doc.exists:
            flash("❌ Firebase user not found.", "danger")
            return redirect(url_for('main.manage_users'))

        data = user_doc.to_dict()

        if request.method == 'POST':
            # Check if current admin is trying to change their own Firebase role
            requested_role_firebase = request.form.get('role')
            if user_id == current_admin_id and requested_role_firebase != data.get('role'):
                flash("❌ You can't change your own role.", 'danger')
                return redirect(url_for('main.edit_user', source='firebase', user_id=user_id))

            update_data = {
                'full_name': request.form.get('full_name'),
                'email': request.form.get('email'),
                'role': requested_role_firebase, # Update role in Firestore
                'phone_number': request.form.get('phone_number')
            }
            # Firebase specific fields that might be updated
            if 'id_number' in request.form:
                update_data['id_number'] = request.form.get('id_number')
            if 'next_of_kin_name' in request.form and 'next_of_kin_phone' in request.form:
                update_data['next_of_kin'] = {
                    'name': request.form.get('next_of_kin_name'),
                    'phone': request.form.get('next_of_kin_phone')
                }
                # If both are empty, set next_of_kin to None or delete the field
                if not update_data['next_of_kin']['name'] and not update_data['next_of_kin']['phone']:
                    update_data['next_of_kin'] = None # or firestore.DELETE_FIELD for complete removal

            new_password = request.form.get('password')
            if new_password:
                if len(new_password) < 6:
                    flash("Password must be at least 6 characters.", "danger")
                    return redirect(url_for('main.edit_user', source='firebase', user_id=user_id))
                try:
                    # Update password in Firebase Auth directly
                    current_app.firebase_auth.update_user(user_id, password=new_password)
                except Exception as auth_e:
                    current_app.logger.exception(f"Error updating Firebase Auth password for {user_id}:")
                    flash(f"Error updating Firebase user password: {str(auth_e)}", 'danger')
                    return redirect(url_for('main.edit_user', source='firebase', user_id=user_id))


            try:
                doc_ref.update(update_data) # Update Firestore document
                flash("✅ Firebase user updated.", "success")
                return redirect(url_for('main.manage_users'))
            except Exception as e:
                current_app.logger.exception("Error updating Firebase user:") # Use current_app.logger
                flash("Error updating Firebase user.", 'danger')

        return render_template('edit_user.html', user=data, user_id=user_id, source='firebase')

    flash("❌ Unknown user source.", 'danger')
    return redirect(url_for('main.manage_users'))


@main.route('/admin/users/delete/<source>/<user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(source, user_id):
    current_admin_id = str(session.get('user_id'))

    if source == 'local':
        user = db.session.get(User, int(user_id)) # Use db.session.get
        if not user:
            flash("❌ Local user not found.", "danger")
            return redirect(url_for('main.manage_users'))

        if str(user.id) == current_admin_id:
            flash("❌ You can't delete your own account.", 'danger')
            return redirect(url_for('main.manage_users'))

        try:
            db.session.delete(user)
            db.session.commit()
            flash(f"🗑️ {user.full_name} deleted.", "success")
        except Exception as e:
            db.session.rollback()
            current_app.logger.exception("Error deleting local user:") # Use current_app.logger
            flash("Error deleting local user.", 'danger')

    elif source == 'firebase':
        if user_id == current_admin_id:
            flash("❌ You can't delete your own Firebase account.", 'danger')
            return redirect(url_for('main.manage_users'))

        try:
            current_app.firebase_db.collection('users').document(user_id).delete() # Delete Firestore doc
            current_app.firebase_auth.delete_user(user_id) # Also delete from Firebase Auth
            flash("🗑️ Firebase user deleted.", "success")
        except Exception as e:
            current_app.logger.exception("Error deleting Firebase user:") # Use current_app.logger
            flash("Error deleting Firebase user.", 'danger')

    else:
        flash("❌ Unknown user source.", 'danger')

    return redirect(url_for('main.manage_users'))

import csv # Moved import to the top of the file if not already there, or keep here if specific
from flask import Response # Moved import to the top of the file if not already there, or keep here if specific

@main.route('/admin/users/export/csv')
@login_required
@role_required('admin')
def export_users_csv():
    users = User.query.all()

    def generate():
        data_rows = []
        header = ['ID', 'Full Name', 'Email', 'Role', 'ID Number', 'Phone']
        data_rows.append(header)

        for u in users:
            data_rows.append([
                u.id,
                u.full_name,
                u.email,
                u.role.value if isinstance(u.role, UserRole) else u.role, # Handle enum or string
                u.id_number or '',
                u.phone_number or ''
            ])

        # Use io.StringIO to write CSV data to an in-memory file
        csv_buffer = io.StringIO()
        csv_writer = csv.writer(csv_buffer)
        csv_writer.writerows(data_rows)
        csv_buffer.seek(0) # Rewind to the beginning

        yield csv_buffer.read()

    return Response(
        generate(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=am_users.csv"}
    )

@main.route('/admin/firebase/reset-password/<user_id>')
@login_required
@role_required('admin')
def reset_firebase_password(user_id):
    try:
        firebase_auth = current_app.firebase_auth # Use current_app
        # Note: firebase_link is not needed if using firebase_admin.auth directly for send_password_reset_email
        # firebase_link = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={current_app.config['FIREBASE_WEB_API_KEY']}"

        # Get user email from Firestore
        user_doc = current_app.firebase_db.collection('users').document(user_id).get() # Use current_app
        if not user_doc.exists:
            flash("🚫 Firebase user not found.", "danger")
            return redirect(url_for('main.manage_users'))

        user_email = user_doc.to_dict().get('email')
        if not user_email:
            flash("⚠️ User has no email to send reset link.", "warning")
            return redirect(url_for('main.manage_users'))

        # Send password reset email using Firebase Admin SDK
        firebase_auth.send_password_reset_email(user_email)
        flash(f"✅ Password reset email sent to {user_email}.", "success")

    except Exception as e:
        current_app.logger.exception("[Reset Firebase Password Error]") # Use current_app.logger
        flash("⚠️ Failed to send reset email.", "danger")

    return redirect(url_for('main.manage_users'))



@main.route('/admin/land', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def manage_land():
    if request.method == 'POST':
        plot_reference = request.form['plot_reference']
        location = request.form['location']
        
        try:
            size_acres = float(request.form['size_acres'])
            price_kes = float(request.form['price_kes'])
        except ValueError:
            flash('Size acres and Price must be valid numbers.', 'danger')
            return redirect(url_for('main.manage_land')) # Corrected redirect for blueprint

        description = request.form.get('description')
        
        # Handle file upload
        if 'image' not in request.files:
            flash('No image part in the request', 'danger')
            return redirect(url_for('main.manage_land')) # Corrected redirect

        file = request.files['image']
        
        if file.filename == '':
            flash('No selected image', 'danger')
            return redirect(url_for('main.manage_land')) # Corrected redirect
            
        if file and current_app.allowed_file(file.filename): # Use current_app.allowed_file
            filename = secure_filename(file.filename)
            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], unique_filename) # Use current_app.config
            
            try:
                file.save(file_path)
            except Exception as e:
                current_app.logger.exception(f"Failed to save image file: {e}") # Use current_app.logger
                flash(f"Failed to save image file: {e}", 'danger')
                return redirect(url_for('main.manage_land')) # Corrected redirect

            new_land = Land(
                plot_reference=plot_reference,
                location=location,
                size_acres=size_acres,
                price_kes=price_kes,
                description=description,
                image_filename=unique_filename
            )
            db.session.add(new_land)
            db.session.commit()
            flash('Land plot added successfully!', 'success')
            return redirect(url_for('main.manage_land')) # Corrected redirect
        else:
            flash('Allowed image types are png, jpg, jpeg, gif', 'danger')
            return redirect(url_for('main.manage_land')) # Corrected redirect

    land_listings = Land.query.all()
    return render_template('manage_land.html', land_listings=land_listings)

# Route to serve uploaded images (important for development, Render handles static files automatically)
@main.route('/static/uploads/land_images/<filename>')
def uploaded_file(filename):
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename) # Use current_app.config

@main.route('/admin/investments')
@login_required
@role_required('admin')
def manage_investments():
    all_investments = Investment.query.all()
    
    investment_details = []
    for inv in all_investments:
        total_paid_for_inv = db.session.query(db.func.sum(Transaction.amount)).filter(
            Transaction.investment_id == inv.id,
            Transaction.user_id == inv.user_id,
            Transaction.status == 'COMPLETED'
        ).scalar() or 0

        balance_remaining = None
        if inv.target_amount is not None:
            balance_remaining = inv.target_amount - total_paid_for_inv
            if balance_remaining < 0:
                balance_remaining = 0
            
        progress_percentage = 0
        if inv.target_amount and inv.target_amount > 0:
            progress_percentage = (total_paid_for_inv / inv.target_amount) * 100
            if progress_percentage > 100:
                progress_percentage = 100
        
        investment_details.append({
            'investment': inv,
            'investor': inv.investor,
            'total_paid': total_paid_for_inv,
            'balance_remaining': balance_remaining,
            'progress_percentage': progress_percentage
        })

    return render_template('manage_investments.html', investment_details=investment_details)

@main.route('/admin/send_reminder/<int:investment_id>')
@login_required
@role_required('admin')
def send_payment_reminder(investment_id):
    investment = Investment.query.get_or_404(investment_id)
    investor = investment.investor

    if not investor or not investor.email:
        flash(f'Cannot send reminder: Investor for investment ID {investment_id} not found or has no email.', 'danger')
        return redirect(url_for('main.manage_investments'))

    total_paid_for_inv = db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.investment_id == investment.id,
        Transaction.user_id == investment.user_id,
        Transaction.status == 'COMPLETED'
    ).scalar() or 0

    balance_remaining = None
    if investment.target_amount is not None:
        balance_remaining = investment.target_amount - total_paid_for_inv
        if balance_remaining < 0:
            balance_remaining = 0

    if balance_remaining is None or balance_remaining <= 0:
        flash(f'Investment ID {investment_id} has no target or goal already met. No reminder sent.', 'info')
        return redirect(url_for('main.manage_investments'))

    subject = f"Payment Reminder for Your Investment with AMSA Developers (ID: {investment.id})"
    # Ensure MAIL_DEFAULT_SENDER, MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD are configured in app.config
    # (usually in __init__.py or a config file)
    body = f"""
    Dear {investor.full_name},

    This is a friendly reminder about your investment (ID: {investment.id}, Tier: {investment.tier}) with AMSA Developers.

    Your target investment goal is KES {investment.target_amount:,.2f}.
    You have currently paid KES {total_paid_for_inv:,.2f}.
    The remaining balance to meet your goal is KES {balance_remaining:,.2f}.

    You can make payments through M-Pesa by logging into your dashboard and initiating a new investment transaction.

    Thank you for your continued trust in AMSA Developers.

    Best regards,
    The AMSA Developers Team
    """
    
    try:
        msg = MIMEMultipart()
        msg['From'] = current_app.config['MAIL_DEFAULT_SENDER'] # Use current_app.config
        msg['To'] = investor.email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(current_app.config['MAIL_SERVER'], current_app.config['MAIL_PORT']) as server: # Use current_app.config
            server.starttls()
            server.login(current_app.config['MAIL_USERNAME'], current_app.config['MAIL_PASSWORD']) # Use current_app.config
            server.send_message(msg)
        
        flash(f'Payment reminder sent successfully to {investor.email} for investment ID {investment.id}!', 'success')
    except Exception as e:
        flash(f'Failed to send payment reminder: {e}', 'danger')
        current_app.logger.exception(f"Email sending error for investment ID {investment.id} to {investor.email}:") # Use current_app.logger
        
    return redirect(url_for('main.manage_investments'))


@main.route('/admin/transactions')
@login_required
@role_required('admin')
def view_transactions():
    transactions = Transaction.query.join(User).order_by(Transaction.date.desc()).all()
    return render_template('view_transactions.html', transactions=transactions)

@main.route('/admin/transactions/download_receipt/<int:txn_id>')
@login_required
@role_required('admin')
def download_receipt(txn_id):
    transaction = Transaction.query.get_or_404(txn_id)
    user = transaction.user_rel

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(0, 10, txt="Transaction Receipt", ln=True, align='C')
    pdf.ln(10)

    local_datetime = transaction.date

    pdf.set_font("Arial", 'B', size=12)
    pdf.cell(0, 10, txt=f"Transaction ID: {transaction.id}", ln=True)
    pdf.cell(0, 10, txt=f"Date: {local_datetime.strftime('%Y-%m-%d')}", ln=True)
    pdf.cell(0, 10, txt=f"Time: {local_datetime.strftime('%H:%M:%S')}", ln=True)
    pdf.cell(0, 10, txt=f"Day: {local_datetime.strftime('%A')}", ln=True)
    pdf.cell(0, 10, txt=f"Amount: KES {transaction.amount:,.2f}", ln=True)
    pdf.cell(0, 10, txt=f"Description: {transaction.description or 'N/A'}", ln=True)
    pdf.cell(0, 10, txt=f"Status: {transaction.status}", ln=True)
    pdf.cell(0, 10, txt=f"M-Pesa Receipt: {transaction.mpesa_receipt_number or 'N/A'}", ln=True)
    
    pdf.ln(5)
    pdf.set_font("Arial", 'U', size=12)
    pdf.cell(0, 10, txt="Transaction Details:", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, txt=f"Transacted by: {user.full_name} ({user.email})", ln=True)
    pdf.cell(0, 10, txt=f"Phone Number: {transaction.phone_number or 'N/A'}", ln=True)
    pdf.cell(0, 10, txt=f"Method of Payment: M-Pesa", ln=True)

    if transaction.investment_id:
        investment = transaction.investment
        if investment:
            pdf.ln(5)
            pdf.set_font("Arial", 'U', size=12)
            pdf.cell(0, 10, txt="Associated Investment:", ln=True)
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 10, txt=f"Investment ID: {investment.id}", ln=True)
            pdf.cell(0, 10, txt=f"Investment Tier: {investment.tier}", ln=True)
            pdf.cell(0, 10, txt=f"Investment Purpose: {investment.purpose or 'N/A'}", ln=True)
            if investment.target_amount:
                pdf.cell(0, 10, txt=f"Target Amount: KES {investment.target_amount:,.2f}", ln=True)


    pdf_output = io.BytesIO()
    pdf.output(pdf_output, dest='S')
    pdf_output.seek(0)

    filename = f"transaction_receipt_{txn_id}.pdf"
    return send_file(pdf_output, as_attachment=True, download_name=filename, mimetype='application/pdf')


# --- Other informational routes ---
@main.route('/buy-land')
def buy_land():
    available_land = Land.query.filter_by(status='Available').all()
    return render_template('buy_land.html', land_listings=available_land)

@main.route('/available_land') # Changed from @app.route('/') to avoid conflict with main.index
def available_land():
    """
    Renders the available land listings page, fetching data from the database.
    """
    land_listings = Land.query.order_by(Land.added_date.desc()).all()
    return render_template('available_land.html', land_listings=land_listings)

@main.route('/microfinance', methods=['GET', 'POST'])
def microfinance():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        if not name or not email or not message:
            flash('Please fill in all required fields (Name, Email, Message).', 'error')
            return render_template('microfinance.html')

        try:
            msg = MIMEMultipart()
            msg['From'] = current_app.config.get('MAIL_DEFAULT_SENDER') # Use current_app.config.get for safety
            msg['To'] = 'amsavillage@gmail.com'
            msg['Subject'] = f"New Message from Microfinance Contact Form: {subject}"

            body = f"Name: {name}\n" \
                    f"Email: {email}\n" \
                    f"Subject: {subject}\n\n" \
                    f"Message:\n{message}"
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(current_app.config.get('MAIL_SERVER'), current_app.config.get('MAIL_PORT')) as server: # Use current_app.config.get
                server.starttls()
                server.login(current_app.config.get('MAIL_USERNAME'), current_app.config.get('MAIL_PASSWORD')) # Use current_app.config.get
                server.send_message(msg)

            flash('Your message has been sent successfully!', 'success')
            return redirect(url_for('main.microfinance') + '#contact')
        except Exception as e:
            flash(f'An error occurred while sending your message: {e}', 'error')
            current_app.logger.exception(f"Error sending microfinance contact email: {e}") # Use current_app.logger
            return render_template('microfinance.html')

    return render_template('microfinance.html')

@main.route('/about')
def about():
    return render_template('about.html')

@main.route('/contact')
def contact():
    return render_template('contact.html')
@main.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    if not user_id:
        flash('Session expired. Please log in again.', 'warning')
        return redirect(url_for('main.logout'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('main.logout'))

    if request.method == 'POST':
        user.full_name = request.form.get('full_name')
        user.email = request.form.get('email')
        user.id_number = request.form.get('id_number')
        user.phone_number = request.form.get('phone_number')
        user.next_of_kin_name = request.form.get('next_of_kin_name')
        user.next_of_kin_phone = request.form.get('next_of_kin_phone')

        # Validate phone number
        if user.phone_number and not (
            (user.phone_number.startswith('07') or user.phone_number.startswith('254')) and len(user.phone_number) >= 9
        ):
            flash('Invalid primary phone number format. Must start with 07 or 254.', 'danger')
            return redirect(url_for('main.profile'))

        if user.next_of_kin_phone and not (
            (user.next_of_kin_phone.startswith('07') or user.next_of_kin_phone.startswith('254')) and len(user.next_of_kin_phone) >= 9
        ):
            flash('Invalid Next of Kin phone number format. Must start with 07 or 254.', 'danger')
            return redirect(url_for('main.profile'))

        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')

        return redirect(url_for('main.profile'))

    return render_template('profile.html', user=user)
@main.route('/generate-pdf')
@login_required 
def generate_pdf():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('main.dashboard'))

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="User Profile Report", ln=True, align='C')
    pdf.ln(10)

    pdf.cell(200, 10, txt=f"Full Name: {user.full_name}", ln=True)
    pdf.cell(200, 10, txt=f"Email: {user.email}", ln=True)
    pdf.cell(200, 10, txt=f"Phone Number: {user.phone_number if user.phone_number else 'N/A'}", ln=True)
    pdf.cell(200, 10, txt=f"ID Number: {user.id_number if user.id_number else 'N/A'}", ln=True)
    pdf.cell(200, 10, txt=f"Role: {user.role.capitalize()}", ln=True)

    if user.next_of_kin_name:
        pdf.cell(200, 10, txt=f"Next of Kin: {user.next_of_kin_name}", ln=True)
    if user.next_of_kin_phone:
        pdf.cell(200, 10, txt=f"Next of Kin Phone: {user.next_of_kin_phone}", ln=True)

    # Role-specific details
    if user.role == 'investor':
        pdf.ln(10)
        pdf.set_font("Arial", 'B', size=14)
        pdf.cell(200, 10, txt="Investor Details", ln=True, align='L')
        pdf.set_font("Arial", size=12)

        latest_investment = Investment.query.filter_by(user_id=user.id).order_by(Investment.date_invested.desc()).first()
        if latest_investment:
            pdf.cell(200, 10, txt=f"Latest Investment Amount: KES {latest_investment.amount:,.2f}", ln=True)
            pdf.cell(200, 10, txt=f"Investment Tier: {latest_investment.tier}", ln=True)
            pdf.cell(200, 10, txt=f"Investment Purpose: {latest_investment.purpose if latest_investment.purpose else 'N/A'}", ln=True)
            if latest_investment.target_amount:
                pdf.cell(200, 10, txt=f"Investment Target: KES {latest_investment.target_amount:,.2f}", ln=True)
        else:
            pdf.cell(200, 10, txt="No investment details found.", ln=True)

    elif user.role == 'landbuyer':
        pdf.ln(10)
        pdf.set_font("Arial", 'B', size=14)
        pdf.cell(200, 10, txt="Land Buyer Details", ln=True, align='L')
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt=f"Client Name (Reg): {user.full_name}", ln=True)
        pdf.cell(200, 10, txt=f"Client ID (Reg): {user.id_number if user.id_number else 'N/A'}", ln=True)
        pdf.cell(200, 10, txt=f"Client Phone (Reg): {user.phone_number if user.phone_number else 'N/A'}", ln=True)
        pdf.cell(200, 10, txt=f"Client Email (Reg): {user.email}", ln=True)

    # Stream PDF as response
    pdf_output = io.BytesIO()
    pdf.output(pdf_output, dest='S')
    pdf_output.seek(0)

    filename = f"profile_{user.id}.pdf"
    return send_file(pdf_output, as_attachment=True, download_name=filename, mimetype='application/pdf')

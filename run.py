from werkzeug.utils import secure_filename  # ✅ this line fixes the error
import base64
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import io
import os
import smtplib
import traceback
import click
from flask import Flask, json, send_file, send_from_directory
from firebase_admin import auth, firestore
from flask.cli import with_appcontext
from fpdf import FPDF
from app import create_app, db
from app.models import Investment, Transaction
from app.decorators import login_required, redirect_by_role, role_required  # factory method & db instance
from main import main as main_blueprint
# --- Create Flask App ---
app = create_app()
main = app  # For Firebase Cloud Function

# --- Firebase Admin User Setup ---
with app.app_context():
    print("--- Firebase Admin Setup ---")

    admin_email = os.getenv('FIREBASE_ADMIN_EMAIL')
    admin_password = os.getenv('FIREBASE_ADMIN_PASSWORD')
    admin_full_name = os.getenv('FIREBASE_ADMIN_FULL_NAME')
    admin_id = os.getenv('FIREBASE_ADMIN_ID')
    firestore_users = app.firebase_db.collection('users') if app.firebase_db else None

    try:
        if not admin_email or not admin_password:
            raise ValueError("Missing Firebase admin credentials.")

        if app.firebase_auth is None:
            raise Exception("Firebase Auth not initialized")

        try:
            existing_user = auth.get_user_by_email(admin_email)
            print(f"✅ Firebase Auth user exists: {admin_email}")
        except auth.UserNotFoundError:
            print("⚠️ Admin not found. Creating...")
            existing_user = auth.create_user(
                email=admin_email,
                password=admin_password,
                display_name=admin_full_name or "Admin User"
            )
            print(f"✅ Firebase Admin created: {admin_email}")

        if firestore_users:
            user_doc_ref = firestore_users.document(existing_user.uid)
            if not user_doc_ref.get().exists:
                user_doc_ref.set({
                    "full_name": admin_full_name,
                    "email": admin_email,
                    "id_number": admin_id,
                    "role": "admin",
                    "created_at": firestore.SERVER_TIMESTAMP
                })
                print("✅ Admin Firestore doc created.")
            else:
                print("ℹ️ Admin Firestore doc already exists.")
        else:
            print("⚠️ Firestore not initialized. Skipping user doc.")
    except Exception as e:
        print(f"❌ Firebase setup error: {e}")
        traceback.print_exc()

    print("--- Firebase Admin Setup Complete ---")

# --- M-PESA Config ---
app.config['MPESA_CONSUMER_KEY'] = os.environ.get('MPESA_CONSUMER_KEY')
app.config['MPESA_CONSUMER_SECRET'] = os.environ.get('MPESA_CONSUMER_SECRET')
app.config['MPESA_BUSINESS_SHORTCODE'] = os.environ.get('MPESA_BUSINESS_SHORTCODE')
app.config['MPESA_PASSKEY'] = os.environ.get('MPESA_PASSKEY')
app.config['MPESA_ENV'] = os.environ.get('MPESA_ENV')
app.config['MPESA_CALLBACK_URL'] = os.environ.get('MPESA_CALLBACK_URL')
app.config['MPESA_API_BASE_URL'] = (
    'https://sandbox.safaricom.co.ke'
    if app.config['MPESA_ENV'] == 'sandbox'
    else 'https://api.safaricom.co.ke'
)
MPESA_PAYBILL = os.getenv("MPESA_PAYBILL")
MPESA_ACCOUNT = os.getenv("MPESA_ACCOUNT")

# --- Email Config ---
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS') == 'True'
app.config['MAIL_USE_SSL'] = os.environ.get('MAIL_USE_SSL') == 'True'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

# --- File Upload Setup ---
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads', 'land_images')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = ALLOWED_EXTENSIONS
app.allowed_file = allowed_file  # attach utility

# --- Firebase API Key for Client SDK ---
app.config['FIREBASE_WEB_API_KEY'] = os.getenv('FIREBASE_WEB_API_KEY')

# --- Secret Key ---
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')



@app.route('/')
def index():
    """
    Homepage route. If user is logged in, redirect based on role.
    Otherwise, show the public homepage.
    """
    user_id = session.get('user_id')
    if not user_id:
        return render_template('index.html')  # Not logged in — show homepage

    try:
        # ✅ Try to get role from Firebase Firestore
        user_doc = app.firebase_db.collection('users').document(user_id).get()

        if not user_doc.exists:
            session.clear()
            flash("Session invalid. Please log in again.", "warning")
            return redirect(url_for('login'))

        user_data = user_doc.to_dict()
        role = user_data.get('role', '').lower()

        if role == 'investor':
            return redirect(url_for('dashboard_investor'))
        elif role == 'land_buyer':  # ✅ Correct role check
            return redirect(url_for('dashboard_landbuyer'))
        else:
            flash("Unrecognized user role. Please contact support.", "danger")
            session.clear()
            return redirect(url_for('index'))

    except Exception as e:
        print("⚠️ Error in index route:", str(e))
        flash("An error occurred. Please try again.", "danger")
        session.clear()
        return render_template('index.html')  # Safe fallback if error



    
@app.route('/register', methods=['GET'])
def register_page():
    """Render the user registration page."""
    return render_template('register.html')


from werkzeug.security import generate_password_hash
from app.models import Land, LandPurchase, User, UserRole  # Ensure your User SQLAlchemy model is imported

@app.route('/api/signup', methods=['POST'])
def signup_api():
    if not app.firebase_db or not app.firebase_auth:
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
        'Full name': full_name, 'Email': email, 'Password': password,
        'ID number': id_number, 'Phone number': phone_number, 'Role': role_str
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

    def format_phone(phone):
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

    formatted_phone = format_phone(phone_number)
    if not formatted_phone:
        return jsonify({"status": "error", "message": "Invalid or missing primary phone number."}), 400

    formatted_nok_phone = format_phone(next_of_kin_phone)

    user_data = {
        'full_name': full_name,
        'email': email,
        'id_number': id_number,
        'phone_number': formatted_phone,
        'role': user_role.value,
        'created_at': firestore.SERVER_TIMESTAMP,
        'next_of_kin': {
            'name': next_of_kin_name if next_of_kin_name else None,
            'phone': formatted_nok_phone if formatted_nok_phone else None
        }
    }

    if not any(user_data['next_of_kin'].values()):
        user_data['next_of_kin'] = None

    # --- Optional details ---
    if user_role == UserRole.INVESTOR:
        try:
            investment_amount = float(data.get('investmentAmount', 0))
            if investment_amount < 0:
                raise ValueError
        except (TypeError, ValueError):
            return jsonify({"status": "error", "message": "Invalid investment amount."}), 400

        tenure = data.get('tenure')
        payout = data.get('payout')
        payment_mode = data.get('paymentModeInvestor')

        if not all([tenure, payout, payment_mode]):
            return jsonify({"status": "error", "message": "Missing investor details."}), 400

        user_data['investor_details'] = {
            'investment_amount': investment_amount,
            'tenure': tenure,
            'payout_frequency': payout,
            'payment_mode': payment_mode
        }

    elif user_role == UserRole.LANDBUYER:
        location = data.get('location')
        client_name = data.get('clientName')
        client_id = data.get('clientID')
        client_phone = data.get('clientPhone')
        client_email = data.get('clientEmail')

        if not all([location, client_name, client_id, client_phone, client_email]):
            return jsonify({"status": "error", "message": "Missing land buyer contact info."}), 400

        user_data['landbuyer_details'] = {
            'plot_reference': data.get('plotReference') or None,
            'desired_location': location,
            'client_inquiry_name': client_name,
            'client_inquiry_id': client_id,
            'client_inquiry_phone': client_phone,
            'client_inquiry_email': client_email
        }

    try:
        existing = app.firebase_db.collection('users')\
            .where(filter=firestore.FieldFilter('id_number', '==', id_number))\
            .limit(1).get()

        if existing:
            return jsonify({"status": "error", "message": "This ID Number is already registered."}), 409

        user_record = app.firebase_auth.create_user(
            email=email,
            password=password,
            display_name=full_name,
            phone_number=formatted_phone if formatted_phone else None,
            disabled=False
        )
        uid = user_record.uid
        user_data['id'] = uid
        user_data['firebase_uid'] = uid

        # ✅ Save in Firebase
        app.firebase_db.collection('users').document(uid).set(user_data)

        # ✅ Save in local SQL DB
        from app import db  # Import db here if not already at the top
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
        return jsonify({"status": "error", "message": f"Registration failed: {str(e)}"}), 500
from werkzeug.security import check_password_hash
from app.models import User
from urllib.parse import urlparse, urljoin
from flask import request, redirect, session, url_for, render_template, flash
import requests

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        # Already logged in, redirect based on role
        return redirect_by_role(session.get('user_role'))

    next_page = request.args.get('next') or request.form.get('next')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Please enter both email and password.", "danger")
            return render_template('login.html', next=next_page)

        try:
            # Firebase authentication
            firebase_api_key = app.config['FIREBASE_WEB_API_KEY']
            login_url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={firebase_api_key}"
            payload = {"email": email, "password": password, "returnSecureToken": True}

            response = requests.post(login_url, json=payload)
            result = response.json()

            if "error" not in result:
                local_id = result['localId']
                user_doc = app.firebase_db.collection('users').document(local_id).get()

                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    session['user_id'] = local_id
                    session['user_role'] = user_data.get('role', '').lower()

                    flash("Login successful!", "success")

                    if next_page and is_safe_url(next_page):
                        return redirect(next_page)

                    return redirect_by_role(session['user_role'])

        except Exception as e:
            print("[Firebase login error]", e)

        # Fallback to local DB
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = str(user.id)
            session['user_role'] = user.role.lower() if isinstance(user.role, str) else user.role.value.lower()

            flash("Login successful!", "success")

            if next_page and is_safe_url(next_page):
                return redirect(next_page)

            return redirect_by_role(session['user_role'])

        flash("Invalid email or password.", "danger")
        return render_template('login.html', next=next_page)

    return render_template('login.html', next=next_page)


# --- LOGOUT ROUTE ---
@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))
# --- BASE DASHBOARD REDIRECT ROUTE ---
@app.route('/dashboard')
@login_required
def dashboard():
    user_id = session.get('user_id')
    user_role = session.get('user_role')

    if not user_id or not user_role:
        flash("Invalid session. Please log in again.", "danger")
        session.clear()
        return redirect(url_for('login'))

    if user_role == 'investor':
        return redirect(url_for('dashboard_investor'))
    elif user_role == 'landbuyer':
        return redirect(url_for('dashboard_landbuyer'))
    elif user_role == 'admin':
        return redirect(url_for('dashboard_admin'))  # Make sure this route exists
    else:
        flash("Unrecognized user role.", "danger")
        session.clear()
        return redirect(url_for('login'))

# --- ADMIN DASHBOARD ROUTE ---
@app.route('/dashboard/admin')
@login_required
@role_required('admin')
def dashboard_admin():
    total_users = User.query.count()
    total_investors = User.query.filter_by(role='investor').count()
    total_landbuyers = User.query.filter_by(role='landbuyer').count()
    total_transactions = Transaction.query.count()

    total_revenue = db.session.query(
        db.func.coalesce(db.func.sum(Transaction.amount), 0)
    ).filter_by(status='COMPLETED').scalar()

    active_investments = Investment.query.count()

    # Outstanding balance calculation
    total_outstanding_balance = 0
    investments = Investment.query.filter(Investment.target_amount.isnot(None)).all()

    for inv in investments:
        total_paid = db.session.query(
            db.func.coalesce(db.func.sum(Transaction.amount), 0)
        ).filter_by(investment_id=inv.id, user_id=inv.user_id, status='COMPLETED').scalar()

        if inv.target_amount > total_paid:
            total_outstanding_balance += (inv.target_amount - total_paid)

    # 🔍 Show all registered users
    users = User.query.order_by(User.created_at.desc()).all()

    return render_template('dashboard_admin.html', **{
        "total_users": total_users,
        "total_investors": total_investors,
        "total_landbuyers": total_landbuyers,
        "total_transactions": total_transactions,
        "total_revenue": total_revenue,
        "active_investments": active_investments,
        "total_outstanding_balance": total_outstanding_balance,
        "users": users
    })
# --- INVESTOR DASHBOARD ROUTE ---
@app.route('/dashboard/investor')
@login_required
@role_required('investor')
def dashboard_investor():
    user_id = session.get('user_id')  # This is the Firebase UID

    # 🔥 Skipping User.query.get(user_id)

    # Fetch investments and transactions linked to Firebase UID
    investments = Investment.query.filter_by(user_id=user_id).order_by(Investment.date_invested.desc()).all()
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date.desc()).all()

    total_invested = db.session.query(
        db.func.coalesce(db.func.sum(Transaction.amount), 0)
    ).filter_by(user_id=user_id, status='COMPLETED').scalar()

    investment_data = []
    for inv in investments:
        total_paid = db.session.query(
            db.func.coalesce(db.func.sum(Transaction.amount), 0)
        ).filter_by(user_id=user_id, investment_id=inv.id, status='COMPLETED').scalar()

        target = inv.target_amount or 0
        balance_remaining = max(0, target - total_paid)
        progress = min(100, (total_paid / target * 100) if target else 0)

        investment_data.append({
            'investment': inv,
            'total_paid': total_paid,
            'balance_remaining': balance_remaining,
            'progress_percentage': round(progress, 2)
        })

    return render_template('dashboard_investor.html', data={
        'total_invested': total_invested,
        'active_investments_count': len(investments),
        'expected_payouts': 0,
        'balance_remaining': sum(item['balance_remaining'] for item in investment_data),
        'investments': investment_data,
        'transactions': transactions,
        'total_earned_interest': 0  # placeholder
    })

# --- LAND BUYER DASHBOARD ROUTE ---
@app.route('/dashboard/landbuyer')
@login_required
@role_required('landbuyer')
def dashboard_landbuyer():
    from sqlalchemy import extract, func

    user_id = session.get('user_id')  # Firebase UID

    # Fetch all completed and pending transactions for the user
    transactions = Transaction.query.filter_by(user_id=user_id).order_by(Transaction.date.desc()).all()

    # Fetch all land purchases
    purchases = LandPurchase.query.filter_by(user_id=user_id).order_by(LandPurchase.purchase_date.desc()).all()

    # Calculate total invested (completed transactions only)
    total_invested = db.session.query(
        func.coalesce(func.sum(Transaction.amount), 0)
    ).filter_by(user_id=user_id, status='COMPLETED').scalar()

    # Calculate total pending payments
    pending_payments = db.session.query(
        func.coalesce(func.sum(Transaction.amount), 0)
    ).filter_by(user_id=user_id, status='PENDING').scalar()

    # Prepare detailed land purchase data
    land_data = []
    for purchase in purchases:
        land = purchase.land
        land_price = getattr(land, 'price', 0) or 0

        total_paid = db.session.query(
            func.coalesce(func.sum(Transaction.amount), 0)
        ).filter(
            Transaction.user_id == user_id,
            Transaction.land_purchase_id == purchase.id,
            Transaction.status == 'COMPLETED'
        ).scalar()

        balance_remaining = max(0, land_price - total_paid)
        progress_percentage = round(min(100, (total_paid / land_price * 100) if land_price else 0), 2)

        land_data.append({
            'plot_name': getattr(land, 'name', 'Unnamed Plot'),
            'purchase_date': purchase.purchase_date.strftime('%Y-%m-%d') if purchase.purchase_date else 'N/A',
            'total_paid': total_paid,
            'balance_remaining': balance_remaining,
            'progress_percentage': progress_percentage,
            'status': getattr(purchase, 'status', 'Unknown'),
            'purchase': purchase,
            'land': land
        })

    # Monthly payments aggregation (for chart display)
    monthly_payments = db.session.query(
        extract('year', Transaction.date).label('year'),
        extract('month', Transaction.date).label('month'),
        func.coalesce(func.sum(Transaction.amount), 0)
    ).filter(
        Transaction.user_id == user_id,
        Transaction.status == 'COMPLETED'
    ).group_by('year', 'month').order_by('year', 'month').all()

    payment_data = {
        'labels': [f"{int(year)}-{int(month):02d}" for year, month, _ in monthly_payments],
        'amounts': [amount for _, _, amount in monthly_payments]
    }

    # Final stats and recent purchases (limit 5)
    stats = {
        'total_plots': len(purchases),
        'total_invested': total_invested,
        'pending_payments': pending_payments
    }

    recent_purchases = land_data[:5]

    return render_template(
        'dashboard_landbuyer.html',
        stats=stats,
        recent_purchases=recent_purchases,
        payment_data=payment_data,
        transactions=transactions
    )

# --- PROFILE ROUTE ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('logout'))

    if request.method == 'POST':
        user.full_name = request.form.get('full_name')
        user.email = request.form.get('email')
        user.id_number = request.form.get('id_number') # Allow update for potentially nullable field
        user.phone_number = request.form.get('phone_number') # Allow update for potentially nullable field
        user.next_of_kin_name = request.form.get('next_of_kin_name')
        user.next_of_kin_phone = request.form.get('next_of_kin_phone')

        # Basic phone number format validation for updates
        if user.phone_number and not (user.phone_number.startswith('07') or user.phone_number.startswith('254')) or (user.phone_number and len(user.phone_number) < 9):
            flash('Invalid primary phone number format. Must start with 07 or 254 (e.g., 0712345678 or 254712345678).', 'danger')
            return redirect(url_for('profile'))
        
        if user.next_of_kin_phone and not ((user.next_of_kin_phone.startswith('07') or user.next_of_kin_phone.startswith('254')) and len(user.next_of_kin_phone) >= 9):
            flash('Invalid Next of Kin phone number format. Must start with 07 or 254 (e.g., 0712345678 or 254712345678), if provided.', 'danger')
            return redirect(url_for('profile'))

        db.session.commit()
        # session['user_phone'] = user.phone_number # Update session with new phone number if needed elsewhere
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/generate-pdf')
@login_required 
def generate_pdf():
    user = User.query.get(session['user_id'])
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

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

    # Add role-specific details to PDF (from original provided code)
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
        pdf.cell(200, 10, txt=f"Client Name (Reg): {user.full_name}", ln=True) # Assuming user's name is client name
        pdf.cell(200, 10, txt=f"Client ID (Reg): {user.id_number if user.id_number else 'N/A'}", ln=True)
        pdf.cell(200, 10, txt=f"Client Phone (Reg): {user.phone_number if user.phone_number else 'N/A'}", ln=True)
        pdf.cell(200, 10, txt=f"Client Email (Reg): {user.email}", ln=True)


    pdf_output = io.BytesIO()
    pdf.output(pdf_output, dest='S')
    pdf_output.seek(0)

    filename = f"profile_{user.id}.pdf"
    return send_file(pdf_output, as_attachment=True, download_name=filename, mimetype='application/pdf')
import requests
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

# --- Forgot Password Page ---
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password_page():
    if request.method == 'POST':
        email = request.form.get('email')

        if not email:
            flash("Please provide your email.", "warning")
            return redirect(url_for('forgot_password_page'))

        try:
            firebase_api_key = app.config.get('FIREBASE_WEB_API_KEY')
            reset_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={firebase_api_key}"
            payload = {
                "requestType": "PASSWORD_RESET",
                "email": email
            }

            response = requests.post(reset_url, json=payload)
            result = response.json()
            print("[DEBUG] Firebase reset password response:", result)

            # Don't expose whether the email exists or not
            flash("If the email is registered, a password reset link has been sent.", "info")
            return redirect(url_for('reset_request_confirmation'))

        except Exception as e:
            print(f"[ERROR] Firebase reset error: {e}")
            flash("An unexpected error occurred. Please try again later.", "danger")
            return redirect(url_for('forgot_password_page'))

    return render_template('forgot_password.html')


# --- Optional API version (for JS-based frontend) ---
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password_api():
    if not app.firebase_auth:
        return jsonify({"status": "error", "message": "Auth service not available"}), 500

    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"status": "error", "message": "Email is required"}), 400

    try:
        firebase_api_key = app.config.get("FIREBASE_WEB_API_KEY")
        reset_url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={firebase_api_key}"
        payload = {
            "requestType": "PASSWORD_RESET",
            "email": email
        }

        response = requests.post(reset_url, json=payload)
        result = response.json()
        print("[DEBUG] API Reset Response:", result)

        # Always respond success (security best practice)
        return jsonify({
            "status": "success",
            "message": "If the email is registered, a password reset link has been sent."
        }), 200

    except Exception as e:
        return jsonify({"status": "error", "message": f"Reset failed: {str(e)}"}), 500


# --- Confirmation Page ---
@app.route('/reset-request-confirmation')
def reset_request_confirmation():
    return render_template('reset_confirmation.html')

@app.route('/pay', methods=['POST'])
def pay_api_endpoint(): # Generic payment endpoint, not used by current M-Pesa STK flow
    data = request.get_json()
    phone = data.get('phone')
    amount = data.get('amount')

    if not phone or amount is None:
        return jsonify({"error": "Phone and amount required"}), 400

    try:
        amount = float(amount)
    except ValueError:
        return jsonify({"error": "Invalid amount"}), 400

    print(f"Received generic payment request for phone: {phone}, amount: {amount}")
    return jsonify({"status": "success", "message": "Generic payment request received."})

@app.route('/mpesa_callback', methods=['POST'])
def mpesa_callback():
    """
    This route receives the M-Pesa STK Push callback.
    It should be publicly accessible (e.g., via ngrok during development, or live domain in production).
    """
    data = request.json
    print(f"--- M-Pesa Callback Received ---")
    print(json.dumps(data, indent=2))
    print("---------------------------------")

    try:
        # Extract common callback data
        result_code = data['Body']['stkCallback']['ResultCode']
        checkout_request_id = data['Body']['stkCallback']['CheckoutRequestID']
        
        transaction_status = 'FAILED' # Default to failed
        mpesa_receipt_number = None
        amount_from_callback = None
        phone_number_from_callback = None
        
        if result_code == 0: # Success
            transaction_status = 'COMPLETED'
            # Extract details from CallbackMetadata for successful payments
            if 'CallbackMetadata' in data['Body']['stkCallback'] and 'Item' in data['Body']['stkCallback']['CallbackMetadata']:
                for item in data['Body']['stkCallback']['CallbackMetadata']['Item']:
                    if item['Name'] == 'MpesaReceiptNumber':
                        mpesa_receipt_number = item['Value']
                    elif item['Name'] == 'Amount':
                        amount_from_callback = item['Value']
                    elif item['Name'] == 'PhoneNumber':
                        phone_number_from_callback = item['Value']
        else: # Failed or Cancelled (ResultCode != 0)
            print(f"M-Pesa transaction failed/cancelled: ResultCode {result_code}. Desc: {data['Body']['stkCallback'].get('ResultDesc')}")
            # Consider more specific status like 'CANCELLED' if ResultCode allows distinguishing

        # Find the pending transaction using CheckoutRequestID (most robust method)
        transaction = Transaction.query.filter_by(
            checkout_request_id=checkout_request_id,
            status='PENDING' # Only look for pending transactions to update
        ).first()
        
        if transaction:
            transaction.status = transaction_status
            transaction.mpesa_receipt_number = mpesa_receipt_number
            # Update amount and phone if they weren't fully captured or for confirmation
            if amount_from_callback:
                transaction.amount = float(amount_from_callback) # Ensure float conversion
            if phone_number_from_callback:
                transaction.phone_number = phone_number_from_callback

            db.session.commit()
            print(f"Transaction {transaction.id} updated to {transaction_status}. MpesaReceipt: {mpesa_receipt_number}")
        else:
            print(f"No matching PENDING transaction found for CheckoutRequestID: {checkout_request_id}. This might be a duplicate callback or a transaction that failed initial logging.")
            # For unhandled callbacks, you might want to log them for manual review
            # You could create a new 'UnhandledCallback' model to store them

        return jsonify({"ResultCode": 0, "ResultDesc": "Callback received successfully"}), 200

    except Exception as e:
        print(f"Error processing M-Pesa callback: {e}")
        traceback.print_exc() # Print full traceback for debugging server-side errors
        return jsonify({"ResultCode": 1, "ResultDesc": "Error processing callback"}), 200 # Always return 200 to M-Pesa

# --- Investment Tiers Landing Page ---
@app.route('/invest', methods=['GET'])
@login_required
@role_required('investor')
def invest_tiers_page():
    """
    Displays investment tiers to logged-in investors.
    """
    try:
        user_id = session.get('user_id')
        if not user_id:
            flash("Session expired. Please log in again.", "warning")
            return redirect(url_for('login'))

        # Fetch user data from Firebase
        user_doc_ref = app.firebase_db.collection('users').document(str(user_id))
        user_doc = user_doc_ref.get()

        if not user_doc.exists:
            flash("User not found in database. Please log in again.", "danger")
            session.clear()
            return redirect(url_for('login'))

        user_data = user_doc.to_dict()
        role = user_data.get('role', '')

        if role != 'investor':
            flash("Unauthorized access. Investor role required.", "danger")
            session.clear()
            return redirect(url_for('login'))

        # ✅ Render tier selection page
        return render_template('invest.html', user=user_data)

    except Exception as e:
        print(f"[ERROR] Failed to load investment tiers: {e}")
        traceback.print_exc()
        flash("An error occurred while loading your investment options.", "danger")
        session.clear()
        return redirect(url_for('login'))


# --- Investment Form Page with M-Pesa STK Push Integration ---
@app.route('/invest_form', methods=['GET', 'POST'])
@login_required
@role_required('investor')
def invest_form():
    from sqlalchemy.orm import Session
    user_id = session.get('user_id')

    if not user_id:
        session.clear()
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    # ✅ Fetch user from Firebase (not SQLAlchemy)
    user_doc_ref = app.firebase_db.collection('users').document(str(user_id))
    user_doc = user_doc_ref.get()

    if not user_doc.exists:
        session.clear()
        flash("User not found. Please log in again.", "danger")
        return redirect(url_for('login'))

    user_data = user_doc.to_dict()
    phone_number = user_data.get("phone_number", "").strip()

    VALID_TIERS = ['Seed', 'Sprout', 'Harvest', 'Orchard', 'Legacy', 'Custom']

    if request.method == 'GET':
        tier = request.args.get('tier', '').strip()
        if tier not in VALID_TIERS:
            flash('Invalid or missing investment tier selected.', 'danger')
            return redirect(url_for('invest_tiers_page'))  # Redirect to safe tier selection page
        print(f"[DEBUG] User {user_id} accessed tier: {tier}")
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

            # 🔁 Save investment to database using SQLAlchemy
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

            # 🔐 Get M-Pesa token
            def get_mpesa_token():
                try:
                    key = app.config['MPESA_CONSUMER_KEY']
                    secret = app.config['MPESA_CONSUMER_SECRET']
                    token_url = f"{app.config['MPESA_API_BASE_URL']}/oauth/v1/generate?grant_type=client_credentials"
                    r = requests.get(token_url, auth=(key, secret))
                    r.raise_for_status()
                    return r.json().get('access_token')
                except Exception as e:
                    print("[M-PESA ERROR] Token Fetch Failed:", e)
                    return None

            access_token = get_mpesa_token()
            if not access_token:
                db.session.rollback()
                return jsonify({'status': 'error', 'message': 'M-Pesa access token generation failed.'}), 500

            # 🔁 Prepare STK Push payload
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            shortcode = app.config['MPESA_BUSINESS_SHORTCODE']
            passkey = app.config['MPESA_PASSKEY']
            password = base64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()

            stk_url = f"{app.config['MPESA_API_BASE_URL']}/mpesa/stkpush/v1/processrequest"
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
                "CallBackURL": app.config['MPESA_CALLBACK_URL'],
                "AccountReference": f"AmsaInvest_{investment.id}",
                "TransactionDesc": f"Investment for {tier}"
            }

            response = requests.post(stk_url, headers=headers, json=payload)
            response.raise_for_status()
            stk_response = response.json()

            # ✅ Log transaction
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
            traceback.print_exc()
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'Unexpected server error during investment.'}), 500


# --- Check Payment Status API ---
@app.route('/check_payment_status/<int:transaction_id>', methods=['GET'])

def check_payment_status(transaction_id):
    user_id = session.get('user_id')
    transaction = Transaction.query.filter_by(id=transaction_id, user_id=user_id).first()

    if not transaction:
        return jsonify({"status": "error", "message": "Transaction not found or unauthorized."}), 404

    return jsonify({"status": transaction.status})
# --- Route: Invest Land ---
@app.route('/invest_land', methods=['GET'])
@login_required
def invest_land():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)

    if not user:
        session.clear()
        flash('User session expired or invalid. Please log in again.', 'danger')
        return redirect(url_for('login'))

    plan_id = request.args.get('plan_id')
    if plan_id:
        return redirect(url_for('land_purchase_form', plan_id=plan_id))

    return render_template('invest_land.html', user=user)


# --- Route: Land Purchase Form with M-Pesa STK Push ---
@app.route('/land_purchase_form', methods=['GET', 'POST'])
@login_required
def land_purchase_form():
    user_id = session.get('user_id')
    user = db.session.get(User, user_id)

    if not user:
        session.clear()
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'status': 'error', 'message': 'No data received.'}), 400

        plot_location = data.get('plot_location', '').strip()
        purchase_price_str = data.get('purchase_price')
        purpose = data.get('purchase_purpose', '').strip()
        plan_id_post = data.get('plan_id', '').strip()

        errors = []

        # Validate purchase price
        try:
            purchase_price = float(purchase_price_str)
            if purchase_price <= 0:
                errors.append("Purchase price must be greater than zero.")
        except (ValueError, TypeError):
            errors.append("Invalid purchase price format.")

        # Validate phone number
        phone_number = user.phone_number
        if not phone_number:
            errors.append("No phone number found in your profile.")
        else:
            if phone_number.startswith('0'):
                phone_number = '254' + phone_number[1:]
            elif phone_number.startswith('+254'):
                phone_number = phone_number[1:]

            if not (phone_number.startswith('2547') or phone_number.startswith('2541')) or len(phone_number) != 12:
                errors.append("Invalid phone number. Use Safaricom format: 2547XXXXXXXX.")

        if errors:
            return jsonify({'status': 'error', 'errors': errors}), 400

        # Save purchase
        new_purchase = LandPurchase(
            user_id=user.id,
            plot_location=plot_location,
            purchase_price=purchase_price,
            purpose=purpose
        )
        db.session.add(new_purchase)
        db.session.commit()

        # Generate M-Pesa Token
        def get_mpesa_access_token():
            try:
                token_url = f"{app.config['MPESA_API_BASE_URL']}/oauth/v1/generate?grant_type=client_credentials"
                res = requests.get(token_url, auth=(app.config['MPESA_CONSUMER_KEY'], app.config['MPESA_CONSUMER_SECRET']))
                res.raise_for_status()
                return res.json().get('access_token')
            except Exception as e:
                print("[M-PESA TOKEN ERROR]", e)
                return None

        access_token = get_mpesa_access_token()
        if not access_token:
            db.session.rollback()
            return jsonify({'status': 'error', 'message': 'Failed to retrieve M-Pesa token.'}), 500

        # Prepare STK Push
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        shortcode = app.config['MPESA_BUSINESS_SHORTCODE']
        passkey = app.config['MPESA_PASSKEY']
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
            "CallBackURL": app.config['MPESA_CALLBACK_URL'],
            "AccountReference": f"LAND_{new_purchase.id}",
            "TransactionDesc": f"Land Purchase at {plot_location}"
        }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(
                f"{app.config['MPESA_API_BASE_URL']}/mpesa/stkpush/v1/processrequest",
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
            print("[M-PESA ERROR]", e)
            traceback.print_exc()
            return jsonify({'status': 'error', 'message': f'STK Push failed: {str(e)}'}), 500

    # --- GET: Render form page with prefilled plan if any ---
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
        },
        'monthly-40000': {
            'name': 'Annual Installment Plan',
            'rate': 'KES 40,000/month',
            'period': '12 months',
            'description': 'Monthly for 1 year.',
            'suggested_price': 40000 * 12
        },
        'one-off-500000': {
            'name': 'One-Off Cash Purchase',
            'rate': 'KES 500,000',
            'period': 'One-off',
            'description': 'One-time payment with 5% discount.',
            'suggested_price': 500000
        }
    }

    selected_plan_info = plan_details.get(selected_plan_id, {})
    return render_template('land_purchase_form.html',
                           user=user,
                           selected_plan_id=selected_plan_id,
                           selected_plan_info=selected_plan_info)


@app.route('/manage_land', methods=['GET', 'POST'])
def manage_land_view():
    if request.method == 'POST':
        try:
            plot_reference = request.form['plot_reference']
            location = request.form['location']
            size_acres = request.form['size_acres']
            price_kes = request.form['price_kes']
            description = request.form['description']

            new_land = Land(
                plot_reference=plot_reference,
                location=location,
                size_acres=size_acres,
                price_kes=price_kes,
                description=description
            )

            db.session.add(new_land)
            db.session.commit()
            flash('New land parcel added successfully!', 'success')
        except Exception as e:
            flash(f'Error: {str(e)}', 'danger')

        return redirect(url_for('manage_land_view'))

    lands = Land.query.all()
    return render_template('manage_land.html', lands=lands)


# --- Admin Panel Routes ---
# --- Unified Admin User Management (Firebase + Local) ---
@app.route('/admin/users')
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
            'role': user.role,
            'phone_number': user.phone_number,
            'source': 'local'
        })

    # --- Firebase Users ---
    try:
        users_ref = app.firebase_db.collection('users')
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
        flash("⚠️ Failed to fetch Firebase users.", "warning")
        print("[Firebase Error - Manage Users]:", e)

    return render_template('manage_users.html', users=users)


# --- Admin: Edit Local User ---
@app.route('/admin/users/edit/<source>/<user_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def edit_user(source, user_id):
    current_admin_id = str(session.get('user_id'))

    if source == 'local':
        user = User.query.get_or_404(int(user_id))

        if request.method == 'POST':
            if str(user.id) == current_admin_id and request.form.get('role') != user.role:
                flash("❌ You can't change your own role.", 'danger')
                return redirect(url_for('edit_user', source='local', user_id=user_id))

            user.full_name = request.form.get('full_name')
            user.email = request.form.get('email')
            user.role = request.form.get('role')
            user.phone_number = request.form.get('phone_number')
            user.id_number = request.form.get('id_number')
            user.next_of_kin_name = request.form.get('next_of_kin_name')
            user.next_of_kin_phone = request.form.get('next_of_kin_phone')

            new_password = request.form.get('password')
            if new_password:
                user.password = generate_password_hash(new_password)

            try:
                db.session.commit()
                flash(f'✅ {user.full_name} updated.', 'success')
                return redirect(url_for('manage_users'))
            except Exception as e:
                db.session.rollback()
                flash("Error updating local user.", 'danger')
                print("[Edit Local User Error]:", e)

        return render_template('edit_user.html', user=user, source='local')

    elif source == 'firebase':
        doc_ref = app.firebase_db.collection('users').document(user_id)
        user_doc = doc_ref.get()

        if not user_doc.exists:
            flash("❌ Firebase user not found.", "danger")
            return redirect(url_for('manage_users'))

        data = user_doc.to_dict()

        if request.method == 'POST':
            if user_id == current_admin_id and request.form.get('role') != data.get('role'):
                flash("❌ You can't change your own role.", 'danger')
                return redirect(url_for('edit_user', source='firebase', user_id=user_id))

            try:
                doc_ref.update({
                    'full_name': request.form.get('full_name'),
                    'email': request.form.get('email'),
                    'role': request.form.get('role'),
                    'phone_number': request.form.get('phone_number')
                })
                flash("✅ Firebase user updated.", "success")
                return redirect(url_for('manage_users'))
            except Exception as e:
                flash("Error updating Firebase user.", 'danger')
                print("[Edit Firebase User Error]:", e)

        return render_template('edit_user.html', user=data, user_id=user_id, source='firebase')

    flash("❌ Unknown user source.", 'danger')
    return redirect(url_for('manage_users'))



@app.route('/admin/users/delete/<source>/<user_id>', methods=['POST'])
@login_required
@role_required('admin')
def delete_user(source, user_id):
    current_admin_id = str(session.get('user_id'))

    if source == 'local':
        user = User.query.get_or_404(int(user_id))
        if str(user.id) == current_admin_id:
            flash("❌ You can't delete your own account.", 'danger')
            return redirect(url_for('manage_users'))

        try:
            db.session.delete(user)
            db.session.commit()
            flash(f"🗑️ {user.full_name} deleted.", "success")
        except Exception as e:
            db.session.rollback()
            flash("Error deleting local user.", 'danger')
            print("[Delete Local User Error]:", e)

    elif source == 'firebase':
        if user_id == current_admin_id:
            flash("❌ You can't delete your own Firebase account.", 'danger')
            return redirect(url_for('manage_users'))

        try:
            app.firebase_db.collection('users').document(user_id).delete()
            flash("🗑️ Firebase user deleted.", "success")
        except Exception as e:
            flash("Error deleting Firebase user.", 'danger')
            print("[Delete Firebase User Error]:", e)

    else:
        flash("❌ Unknown user source.", 'danger')

    return redirect(url_for('manage_users'))
import csv
from flask import Response

@app.route('/admin/users/export/csv')
@login_required
@role_required('admin')
def export_users_csv():
    users = User.query.all()

    def generate():
        data = []
        header = ['ID', 'Full Name', 'Email', 'Role', 'ID Number', 'Phone']
        data.append(header)

        for u in users:
            data.append([
                u.id,
                u.full_name,
                u.email,
                u.role if isinstance(u.role, str) else u.role.value,
                u.id_number or '',
                u.phone_number or ''
            ])

        csv_data = ''
        for row in data:
            csv_data += ','.join([str(item) for item in row]) + '\n'
        return csv_data

    return Response(
        generate(),
        mimetype='text/csv',
        headers={"Content-Disposition": "attachment;filename=am_users.csv"}
    )
@app.route('/admin/firebase/reset-password/<user_id>')
@login_required
@role_required('admin')
def reset_firebase_password(user_id):
    try:
        firebase_auth = app.firebase_auth
        firebase_link = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={app.config['FIREBASE_WEB_API_KEY']}"

        # Get user email from Firestore
        user_doc = app.firebase_db.collection('users').document(user_id).get()
        if not user_doc.exists:
            flash("🚫 Firebase user not found.", "danger")
            return redirect(url_for('manage_users'))

        user_email = user_doc.to_dict().get('email')
        if not user_email:
            flash("⚠️ User has no email to send reset link.", "warning")
            return redirect(url_for('manage_users'))

        # Send password reset email
        payload = {
            "requestType": "PASSWORD_RESET",
            "email": user_email
        }
        response = requests.post(firebase_link, json=payload)
        result = response.json()

        if "error" in result:
            flash(f"❌ Error sending reset link: {result['error']['message']}", "danger")
        else:
            flash(f"✅ Password reset email sent to {user_email}.", "success")

    except Exception as e:
        print("[Reset Firebase Password Error]", e)
        flash("⚠️ Failed to send reset email.", "danger")

    return redirect(url_for('manage_users'))



@app.route('/admin/land', methods=['GET', 'POST'])
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
            return redirect(request.url)

        description = request.form.get('description')
        
        # Handle file upload
        if 'image' not in request.files:
            flash('No image part in the request', 'danger')
            return redirect(request.url)
        
        file = request.files['image']
        
        if file.filename == '':
            flash('No selected image', 'danger')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Create a unique filename to prevent clashes
            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            try:
                file.save(file_path)
            except Exception as e:
                flash(f"Failed to save image file: {e}", 'danger')
                return redirect(request.url)

            new_land = Land(
                plot_reference=plot_reference,
                location=location,
                size_acres=size_acres,
                price_kes=price_kes,
                description=description,
                image_filename=unique_filename # Store the unique filename in DB
            )
            db.session.add(new_land)
            db.session.commit()
            flash('Land plot added successfully!', 'success')
            return redirect(url_for('manage_land'))
        else:
            flash('Allowed image types are png, jpg, jpeg, gif', 'danger')
            return redirect(request.url)

    land_listings = Land.query.all()
    return render_template('manage_land.html', land_listings=land_listings)

# Route to serve uploaded images (important for development, Render handles static files automatically)
@app.route('/static/uploads/land_images/<filename>')
def uploaded_file(filename):
    # Ensure this path is correct relative to app.root_path for local development
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/admin/investments')
@login_required
@role_required('admin')
def manage_investments():
    all_investments = Investment.query.all()
    
    investment_details = []
    for inv in all_investments:
        total_paid_for_inv = db.session.query(db.func.sum(Transaction.amount)).filter(
            Transaction.investment_id == inv.id,
            Transaction.user_id == inv.user_id, # Ensure it's the correct user's transaction for this investment
            Transaction.status == 'COMPLETED'
        ).scalar() or 0

        balance_remaining = None
        if inv.target_amount is not None:
            balance_remaining = inv.target_amount - total_paid_for_inv
            if balance_remaining < 0:
                balance_remaining = 0 # Cannot have negative balance remaining towards goal
            
        progress_percentage = 0
        if inv.target_amount and inv.target_amount > 0:
            progress_percentage = (total_paid_for_inv / inv.target_amount) * 100
            if progress_percentage > 100:
                progress_percentage = 100
        
        investment_details.append({
            'investment': inv,
            'investor': inv.investor, # Access the linked User object
            'total_paid': total_paid_for_inv,
            'balance_remaining': balance_remaining,
            'progress_percentage': progress_percentage
        })

    return render_template('manage_investments.html', investment_details=investment_details)

@app.route('/admin/send_reminder/<int:investment_id>')
@login_required
@role_required('admin')
def send_payment_reminder(investment_id):
    investment = Investment.query.get_or_404(investment_id)
    investor = investment.investor # Access the linked investor User object

    if not investor or not investor.email:
        flash(f'Cannot send reminder: Investor for investment ID {investment_id} not found or has no email.', 'danger')
        return redirect(url_for('manage_investments'))

    # Calculate current balance for the reminder
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
        return redirect(url_for('manage_investments'))

    subject = f"Payment Reminder for Your Investment with AMSA Developers (ID: {investment.id})"
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
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = investor.email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        
        flash(f'Payment reminder sent successfully to {investor.email} for investment ID {investment.id}!', 'success')
    except Exception as e:
        flash(f'Failed to send payment reminder: {e}', 'danger')
        print(f"Email sending error for investment ID {investment.id} to {investor.email}: {e}")
        traceback.print_exc() # Print full traceback for debugging
    
    return redirect(url_for('manage_investments'))


@app.route('/admin/transactions')
@login_required
@role_required('admin')
def view_transactions():
    # Fetch transactions and eager-load the related user to avoid N+1 queries
    transactions = Transaction.query.join(User).order_by(Transaction.date.desc()).all()
    # Pass user_rel (which is the User object linked by backref) to the template
    return render_template('view_transactions.html', transactions=transactions)

@app.route('/admin/transactions/download_receipt/<int:txn_id>')
@login_required
@role_required('admin')
def download_receipt(txn_id):
    transaction = Transaction.query.get_or_404(txn_id)
    user = transaction.user_rel # Access the related User object

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(0, 10, txt="Transaction Receipt", ln=True, align='C')
    pdf.ln(10)

    # Convert UTC datetime to local time for display if needed, or keep as UTC
    local_datetime = transaction.date # Assuming transaction.date is UTC, use as is for now

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
        investment = transaction.investment # Access the related Investment object
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
@app.route('/buy-land')
def buy_land():
    # You might fetch available land listings here to display to customers
    available_land = Land.query.filter_by(status='Available').all()
    return render_template('buy_land.html', land_listings=available_land)
# ... (rest of your app.py code before the routes) ...

@app.route('/')
@app.route('/available_land')
def available_land():
    """
    Renders the available land listings page, fetching data from the database.
    """
    # Fetch all land listings from the database, ordered by added_date descending
    # THIS IS THE CORRECTED LINE:
    land_listings = Land.query.order_by(Land.added_date.desc()).all()

    # Flash a message (optional, for demo)
    # flash('Welcome to Amsa Group land listings!', 'success')
    return render_template('available_land.html', land_listings=land_listings) # Use the fetched 'land_listings' variable

# ... (rest of your app.py code after the routes) ...

@app.route('/microfinance', methods=['GET', 'POST'])
def microfinance():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        subject = request.form.get('subject')
        message = request.form.get('message')

        if not name or not email or not message:
            flash('Please fill in all required fields (Name, Email, Message).', 'error')
            return render_template('microfinance.html')

        # Email sending logic
        try:
            msg = MIMEMultipart()
            msg['From'] = app.config['MAIL_DEFAULT_SENDER']
            msg['To'] = 'amsavillage@gmail.com' # Recipient of the contact form message
            msg['Subject'] = f"New Message from Microfinance Contact Form: {subject}"

            body = f"Name: {name}\n" \
                   f"Email: {email}\n" \
                   f"Subject: {subject}\n\n" \
                   f"Message:\n{message}"
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
                server.starttls()
                server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
                server.send_message(msg)

            flash('Your message has been sent successfully!', 'success')
            return redirect(url_for('microfinance') + '#contact') # Redirect back to contact section
        except Exception as e:
            flash(f'An error occurred while sending your message: {e}', 'error')
            print(f"Error sending microfinance contact email: {e}")
            traceback.print_exc()
            return render_template('microfinance.html')

    return render_template('microfinance.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

# --- Flask CLI Command for Secure Admin User Creation ---

@app.cli.command("create-admin-secure")
@with_appcontext
def create_admin_secure():
    """
    Securely create a new admin user via CLI prompts.
    Passwords are hidden and confirmed, and never stored in code or history.
    """
    click.echo("\n--- Secure Admin User Creation ---")

    # Check if an admin already exists
    if User.query.filter_by(role='admin').first():
        click.echo(click.style("An admin user already exists. Skipping creation.", fg="yellow"))
        click.echo("To modify or create another admin, please use your application's internal management tools.")
        return

    click.echo("\nPlease provide the following details for the new admin user:")

    full_name = click.prompt(click.style("Enter Admin Full Name", fg="cyan"), type=str)
    email = click.prompt(click.style("Enter Admin Email", fg="cyan"), type=str)

    # Secure password input: hidden and confirmed
    password = click.prompt(
        click.style("Enter Admin Password", fg="cyan"),
        hide_input=True,
        confirmation_prompt=True,
        type=str
    )

    id_number = click.prompt(click.style("Enter Admin ID Number", fg="cyan"), type=str)
    phone_number = click.prompt(click.style("Enter Admin Phone Number (e.g., 2547XXXXXXXX)", fg="cyan"), type=str)

    try:
        admin_user = User(
            full_name=full_name,
            email=email,
            password=generate_password_hash(password),
            role="admin",
            id_number=id_number,
            phone_number=phone_number
        )

        db.session.add(admin_user)
        db.session.commit()
        click.echo(click.style(f"\nAdmin user '{email}' created successfully for {full_name}.", fg="green"))
        click.echo(click.style("Remember to store these credentials securely!", fg="yellow"))
    except Exception as e:
        db.session.rollback()
        click.echo(click.style(f"\nError creating admin user: {e}", fg="red"))
        click.echo(click.style("Database transaction rolled back.", fg="red"))

    click.echo("----------------------------------\n")

if __name__ == "__main__":
    app.run(debug=True)

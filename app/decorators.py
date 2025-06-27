# functions/app/decorators.py

from functools import wraps
from json.tool import main
from flask import jsonify, session, redirect, url_for, flash, request, current_app
from app.models import User
from app.security import csrf_required_json_header  # Correct relative import


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("⚠️ Please log in to continue.", "warning")
            return redirect(url_for('main.login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            session_role = session.get('user_role')

            if not user_id:
                flash("🚫 Access denied. Please log in.", "danger")
                return redirect(url_for('main.login', next=request.path))

            # Primary Check: Session role
            if session_role == required_role:
                return f(*args, **kwargs)

            # Fallback 1: Check role from local DB
            try:
                # Ensure user_id is an int if your User model uses Integer primary keys
                local_user = User.query.get(int(user_id))
                if local_user and local_user.role.value.lower() == required_role.lower(): # Compare string values of enum
                    session['user_role'] = local_user.role.value # Refresh session role with string
                    return f(*args, **kwargs)
            except ValueError:
                current_app.logger.error(f"[ROLE FALLBACK - SQLAlchemy] Invalid user_id format: {user_id}")
            except Exception as e:
                current_app.logger.error(f"[ROLE FALLBACK - SQLAlchemy] Error checking local DB role for user {user_id}: {e}", exc_info=True)


            # Fallback 2: Check role from Firebase Firestore
            try:
                user_doc = current_app.firebase_db.collection('users').document(str(user_id)).get()
                if user_doc.exists:
                    firebase_role = user_doc.to_dict().get('role')
                    if firebase_role and firebase_role.lower() == required_role.lower():
                        session['user_role'] = firebase_role # Refresh session role
                        return f(*args, **kwargs)
            except Exception as e:
                current_app.logger.error(f"[ROLE FALLBACK - Firebase] Error checking Firebase role for user {user_id}: {e}", exc_info=True)

            # Final fallback: clear session and deny if no role matches after checks
            session.clear()
            flash("❌ Access denied. Invalid role or session expired.", "danger")
            return redirect(url_for('main.login', next=request.path))
        return decorated_function
    return decorator


def redirect_by_role(role):
    """
    Redirect user to their appropriate dashboard based on role.
    """
    if role == 'admin':
        return redirect(url_for('main.dashboard_admin')) # Corrected: Specific admin dashboard
    elif role == 'investor':
        return redirect(url_for('main.dashboard_investor')) # Corrected: Specific investor dashboard
    elif role == 'landbuyer':
        return redirect(url_for('main.dashboard_landbuyer')) # Assuming landbuyer has their own dashboard
    else:
        # Fallback for unrecognized roles or if the role isn't mapped to a specific dashboard
        current_app.logger.warning(f"Unknown role '{role}'. Redirecting to main index.")
        flash("⚠️ Unknown role. Redirecting to home.", "warning")
        return redirect(url_for('main.index')) # Redirect to index or a generic dashboard if one exists

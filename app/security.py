from flask import request, jsonify, session, current_app
from functools import wraps

def verify_csrf_from_header():
    """
    Validates CSRF token sent in the 'X-CSRFToken' HTTP header.
    Returns a Flask response (jsonify) if invalid; otherwise returns None.
    """
    # Extract CSRF tokens
    token_from_client = request.headers.get('X-CSRFToken')
    token_from_session = session.get('csrf_token')

    # Log for debugging
    current_app.logger.info(f"Client CSRF (Header): {token_from_client}")
    current_app.logger.info(f"Session CSRF: {token_from_session}")

    # Step 1: Check missing client token
    if not token_from_client:
        current_app.logger.info("The CSRF token is missing from X-CSRFToken header.")
        return jsonify({"status": "error", "message": "Missing CSRF token in request header."}), 400

    # Step 2: Check missing server token
    if not token_from_session:
        current_app.logger.info("Session CSRF token is missing on server.")
        return jsonify({"status": "error", "message": "Session expired or invalid. Please refresh the page."}), 400

    # Step 3: Check mismatch
    if token_from_client != token_from_session:
        current_app.logger.info("The CSRF token is invalid (mismatch).")
        return jsonify({"status": "error", "message": "CSRF token mismatch. Request denied."}), 400

    # Success
    current_app.logger.info("CSRF token validated successfully from header.")
    return None

def csrf_required_json_header(f):
    """
    Decorator for API routes expecting CSRF token via header.
    Use @csrf_required_json_header above your POST/PUT/DELETE JSON routes.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf_check = verify_csrf_from_header()
        if csrf_check:
            return csrf_check  # Respond immediately if token is invalid
        return f(*args, **kwargs)
    return decorated_function

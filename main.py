import os

try:
    from firebase_functions import https_fn
    from firebase_functions.options import set_global_options
    from firebase_admin import initialize_app
    IS_FIREBASE = True
except ImportError:
    # Firebase SDK not available (local dev)
    IS_FIREBASE = False

from app import create_app

# Create Flask app
flask_app = create_app()

# --- Firebase Setup ---
if IS_FIREBASE:
    # Set global Cloud Function options
    set_global_options(max_instances=10)

    # Initialize Firebase Admin SDK
    initialize_app()

    # Cloud Function Entry Point
    @https_fn.on_request()
    def flask_cloud_function(request: https_fn.Request) -> https_fn.Response:
        return https_fn.Response.from_wsgi_app(flask_app.wsgi_app)(request)

# --- Run Locally ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    flask_app.run(host="127.0.0.1", port=port, debug=True)

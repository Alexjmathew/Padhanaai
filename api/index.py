import os
import sys

# Ensure the root project directory is discoverable by Python's module search
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from app import app


class VercelPathFixMiddleware:
    """
    WSGI Middleware for Vercel Serverless Functions.
    Resolves Vercel path rewrites by inspecting HTTP_X_MATCHED_PATH and normalizing
    /api/index destinations back to Flask's declared application routes.
    """
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        matched_path = environ.get("HTTP_X_MATCHED_PATH")
        path_info = environ.get("PATH_INFO", "")

        if matched_path:
            environ["PATH_INFO"] = matched_path
        elif path_info in ("/api/index", "/api/index.py", "/api"):
            environ["PATH_INFO"] = "/"
        elif path_info.startswith("/api/index/"):
            environ["PATH_INFO"] = path_info[len("/api/index"):]

        return self.wsgi_app(environ, start_response)


# Wrap Flask's WSGI application with the Vercel path fix middleware
app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)

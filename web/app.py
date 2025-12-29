"""
Flask application factory.
"""

import sys
from pathlib import Path

from flask import Flask
from flask_wtf.csrf import CSRFProtect

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vulnscan.config import get_config, set_config, Config
from vulnscan.storage.database import Database

csrf = CSRFProtect()


def create_app(config: Config = None) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)

    if config:
        set_config(config)
    else:
        config = get_config()

    app.config["SECRET_KEY"] = "vuln-scanner-secret-key-change-in-production"
    app.config["DATABASE_PATH"] = str(config.database.path)
    app.config["LANGUAGE"] = config.language

    # Initialize CSRF protection
    csrf.init_app(app)

    # Initialize database
    Database(config.database.path)

    # Register blueprints
    from .views import views_bp
    from .api import api_bp

    app.register_blueprint(views_bp)
    app.register_blueprint(api_bp, url_prefix="/api")

    return app


def run_server(host: str = "127.0.0.1", port: int = 5000, debug: bool = False):
    """Run the Flask development server."""
    app = create_app()
    app.run(host=host, port=port, debug=debug, threaded=True)


if __name__ == "__main__":
    run_server(debug=True)

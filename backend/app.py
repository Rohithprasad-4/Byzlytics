"""Flask application factory with middleware and global error handling."""

from __future__ import annotations

import atexit
import logging
import os

from dotenv import load_dotenv
from flask import Flask, jsonify
from flask_cors import CORS
from werkzeug.exceptions import HTTPException

from backend.config import AppConfig, load_config
from backend.database import close_db_pool, init_db_pool
from backend.exceptions import APIError
from backend.responses import error_response
from backend.routes import api_bp

load_dotenv()

logger = logging.getLogger(__name__)


def _configure_logging(debug: bool) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def create_app(config: AppConfig | None = None, *, testing: bool = False) -> Flask:
    """Application factory used by the dev server, gunicorn, and tests."""
    app_config = config or load_config()
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=app_config.secret_key,
        DEBUG=app_config.debug,
        TESTING=testing,
        REPORTS_DIR=app_config.reports_dir,
        APP_CONFIG=app_config,
    )

    _configure_logging(app_config.debug)

    CORS(
        app,
        resources={r"/*": {"origins": app_config.cors_origins}},
        supports_credentials=True,
    )

    if not app.config.get("TESTING"):
        init_db_pool(app_config.database)
        atexit.register(close_db_pool)

        if os.getenv("ENABLE_SCHEDULER", "1") == "1":
            from reports.scheduler import start_scheduler

            start_scheduler(reports_dir=app_config.reports_dir)

    app.register_blueprint(api_bp)

    @app.errorhandler(APIError)
    def handle_api_error(error: APIError):
        return error_response(error.message, data=error.data, http_status=error.status_code)

    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException):
        return error_response(error.description or error.name, http_status=error.code)

    @app.errorhandler(404)
    def handle_not_found(error):
        return error_response("Endpoint not found.", http_status=404)

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        return error_response("Method not allowed.", http_status=405)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception):
        logger.exception("Unhandled exception: %s", error)
        if app.config.get("DEBUG"):
            return error_response(str(error), http_status=500)
        return error_response("An unexpected error occurred.", http_status=500)

    @app.route("/")
    def root():
        return jsonify({
            "status": "success",
            "message": "SecureGate AI API",
            "data": {
                "version": "1.0.0",
                "docs": "/health",
            },
        })

    return app


def run() -> None:
    """Entry point for `python -m backend.app`."""
    config = load_config()
    app = create_app(config)
    app.run(host=config.host, port=config.port, debug=config.debug)


if __name__ == "__main__":
    run()

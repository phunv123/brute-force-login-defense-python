from flask import Flask
from authlib.integrations.flask_client import OAuth
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

from app.config import Config

db = SQLAlchemy()
bcrypt = Bcrypt()
login_manager = LoginManager()
migrate = Migrate()
csrf = CSRFProtect()
oauth = OAuth()


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    migrate.init_app(app, db)
    csrf.init_app(app)
    oauth.init_app(app)
    _register_oauth_clients(app)

    # Register i18n translation function
    from app.i18n import translate, get_locale, set_locale
    app.jinja_env.globals.update(_=translate, get_locale=get_locale, set_locale=set_locale)

    login_manager.login_view = "auth.login"
    login_manager.login_message = "Vui lòng đăng nhập để truy cập trang này."
    login_manager.login_message_category = "warning"

    from app.models import User

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from app.routes.admin import admin_bp
    from app.routes.auth import auth_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)

    # Seed honeypot decoy accounts on startup
    with app.app_context():
        from app.services.honeypot_service import seed_honeypot_accounts
        try:
            seed_honeypot_accounts()
        except Exception:
            pass  # silently skip if DB not yet ready (first migration)

    return app


def _register_oauth_clients(app: Flask):
    google_client_id = app.config.get("OAUTH_GOOGLE_CLIENT_ID")
    google_client_secret = app.config.get("OAUTH_GOOGLE_CLIENT_SECRET")
    if google_client_id and google_client_secret:
        oauth.register(
            name="google",
            client_id=google_client_id,
            client_secret=google_client_secret,
            server_metadata_url=(
                "https://accounts.google.com/.well-known/openid-configuration"
            ),
            client_kwargs={"scope": "openid email profile"},
        )

    github_client_id = app.config.get("OAUTH_GITHUB_CLIENT_ID")
    github_client_secret = app.config.get("OAUTH_GITHUB_CLIENT_SECRET")
    if github_client_id and github_client_secret:
        oauth.register(
            name="github",
            client_id=github_client_id,
            client_secret=github_client_secret,
            access_token_url="https://github.com/login/oauth/access_token",
            authorize_url="https://github.com/login/oauth/authorize",
            api_base_url="https://api.github.com/",
            client_kwargs={"scope": "read:user user:email"},
        )

    microsoft_client_id = app.config.get("OAUTH_MICROSOFT_CLIENT_ID")
    microsoft_client_secret = app.config.get("OAUTH_MICROSOFT_CLIENT_SECRET")
    microsoft_tenant = app.config.get("OAUTH_MICROSOFT_TENANT", "common")
    if microsoft_client_id and microsoft_client_secret:
        oauth.register(
            name="microsoft",
            client_id=microsoft_client_id,
            client_secret=microsoft_client_secret,
            server_metadata_url=(
                f"https://login.microsoftonline.com/{microsoft_tenant}/v2.0/"
                ".well-known/openid-configuration"
            ),
            client_kwargs={"scope": "openid profile email User.Read"},
        )

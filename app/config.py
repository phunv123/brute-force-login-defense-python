import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env", override=True)


def _get_env_str(name, default=None):
    value = os.getenv(name, default)
    if value is None:
        return None
    value = value.strip()
    if value == "":
        return None
    return value


class Config:
    SECRET_KEY = _get_env_str("SECRET_KEY", "dev-secret-key")

    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "sqlite:///brute_force_defense.db",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
    LOCK_DURATION_MINUTES = int(os.getenv("LOCK_DURATION_MINUTES", 15))
    BLOCK_IP_AFTER_ATTEMPTS = int(os.getenv("BLOCK_IP_AFTER_ATTEMPTS", 10))
    BLOCK_IP_DURATION_MINUTES = int(os.getenv("BLOCK_IP_DURATION_MINUTES", 30))
    RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", 30))

    # OAuth / Social Login
    OAUTH_GOOGLE_CLIENT_ID = _get_env_str("OAUTH_GOOGLE_CLIENT_ID")
    OAUTH_GOOGLE_CLIENT_SECRET = _get_env_str("OAUTH_GOOGLE_CLIENT_SECRET")

    OAUTH_GITHUB_CLIENT_ID = _get_env_str("OAUTH_GITHUB_CLIENT_ID")
    OAUTH_GITHUB_CLIENT_SECRET = _get_env_str("OAUTH_GITHUB_CLIENT_SECRET")

    OAUTH_MICROSOFT_CLIENT_ID = _get_env_str("OAUTH_MICROSOFT_CLIENT_ID")
    OAUTH_MICROSOFT_CLIENT_SECRET = _get_env_str("OAUTH_MICROSOFT_CLIENT_SECRET")
    OAUTH_MICROSOFT_TENANT = _get_env_str("OAUTH_MICROSOFT_TENANT", "common")

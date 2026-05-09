import os

from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")

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

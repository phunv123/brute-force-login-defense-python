import re
import secrets
from datetime import datetime

from sqlalchemy import func, or_

from app import db
from app.models import LoginLog, User


def find_user_by_username_or_email(username):
    keyword = username.strip().lower()
    return User.query.filter(
        or_(
            func.lower(User.username) == keyword,
            func.lower(User.email) == keyword,
        )
    ).first()


def is_username_exists(username):
    return User.query.filter_by(username=username.strip()).first() is not None


def is_email_exists(email):
    return User.query.filter_by(email=email.strip().lower()).first() is not None


def create_user(username, email, password):
    user = User(
        username=username.strip(),
        email=email.strip().lower(),
        role="user",
    )
    user.set_password(password)
    db.session.add(user)
    return user


def log_login(username, ip_address, user_agent, status, user=None, failure_reason=None):
    login_log = LoginLog(
        user_id=user.id if user else None,
        username=username.strip(),
        ip_address=ip_address,
        user_agent=user_agent[:255] if user_agent else None,
        status=status,
        failure_reason=failure_reason,
    )
    db.session.add(login_log)
    return login_log


def login_success(user):
    user.failed_attempts = 0
    user.last_login = datetime.utcnow()


def login_failed(user):
    if user is not None:
        user.failed_attempts += 1


def find_user_by_email(email):
    keyword = email.strip().lower()
    return User.query.filter(func.lower(User.email) == keyword).first()


def _normalize_username_candidate(raw):
    candidate = re.sub(r"[^a-zA-Z0-9_]+", "_", raw.strip().lower()).strip("_")
    if not candidate:
        candidate = "user"
    if len(candidate) < 3:
        candidate = f"{candidate}_usr"
    return candidate[:80]


def generate_unique_username(username_hint):
    base = _normalize_username_candidate(username_hint)
    if not is_username_exists(base):
        return base

    for idx in range(1, 10000):
        suffix = f"_{idx}"
        candidate = f"{base[:80 - len(suffix)]}{suffix}"
        if not is_username_exists(candidate):
            return candidate

    raise ValueError("Không thể tạo username duy nhất cho tài khoản social login.")


def create_oauth_user(email, username_hint):
    user = User(
        username=generate_unique_username(username_hint),
        email=email.strip().lower(),
        role="user",
    )
    # OAuth user không dùng password local, tạo secret random để đảm bảo schema hợp lệ.
    user.set_password(secrets.token_urlsafe(32))
    db.session.add(user)
    return user

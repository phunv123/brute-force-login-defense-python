"""
Detection Service — Brute Force Detection Engine
Phát hiện tấn công brute force dựa trên LoginLog.
"""
from datetime import datetime, timedelta

from app import db
from app.models import LoginLog, SystemConfig


# ── Cấu hình mặc định (có thể override từ SystemConfig) ──
DEFAULT_WINDOW_MINUTES = 10   # Cửa sổ thời gian tính failed login
DEFAULT_MAX_ATTEMPTS   = 5    # Số lần thất bại tối đa trước khi block
DEFAULT_BLOCK_MINUTES  = 30   # Thời gian block IP (phút)

KEY_WINDOW_MINUTES = "security.window_minutes"
KEY_MAX_ATTEMPTS = "security.max_attempts"
KEY_BLOCK_DURATION = "security.block_duration_minutes"


def _get_positive_int_config(key: str, default: int) -> int:
    record = SystemConfig.query.filter_by(key=key).first()
    if record is None:
        return default

    try:
        parsed = int(str(record.value).strip())
    except (TypeError, ValueError):
        return default

    if parsed <= 0:
        return default
    return parsed


def get_detection_config() -> dict:
    return {
        "window_minutes": _get_positive_int_config(
            KEY_WINDOW_MINUTES, DEFAULT_WINDOW_MINUTES
        ),
        "max_attempts": _get_positive_int_config(
            KEY_MAX_ATTEMPTS, DEFAULT_MAX_ATTEMPTS
        ),
        "block_duration_minutes": _get_positive_int_config(
            KEY_BLOCK_DURATION, DEFAULT_BLOCK_MINUTES
        ),
    }


def count_failed_by_ip(ip_address: str, window_minutes: int | None = None) -> int:
    """Đếm số lần đăng nhập thất bại từ một IP trong window_minutes phút gần nhất."""
    if window_minutes is None:
        window_minutes = get_detection_config()["window_minutes"]

    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    return (
        db.session.query(db.func.count(LoginLog.id))
        .filter(
            LoginLog.ip_address == ip_address,
            LoginLog.status == "failed",
            LoginLog.timestamp >= since,
        )
        .scalar()
        or 0
    )


def count_failed_by_username(username: str, window_minutes: int | None = None) -> int:
    """Đếm số lần đăng nhập thất bại với một username trong window_minutes phút gần nhất."""
    if window_minutes is None:
        window_minutes = get_detection_config()["window_minutes"]

    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    return (
        db.session.query(db.func.count(LoginLog.id))
        .filter(
            LoginLog.username == username,
            LoginLog.status == "failed",
            LoginLog.timestamp >= since,
        )
        .scalar()
        or 0
    )


def analyze_login_attempt(ip_address: str, username: str) -> dict:
    """
    Phân tích một lần đăng nhập: có phải brute force không?

    Returns:
        dict với các key:
            - failed_by_ip (int): số lần failed từ IP này
            - failed_by_username (int): số lần failed với username này
            - is_suspicious (bool): vượt ngưỡng cảnh báo (>= MAX/2)
            - should_block (bool): cần block IP ngay (>= MAX)
            - block_duration (int): thời gian block đề xuất (phút)
    """
    config = get_detection_config()
    window_minutes = config["window_minutes"]
    max_attempts = config["max_attempts"]
    base_block_minutes = config["block_duration_minutes"]

    failed_ip = count_failed_by_ip(ip_address, window_minutes=window_minutes)
    failed_user = count_failed_by_username(username, window_minutes=window_minutes)

    suspicious_threshold = max(1, max_attempts // 2)
    is_suspicious = failed_ip >= suspicious_threshold
    should_block = failed_ip >= max_attempts

    # Block lâu hơn nếu tấn công liên tục
    if failed_ip >= max_attempts * 3:
        block_duration = base_block_minutes * 4
    elif failed_ip >= max_attempts * 2:
        block_duration = base_block_minutes * 2
    else:
        block_duration = base_block_minutes

    return {
        "failed_by_ip":       failed_ip,
        "failed_by_username": failed_user,
        "is_suspicious":      is_suspicious,
        "should_block":       should_block,
        "block_duration":     block_duration,
        "threshold":          max_attempts,
        "window_minutes":     window_minutes,
    }

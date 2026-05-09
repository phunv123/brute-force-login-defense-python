"""
Blocking Service — IP Blocking Engine
Tự động block/unblock IP tấn công.
"""
from datetime import datetime, timedelta

from app import db
from app.models import Alert, BlockedIP


def is_ip_blocked(ip_address: str) -> bool:
    """Kiểm tra xem IP có đang bị block không."""
    record = BlockedIP.query.filter_by(
        ip_address=ip_address, is_active=True
    ).first()

    if record is None:
        return False

    # Tự động gỡ block nếu hết hạn
    if record.is_expired():
        record.deactivate()
        db.session.commit()
        return False

    return True


def get_block_info(ip_address: str) -> BlockedIP | None:
    """Lấy thông tin block của IP (trả về None nếu không bị block)."""
    record = BlockedIP.query.filter_by(
        ip_address=ip_address, is_active=True
    ).first()

    if record and record.is_expired():
        record.deactivate()
        db.session.commit()
        return None

    return record


def block_ip(
    ip_address: str,
    reason: str,
    duration_minutes: int = 30,
    blocked_by: int | None = None,
    block_type: str = "temporary",
) -> BlockedIP:
    """
    Block một IP address.
    Nếu IP đã bị block → cập nhật lại thời gian.
    """
    existing = BlockedIP.query.filter_by(ip_address=ip_address).first()

    if existing:
        # Kích hoạt lại và cập nhật thời gian
        existing.is_active   = True
        existing.reason      = reason
        existing.block_type  = block_type
        existing.blocked_at  = datetime.utcnow()
        existing.expires_at  = datetime.utcnow() + timedelta(minutes=duration_minutes)
        existing.blocked_by  = blocked_by
        record = existing
    else:
        record = BlockedIP(
            ip_address   = ip_address,
            reason       = reason,
            block_type   = block_type,
            blocked_at   = datetime.utcnow(),
            expires_at   = datetime.utcnow() + timedelta(minutes=duration_minutes),
            blocked_by   = blocked_by,
            is_active    = True,
        )
        db.session.add(record)

    # Tạo Alert thông báo
    _create_block_alert(ip_address, reason, duration_minutes)

    db.session.commit()
    return record


def unblock_ip(ip_address: str) -> bool:
    """
    Gỡ block IP thủ công.
    Returns True nếu thành công, False nếu IP không bị block.
    """
    record = BlockedIP.query.filter_by(
        ip_address=ip_address, is_active=True
    ).first()

    if record is None:
        return False

    record.deactivate()
    db.session.commit()
    return True


def get_all_blocked_ips():
    """Lấy danh sách tất cả IP đang bị block (còn hiệu lực)."""
    all_records = BlockedIP.query.filter_by(is_active=True).order_by(
        BlockedIP.blocked_at.desc()
    ).all()

    # Lọc bỏ những cái đã hết hạn
    active = []
    changed = False
    for r in all_records:
        if r.is_expired():
            r.deactivate()
            changed = True
        else:
            active.append(r)

    if changed:
        db.session.commit()

    return active


def _create_block_alert(ip_address: str, reason: str, duration_minutes: int):
    """Tạo Alert khi block IP."""
    alert = Alert(
        alert_type = "ip_blocked",
        message    = (
            f"IP {ip_address} đã bị block {duration_minutes} phút. "
            f"Lý do: {reason}"
        ),
        source_ip  = ip_address,
        severity   = "high",
    )
    db.session.add(alert)

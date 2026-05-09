"""
honeypot_service.py
───────────────────
Honey-account logic for the PhúNV Security platform.

Responsibilities:
  - Seed a fixed list of decoy usernames into the DB on startup.
  - Detect when any honeypot account is targeted during login.
  - Auto-create a CRITICAL alert on first probe and HIGH alerts thereafter.
"""

import secrets
from datetime import datetime

from app import db


# ── Honey-account definitions ──────────────────────────────────────────────────

HONEY_ACCOUNTS = [
    {"username": "admin_backup",  "email": "admin_backup@honeypot.internal"},
    {"username": "sysadmin",      "email": "sysadmin@honeypot.internal"},
    {"username": "root",          "email": "root@honeypot.internal"},
    {"username": "administrator", "email": "administrator@honeypot.internal"},
    {"username": "sa",            "email": "sa@honeypot.internal"},
]


def seed_honeypot_accounts():
    """
    Create decoy users that should NEVER receive legitimate login attempts.
    Called once from create_app() after db.create_all().
    """
    from app.models import User

    created = []
    for acct in HONEY_ACCOUNTS:
        existing = User.query.filter_by(username=acct["username"]).first()
        if existing:
            # Ensure flag is set even if user was created before this feature
            if not existing.is_honeypot:
                existing.is_honeypot = True
            continue

        user = User(
            username=acct["username"],
            email=acct["email"],
            role="user",
            is_honeypot=True,
        )
        # Use a cryptographically-random, unknown password — no one should log in
        user.set_password(secrets.token_urlsafe(48))
        db.session.add(user)
        created.append(acct["username"])

    db.session.commit()
    if created:
        print(f"[honeypot] 🍯  Seeded decoy accounts: {created}")


# ── Detection & alerting ───────────────────────────────────────────────────────

def check_honeypot_trigger(username: str, ip_address: str) -> bool:
    """
    Returns True if `username` is a honey-account.
    Side-effect: creates a CRITICAL/HIGH Alert in the DB.
    """
    from app.models import Alert, User

    user = User.query.filter_by(username=username.strip()).first()
    if user is None or not user.is_honeypot:
        return False

    # Count previous probes of this honeypot from any IP
    prior_probes = (
        Alert.query
        .filter(
            Alert.alert_type == "honeypot_triggered",
            Alert.target_username == username,
        )
        .count()
    )

    severity = "critical" if prior_probes == 0 else "high"
    msg = (
        f"🍯 HONEYPOT TRIGGERED — '{username}' is a decoy account. "
        f"Login attempt from {ip_address}. "
        f"This account should never receive real logins. "
        f"Possible reconnaissance or credential-stuffing attack."
    )

    alert = Alert(
        severity=severity,
        alert_type="honeypot_triggered",
        message=msg,
        source_ip=ip_address,
        target_username=username,
        is_read=False,
        created_at=datetime.utcnow(),
    )
    db.session.add(alert)
    # Commit happens in the calling route after log_login()
    return True

import time
from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app import db
from app.models import LoginLog, SystemConfig
from app.services.auth_service import (
    find_user_by_username_or_email,
    log_login,
    login_failed,
)
from app.services.blocking_service import (
    block_ip,
    get_all_blocked_ips,
    get_block_info,
    is_ip_blocked,
    unblock_ip,
)
from app.services.detection_service import (
    KEY_BLOCK_DURATION,
    KEY_MAX_ATTEMPTS,
    KEY_WINDOW_MINUTES,
    analyze_login_attempt,
    get_detection_config,
)
from app.services.honeypot_service import check_honeypot_trigger

admin_bp = Blueprint("admin", __name__)


def _parse_int(value, field_name, minimum, maximum):
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} phải là số nguyên.") from exc

    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{field_name} phải trong khoảng {minimum} - {maximum}.")
    return parsed


def _simulate_failed_login_attempt(target_username, attacker_ip):
    user = find_user_by_username_or_email(target_username)
    user_agent = "AttackSimulator/1.0"

    if is_ip_blocked(attacker_ip):
        block_info = get_block_info(attacker_ip)
        remaining_minutes = 0
        if block_info and block_info.expires_at:
            diff = block_info.expires_at - datetime.utcnow()
            remaining_minutes = max(0, int(diff.total_seconds() // 60))

        log_login(
            target_username,
            attacker_ip,
            user_agent,
            "blocked",
            user=user,
            failure_reason="ip_blocked",
        )
        db.session.commit()
        return {
            "status": "blocked",
            "action": "ip_blocked",
            "failed_by_ip": None,
            "message": f"IP đã bị block (còn khoảng {remaining_minutes} phút).",
        }

    if user and user.is_account_locked():
        log_login(
            target_username,
            attacker_ip,
            user_agent,
            "blocked",
            user=user,
            failure_reason="account_locked",
        )
        db.session.commit()
        return {
            "status": "blocked",
            "action": "account_locked",
            "failed_by_ip": None,
            "message": "Tài khoản đang bị khóa tạm thời.",
        }

    login_failed(user)
    log_login(
        target_username,
        attacker_ip,
        user_agent,
        "failed",
        user=user,
        failure_reason="simulator_invalid_credentials",
    )

    # Check if target is a honeypot account — fire alert immediately
    is_honey = check_honeypot_trigger(target_username, attacker_ip)

    db.session.commit()

    if is_honey:
        return {
            "status": "failed",
            "action": "honeypot_triggered",
            "failed_by_ip": 1,
            "message": f"🍯 HONEYPOT — '{target_username}' is a decoy account! CRITICAL alert created.",
        }

    analysis = analyze_login_attempt(attacker_ip, target_username)
    failed = analysis["failed_by_ip"]
    threshold = analysis["threshold"]

    if analysis["should_block"]:
        block_ip(
            attacker_ip,
            reason=(
                f"Attack Simulator: {failed} lần đăng nhập sai trong "
                f"{analysis['window_minutes']} phút"
            ),
            duration_minutes=analysis["block_duration"],
        )
        if user:
            user.lock_account(minutes=analysis["block_duration"])
            db.session.commit()

        return {
            "status": "blocked",
            "action": "block_triggered",
            "failed_by_ip": failed,
            "message": (
                f"Vượt ngưỡng {threshold}. IP bị block {analysis['block_duration']} phút."
            ),
        }

    if analysis["is_suspicious"]:
        remaining = max(0, threshold - failed)
        return {
            "status": "failed",
            "action": "warning",
            "failed_by_ip": failed,
            "message": f"Hành vi đáng ngờ. Còn {remaining} lần thử trước khi block.",
        }

    return {
        "status": "failed",
        "action": "none",
        "failed_by_ip": failed,
        "message": "Đăng nhập sai (mô phỏng).",
    }


def _upsert_system_config(key: str, value: int, description: str):
    record = SystemConfig.query.filter_by(key=key).first()
    if record is None:
        record = SystemConfig(key=key)
        db.session.add(record)

    record.value = str(value)
    record.description = description
    record.updated_by = current_user.id


@admin_bp.route("/admin/logs")
@login_required
def login_logs():
    page = max(1, request.args.get("page", 1, type=int))
    status_filter = (request.args.get("status") or "").strip().lower()
    ip_filter = (request.args.get("ip") or "").strip()
    username_filter = (request.args.get("username") or "").strip()
    export = (request.args.get("export") or "").strip().lower()

    query = LoginLog.query
    allowed_statuses = {"success", "failed", "blocked"}
    if status_filter in allowed_statuses:
        query = query.filter(LoginLog.status == status_filter)
    else:
        status_filter = ""

    if ip_filter:
        query = query.filter(LoginLog.ip_address.ilike(f"%{ip_filter}%"))
    if username_filter:
        query = query.filter(LoginLog.username.ilike(f"%{username_filter}%"))

    if export == "csv":
        import csv, io
        rows = query.order_by(LoginLog.timestamp.desc()).all()
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["id","timestamp","username","ip_address","status","failure_reason","user_agent"])
        for r in rows:
            writer.writerow([
                r.id,
                r.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                r.username, r.ip_address, r.status,
                r.failure_reason or "",
                (r.user_agent or "")[:200],
            ])
        from flask import Response
        return Response(
            out.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=login_logs.csv"},
        )

    pagination = query.order_by(LoginLog.timestamp.desc()).paginate(
        page=page, per_page=20, error_out=False,
    )

    return render_template(
        "admin/logs.html",
        logs=pagination.items,
        pagination=pagination,
        status_filter=status_filter,
        ip_filter=ip_filter,
        username_filter=username_filter,
    )


@admin_bp.route("/admin/settings", methods=["GET", "POST"])
@login_required
def settings():
    current_settings = get_detection_config()

    if request.method == "POST":
        try:
            max_attempts = _parse_int(
                request.form.get("max_attempts"),
                "max_attempts",
                minimum=1,
                maximum=50,
            )
            window_minutes = _parse_int(
                request.form.get("window_minutes"),
                "window_minutes",
                minimum=1,
                maximum=240,
            )
            block_duration = _parse_int(
                request.form.get("block_duration"),
                "block_duration",
                minimum=1,
                maximum=1440,
            )
        except ValueError as exc:
            flash(str(exc), "danger")
            return redirect(url_for("admin.settings"))

        _upsert_system_config(
            KEY_MAX_ATTEMPTS,
            max_attempts,
            "Ngưỡng số lần đăng nhập sai trước khi block.",
        )
        _upsert_system_config(
            KEY_WINDOW_MINUTES,
            window_minutes,
            "Cửa sổ thời gian (phút) để đếm failed login.",
        )
        _upsert_system_config(
            KEY_BLOCK_DURATION,
            block_duration,
            "Thời gian block IP mặc định (phút).",
        )
        db.session.commit()

        flash("Đã cập nhật Security Settings.", "success")
        return redirect(url_for("admin.settings"))

    return render_template("admin/settings.html", settings=current_settings)


@admin_bp.route("/admin/blocked")
@login_required
def blocked_ips():
    records = get_all_blocked_ips()
    now = datetime.utcnow()
    blocked_items = []
    for record in records:
        remaining_minutes = None
        if record.expires_at:
            remaining_minutes = max(
                0,
                int((record.expires_at - now).total_seconds() // 60),
            )
        blocked_items.append(
            {
                "ip_address": record.ip_address,
                "reason": record.reason,
                "block_type": record.block_type,
                "blocked_at": record.blocked_at,
                "expires_at": record.expires_at,
                "remaining_minutes": remaining_minutes,
            }
        )

    return render_template(
        "admin/blocked.html",
        blocked_items=blocked_items,
    )


@admin_bp.route("/admin/unblock/<path:ip_address>", methods=["POST"])
@login_required
def unblock_blocked_ip(ip_address):
    success = unblock_ip(ip_address)
    if success:
        flash(f"Đã gỡ block IP {ip_address}.", "success")
    else:
        flash(f"IP {ip_address} không ở trạng thái blocked.", "warning")
    return redirect(url_for("admin.blocked_ips"))


@admin_bp.route("/admin/simulator")
@login_required
def simulator():
    return render_template("admin/simulator.html")


@admin_bp.route("/api/simulate", methods=["POST"])
@login_required
def simulate_attack():
    payload = request.get_json(silent=True) or request.form

    target_username = (payload.get("target_username") or "").strip()
    if not target_username:
        return jsonify({"ok": False, "error": "Thiếu target_username."}), 400

    try:
        num_attempts = _parse_int(
            payload.get("num_attempts", 1),
            "num_attempts",
            minimum=1,
            maximum=30,
        )
        delay_ms = _parse_int(
            payload.get("delay_ms", 0),
            "delay_ms",
            minimum=0,
            maximum=3000,
        )
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    attacker_ip = (payload.get("attacker_ip") or "").strip()
    if not attacker_ip:
        suffix = ((current_user.id or 1) % 200) + 20
        attacker_ip = f"203.0.113.{suffix}"
    if len(attacker_ip) > 45:
        return jsonify({"ok": False, "error": "attacker_ip không hợp lệ."}), 400

    steps = []
    for idx in range(num_attempts):
        result = _simulate_failed_login_attempt(target_username, attacker_ip)
        result["attempt"] = idx + 1
        result["timestamp"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        steps.append(result)

        if delay_ms > 0 and idx < num_attempts - 1:
            time.sleep(delay_ms / 1000)

    return jsonify(
        {
            "ok": True,
            "target_username": target_username,
            "attacker_ip": attacker_ip,
            "requested_attempts": num_attempts,
            "executed_attempts": len(steps),
            "steps": steps,
            "blocked": any(step["status"] == "blocked" for step in steps),
        }
    )


# ── GEO MAP API ────────────────────────────────────────────────────────────────

# Demo geo seed: map test IPs to realistic locations for presentation
_GEO_SEED = {
    "203.0.113.20": (39.9042,  116.4074, "CN", "Beijing"),
    "203.0.113.21": (55.7558,   37.6173, "RU", "Moscow"),
    "203.0.113.22": (51.5074,   -0.1278, "GB", "London"),
    "203.0.113.23": (48.8566,    2.3522, "FR", "Paris"),
    "203.0.113.24": (35.6762,  139.6503, "JP", "Tokyo"),
    "203.0.113.25": (37.5665,  126.9780, "KR", "Seoul"),
    "203.0.113.26": (28.6139,   77.2090, "IN", "New Delhi"),
    "203.0.113.27": (41.0082,   28.9784, "TR", "Istanbul"),
    "203.0.113.28": (-23.5505, -46.6333, "BR", "São Paulo"),
    "203.0.113.29": (40.7128,  -74.0060, "US", "New York"),
}


def _ip_to_geo(ip: str):
    """Return (lat, lng, country, city) for an IP — demo-safe."""
    if ip in _GEO_SEED:
        lat, lng, country, city = _GEO_SEED[ip]
        return lat, lng, country, city

    # For other test/private ranges, use hash-based spread
    import hashlib
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    lat = round(-55 + (h % 11000) / 100, 4)
    lng = round(-175 + (h // 100 % 35000) / 100, 4)
    return lat, lng, "XX", "Unknown"


@admin_bp.route("/api/geo-data")
@login_required
def geo_data():
    from collections import Counter
    from app.models import LoginLog

    rows = (
        LoginLog.query
        .filter(LoginLog.status == "failed")
        .with_entities(LoginLog.ip_address)
        .all()
    )
    ip_counter = Counter(r.ip_address for r in rows)

    skip = {"127.0.0.1", "::1", "unknown"}
    results = []
    for ip, count in ip_counter.most_common(20):
        if ip in skip or not ip:
            continue
        lat, lng, country, city = _ip_to_geo(ip)
        results.append({
            "ip": ip,
            "lat": lat,
            "lng": lng,
            "count": count,
            "country": country,
            "city": city,
        })

    return jsonify({"ok": True, "data": results})


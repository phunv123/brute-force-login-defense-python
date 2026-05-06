from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user

from app import db
from app.forms import LoginForm, RegisterForm
from app.services.auth_service import (
    create_user,
    find_user_by_username_or_email,
    is_email_exists,
    is_username_exists,
    log_login,
    login_failed,
    login_success,
)

auth_bp = Blueprint("auth", __name__)


def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "unknown"


@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))
    return render_template("index.html")


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))

    form = RegisterForm()
    if form.validate_on_submit():
        if is_username_exists(form.username.data):
            flash("Tên đăng nhập đã tồn tại.", "danger")
        elif is_email_exists(form.email.data):
            flash("Email đã được sử dụng.", "danger")
        else:
            create_user(form.username.data, form.email.data, form.password.data)
            db.session.commit()
            flash("Đăng ký thành công. Vui lòng đăng nhập.", "success")
            return redirect(url_for("auth.login"))

    return render_template("auth/register.html", form=form)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("auth.dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = find_user_by_username_or_email(username)
        ip_address = get_client_ip()
        user_agent = request.headers.get("User-Agent", "")

        if user is not None and user.check_password(password):
            login_success(user)
            log_login(username, ip_address, user_agent, "success", user=user)
            db.session.commit()
            login_user(user, remember=form.remember.data)
            flash("Đăng nhập thành công.", "success")
            return redirect(url_for("auth.dashboard"))

        login_failed(user)
        log_login(
            username,
            ip_address,
            user_agent,
            "failed",
            user=user,
            failure_reason="invalid_credentials",
        )
        db.session.commit()
        flash("Sai tài khoản hoặc mật khẩu.", "danger")

    return render_template("auth/login.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Đã đăng xuất.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")

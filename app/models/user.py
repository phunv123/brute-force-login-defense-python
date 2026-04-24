from datetime import datetime, timedelta

from flask_login import UserMixin

from app import bcrypt, db


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), default="user", nullable=False)
    is_locked = db.Column(db.Boolean, default=False, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode("utf-8")

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def lock_account(self, minutes):
        self.is_locked = True
        self.locked_until = datetime.utcnow() + timedelta(minutes=minutes)

    def unlock_account(self):
        self.is_locked = False
        self.locked_until = None
        self.failed_attempts = 0

    def is_account_locked(self):
        if not self.is_locked:
            return False

        if self.locked_until is not None and self.locked_until <= datetime.utcnow():
            self.unlock_account()
            return False

        return True

    def is_admin(self):
        return self.role == "admin"

    def __repr__(self):
        return f"<User {self.username}>"

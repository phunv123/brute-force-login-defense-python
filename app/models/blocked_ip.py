from datetime import datetime

from app import db


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)
    reason = db.Column(db.String(255), nullable=False)
    block_type = db.Column(db.String(20), default="temporary", nullable=False)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    blocked_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    admin = db.relationship("User", backref="blocked_ips")

    def is_expired(self):
        if self.expires_at is None:
            return False
        return self.expires_at <= datetime.utcnow()

    def deactivate(self):
        self.is_active = False

    def __repr__(self):
        return f"<BlockedIP {self.ip_address}>"

from datetime import datetime

from app import db


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    severity = db.Column(db.String(20), nullable=False, index=True)
    alert_type = db.Column(db.String(50), nullable=False, index=True)
    message = db.Column(db.String(500), nullable=False)
    source_ip = db.Column(db.String(45), nullable=True, index=True)
    target_username = db.Column(db.String(80), nullable=True, index=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def mark_as_read(self):
        self.is_read = True

    def __repr__(self):
        return f"<Alert {self.severity} {self.alert_type}>"

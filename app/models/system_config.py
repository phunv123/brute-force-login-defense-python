from datetime import datetime

from app import db


class SystemConfig(db.Model):
    __tablename__ = "system_configs"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False, index=True)
    value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
    updated_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    admin = db.relationship("User", backref="updated_configs")

    def __repr__(self):
        return f"<SystemConfig {self.key}>"

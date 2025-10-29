import datetime

from CTFd.models import db


class HeadscaleUserKey(db.Model):
    __tablename__ = "tailscale_user_keys"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    namespace = db.Column(db.String(length=128), nullable=False)
    key = db.Column(db.String(length=255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)

    def is_active(self):
        """Return True if this key has not expired yet."""
        return self.expires_at is None or self.expires_at > datetime.datetime.utcnow()

    @property
    def headscale_user(self):
        """Return the Headscale user identifier returned by Headscale."""
        return self.namespace

    @headscale_user.setter
    def headscale_user(self, value):
        if value is None:
            raise ValueError("Headscale user identifier cannot be None")
        self.namespace = str(value)

    def __repr__(self):
        return f"<HeadscaleUserKey user_id={self.user_id} headscale_user={self.namespace}>"

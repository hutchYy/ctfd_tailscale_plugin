from wtforms import BooleanField, Form, HiddenField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Optional, URL


class BaseForm(Form):
    """WTForms base class mirroring the helpers we relied on from Flask-WTF."""

    def hidden_tag(self, *args, **kwargs):
        return ""

    def is_submitted(self) -> bool:
        from flask import request

        return request.method == "POST"

    def validate_on_submit(self) -> bool:
        return self.is_submitted() and self.validate()


class HeadscaleSettingsForm(BaseForm):
    api_url = StringField(
        "Headscale API URL",
        validators=[DataRequired(message="API URL is required"), URL(message="Enter a valid URL")],
        description="Base URL to the Headscale API (example: https://headscale.example.com)",
    )
    api_token = StringField(
        "Headscale API Token",
        validators=[DataRequired(message="API token is required")],
        description="Access token used for authenticating with the Headscale API",
    )
    verify_tls = BooleanField(
        "Verify TLS certificates",
        default=True,
        description="Disable only when using a self-signed Headscale endpoint during development",
    )
    show_user_keys = BooleanField(
        "Expose pre-auth keys to contestants",
        default=False,
        description="When enabled, contestants can view their cached pre-auth key on the Tailscale profile page",
    )
    save = SubmitField("Save settings")


class EnforcementSettingsForm(BaseForm):
    enforce_connection = BooleanField(
        "Require Tailscale for challenges",
        description="When enabled, challenge pages require visitors to come from an allowed Tailscale network",
    )
    allowed_cidrs = TextAreaField(
        "Allowed CIDR ranges",
        validators=[Optional()],
        description="Comma-separated list of CIDR blocks permitted to access challenges (defaults to Tailscale CGNAT range)",
        render_kw={"rows": 3},
    )
    update = SubmitField("Update enforcement policy")


class RegenerateKeyForm(BaseForm):
    user_id = HiddenField()
    submit = SubmitField("Generate new key")


class BulkProvisionForm(BaseForm):
    provision_missing = SubmitField("Provision missing users")

from wtforms import BooleanField, Form, HiddenField, IntegerField, PasswordField, SelectField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, NumberRange, Optional, URL


class BaseForm(Form):
    """WTForms base class mirroring the helpers we relied on from Flask-WTF."""

    def hidden_tag(self, *args, **kwargs):
        return ""

    def is_submitted(self) -> bool:
        from flask import request

        return request.method == "POST"

    def validate_on_submit(self) -> bool:
        return self.is_submitted() and self.validate()


class ApiConnectionForm(BaseForm):
    api_url = StringField(
        "Headscale API URL",
        validators=[DataRequired(message="API URL is required"), URL(require_tld=False, message="Enter a valid URL")],
        description="Internal URL the plugin uses to reach the Headscale API (e.g., http://headscale:8080). "
                    "This can be an internal hostname or IP. Contestants never see this address.",
    )
    api_token = PasswordField(
        "Headscale API Token",
        validators=[Optional()],
        description="Bearer token for authenticating with the Headscale API. "
                    "Generate this token using 'headscale apikeys create' on your Headscale server. "
                    "Keep this token secure as it grants full access to your Headscale instance.",
    )
    verify_tls = BooleanField(
        "Verify TLS certificates",
        default=True,
        description="Enable SSL/TLS certificate verification for secure connections. "
                    "Only disable this for development/testing with self-signed certificates. "
                    "WARNING: Disabling in production exposes you to man-in-the-middle attacks.",
    )
    save_api = SubmitField("Save")


class ContestantSettingsForm(BaseForm):
    login_server = StringField(
        "Public Login Server URL",
        validators=[Optional(), URL(require_tld=False, message="Enter a valid URL")],
        description="Public URL contestants use in their tailscale login --login-server command. "
                    "Set this when your Headscale API URL is internal (e.g., http://headscale:1200) "
                    "and contestants need a different, publicly reachable address. "
                    "Leave empty to use the Headscale API URL as the login server.",
    )
    show_user_keys = BooleanField(
        "Expose pre-auth keys to contestants",
        default=False,
        description="Controls when contestants can see their pre-auth keys. "
                    "Keep this OFF until you're ready to distribute keys (e.g., at competition start). "
                    "When enabled, users can view their keys at /tailscale/key to connect to your network.",
    )
    save_contestant = SubmitField("Save")


class AclTaggingForm(BaseForm):
    tag_strategy = SelectField(
        "ACL Tag Strategy",
        choices=[
            ("auto", "Auto (adapts to CTFd mode) - Recommended"),
            ("user-only", "User tags only (tag:user-{id})"),
            ("team-only", "Team tags only (tag:team-{id})"),
            ("both", "Both user and team tags"),
            ("none", "No automatic tags"),
        ],
        default="auto",
        description="Controls how users are tagged in Headscale for ACL management. "
                    "Tags are used to define access rules in your Headscale ACL policy.",
    )
    lb_groups = IntegerField(
        "Load Balancer Groups",
        validators=[Optional(), NumberRange(min=0, max=100)],
        default=0,
        description="Automatically distribute users across N load balancer groups (0 = disabled). "
                    "Users get assigned tags like 'lb-group-1', 'lb-group-2', etc. based on their user ID. "
                    "Use this to evenly split traffic across multiple infrastructure nodes or regions.",
    )
    save_acl = SubmitField("Save")


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
    save_enforcement = SubmitField("Save")


class RegenerateKeyForm(BaseForm):
    user_id = HiddenField()
    submit = SubmitField("Generate new key")


class BulkProvisionForm(BaseForm):
    provision_missing = SubmitField("Provision missing users")


class EditCustomTagsForm(BaseForm):
    user_id = HiddenField()
    custom_tags = StringField(
        "Custom Tags",
        validators=[Optional()],
        description="Comma-separated list of custom tags (e.g., loadbalancer-1, premium, region-us-east)",
    )
    update_tags = SubmitField("Update tags")

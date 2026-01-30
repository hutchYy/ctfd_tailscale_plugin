import datetime
import ipaddress
import logging
import secrets
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urljoin

import requests
from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from werkzeug.exceptions import Forbidden

from CTFd.models import Users, db
from CTFd.plugins import register_admin_plugin_menu_bar, register_user_page_menu_bar
from CTFd.utils import get_config, set_config
from CTFd.utils.decorators import admins_only, authed_only
from CTFd.utils.user import get_current_user

from .forms import (
    BulkProvisionForm,
    EditCustomTagsForm,
    EnforcementSettingsForm,
    HeadscaleSettingsForm,
    RegenerateKeyForm,
)
from .models import HeadscaleUserKey


CONFIG_API_URL = "TAILSCALE_API_URL"
CONFIG_API_TOKEN = "TAILSCALE_API_TOKEN"
CONFIG_VERIFY_TLS = "TAILSCALE_VERIFY_TLS"
CONFIG_ENFORCE_CONNECTION = "TAILSCALE_ENFORCE_CONNECTION"
CONFIG_ALLOWED_CIDRS = "TAILSCALE_ALLOWED_CIDRS"
CONFIG_SHOW_USER_KEYS = "TAILSCALE_SHOW_USER_KEYS"
CONFIG_TAG_STRATEGY = "TAILSCALE_TAG_STRATEGY"
CONFIG_LB_GROUPS = "TAILSCALE_LB_GROUPS"

DEFAULT_ALLOWED_CIDRS = ["100.64.0.0/10"]
DEFAULT_KEY_EXPIRATION = datetime.datetime(2099, 12, 31, 23, 59, 59)

logger = logging.getLogger(__name__)

# Track users currently being provisioned to avoid duplicate attempts
_provisioning_in_progress = set()


# Use CTFd's built-in config functions directly
get_ctfd_config = get_config
set_ctfd_config = set_config


try:
    from CTFd.utils.helpers import get_nonce as ctfd_get_nonce  # type: ignore
except ImportError:  # pragma: no cover - fallback for older versions
    ctfd_get_nonce = None

try:
    from CTFd.utils.security.csrf import validate_nonce as ctfd_validate_nonce  # type: ignore
except ImportError:  # pragma: no cover - fallback when import path differs
    ctfd_validate_nonce = None


def generate_nonce() -> str:
    """Return a CSRF nonce, generating one and storing it in the session if necessary."""
    if ctfd_get_nonce is not None:
        return ctfd_get_nonce()
    nonce = session.get("nonce")
    if not nonce:
        nonce = secrets.token_hex(16)
        session["nonce"] = nonce
    return nonce


def is_nonce_valid(candidate: Optional[str]) -> bool:
    """Validate a submitted nonce against the session."""
    if not candidate:
        return False
    if ctfd_validate_nonce is not None:
        try:
            return bool(ctfd_validate_nonce(candidate))
        except TypeError:  # pragma: no cover - handle signature changes gracefully
            return bool(ctfd_validate_nonce(candidate, session.get("nonce")))
    stored = session.get("nonce")
    if not stored:
        return False
    try:
        return secrets.compare_digest(stored, candidate)
    except Exception:  # pragma: no cover - fallback to direct comparison
        return stored == candidate


def _get_bool_config(key: str, default: bool = False) -> bool:
    value = get_ctfd_config(key)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).lower() in {"1", "true", "yes", "on"}


def _get_list_config(key: str, default: Optional[List[str]] = None) -> List[str]:
    value = get_ctfd_config(key)
    if not value:
        return default or []
    return [entry.strip() for entry in value.split(",") if entry.strip()]


def _set_list_config(key: str, values: List[str]):
    cleaned = ", ".join(filter(None, (value.strip() for value in values)))
    set_ctfd_config(key, cleaned)


def _get_ctfd_user_mode() -> str:
    """
    Detect whether CTFd is in 'users' mode or 'teams' mode.
    Returns 'users' or 'teams'.
    """
    mode = get_ctfd_config("user_mode")
    if mode and str(mode).lower() in ("teams", "team"):
        return "teams"
    return "users"


def _get_lb_groups_count() -> int:
    """
    Get the number of load balancer groups configured.
    Returns 0 if load balancing is disabled.
    """
    value = get_ctfd_config(CONFIG_LB_GROUPS)
    if not value:
        return 0
    try:
        count = int(value)
        return max(0, count)  # Ensure non-negative
    except (ValueError, TypeError):
        return 0


def _get_user_lb_group(user) -> Optional[int]:
    """
    Deterministically assign a user to a load balancer group.
    Uses user_id % num_groups to ensure even distribution.
    Returns None if load balancing is disabled.
    """
    num_groups = _get_lb_groups_count()
    if num_groups <= 0:
        return None
    # Use modulo to distribute users evenly across groups
    # Groups are numbered from 1 to num_groups (not 0-indexed for readability)
    return (user.id % num_groups) + 1


def _headscale_user_name(user) -> str:
    return f"ctfd-user-{user.id}"


def _determine_acl_tags(
    user, key_record: Optional[HeadscaleUserKey] = None
) -> List[str]:
    """
    Determine ACL tags for a user based on CTFd mode, configuration, and custom tags.

    Tag strategy options:
    - "auto" (default): Detects CTFd mode and applies appropriate tags
      - In team mode: adds both user and team tags
      - In user mode: adds only user tag
    - "user-only": Only adds user tag (tag:user-{user_id})
    - "team-only": Only adds team tag if available (tag:team-{team_id})
    - "both": Always adds both user and team tags (when team exists)
    - "none": No tags (useful for manual ACL management)

    Custom tags from the key_record are always appended to the strategy-based tags.
    """
    tags: List[str] = []
    strategy = get_ctfd_config(CONFIG_TAG_STRATEGY) or "auto"
    strategy = str(strategy).lower()

    user_id = user.id
    team_id = getattr(user, "team_id", None)
    ctfd_mode = _get_ctfd_user_mode()

    # Determine which tags to add based on strategy
    if strategy != "none":
        if strategy == "auto":
            # Auto mode: adapt to CTFd's current mode
            if ctfd_mode == "teams":
                # In team mode, add both user and team tags for granular control
                tags.append(f"tag:user-{user_id}")
                if team_id:
                    tags.append(f"tag:team-{team_id}")
            else:
                # In user mode, only add user tag
                tags.append(f"tag:user-{user_id}")

        elif strategy == "user-only":
            tags.append(f"tag:user-{user_id}")

        elif strategy == "team-only":
            if team_id:
                tags.append(f"tag:team-{team_id}")

        elif strategy == "both":
            tags.append(f"tag:user-{user_id}")
            if team_id:
                tags.append(f"tag:team-{team_id}")

        else:
            # Unknown strategy, fall back to auto
            logger.warning(
                "Unknown TAILSCALE_TAG_STRATEGY '%s', falling back to 'auto'", strategy
            )
            tags.append(f"tag:user-{user_id}")
            if ctfd_mode == "teams" and team_id:
                tags.append(f"tag:team-{team_id}")

    # Add load balancer group tag if configured
    lb_group = _get_user_lb_group(user)
    if lb_group is not None:
        lb_tag = f"tag:lb-group-{lb_group}"
        if lb_tag not in tags:
            tags.append(lb_tag)

    # Add custom tags from the key record
    if key_record:
        custom_tags = key_record.get_custom_tags_list()
        for tag in custom_tags:
            # Ensure tag has proper format
            if not tag.startswith("tag:"):
                tag = f"tag:{tag}"
            if tag not in tags:
                tags.append(tag)

    return tags


def _extract_headscale_user_id(user_info) -> str:
    if isinstance(user_info, dict):
        user_id = user_info.get("id") or user_info.get("userId")
        if user_id:
            return str(user_id)
    raise RuntimeError("Headscale did not return a valid user identifier.")


def _ensure_headscale_user(user, client: "HeadscaleClient"):
    headscale_name = _headscale_user_name(user)
    user_info = client.ensure_user(
        user_id=headscale_name,
        display_name=user.name or f"user-{user.id}",
        email=user.email or "",
        picture_url="",
    )
    return headscale_name, _extract_headscale_user_id(user_info)


def _build_headscale_client() -> Optional["HeadscaleClient"]:
    """Build a Headscale client from current configuration."""
    api_url = get_ctfd_config(CONFIG_API_URL)
    api_token = get_ctfd_config(CONFIG_API_TOKEN)
    if not (api_url and api_token):
        return None
    verify_tls = _get_bool_config(CONFIG_VERIFY_TLS, True)
    return HeadscaleClient(api_url, api_token, verify=verify_tls, timeout=10)


def _test_headscale_connection() -> tuple[bool, str]:
    """
    Test the current Headscale configuration.
    Returns (success: bool, message: str)
    """
    client = _build_headscale_client()
    if client is None:
        return False, "Headscale API not configured (missing URL or token)"

    try:
        status = client.get_status()
        if status.ok:
            return True, f"Connected successfully: {status.message}"
        return False, status.message
    except Exception as e:
        logger.warning("Connection test failed: %s", e)
        return False, f"Connection failed: {str(e)[:200]}"


def _get_headscale_login_server() -> Optional[str]:
    api_url = get_ctfd_config(CONFIG_API_URL)
    if not api_url:
        return None
    return api_url.rstrip("/")


def _needs_headscale_provision(record: Optional[HeadscaleUserKey]) -> bool:
    if record is None:
        return True
    if not getattr(record, "headscale_user", None):
        return True
    if not getattr(record, "key", None):
        return True
    return False


def _generate_and_store_preauth_key(
    user, client: "HeadscaleClient", acl_tags: Optional[List[str]] = None
):
    headscale_name, headscale_user_id = _ensure_headscale_user(user, client)
    response = client.create_preauth_key(
        headscale_user_id,
        expiration=DEFAULT_KEY_EXPIRATION,
        acl_tags=acl_tags if acl_tags else None,
    )
    key_value = response.get("key")
    expiration_raw = response.get("expiration")
    if isinstance(expiration_raw, str):
        try:
            expiration = datetime.datetime.fromisoformat(
                expiration_raw.replace("Z", "+00:00")
            )
        except ValueError:
            expiration = None
    else:
        expiration = None

    key_record = HeadscaleUserKey.query.filter_by(user_id=user.id).one_or_none()
    if key_record is None:
        key_record = HeadscaleUserKey(user_id=user.id, headscale_user=headscale_user_id)
        db.session.add(key_record)
    key_record.headscale_user = headscale_user_id
    key_record.key = key_value
    key_record.expires_at = expiration
    key_record.created_at = datetime.datetime.utcnow()
    db.session.commit()
    return key_record


@dataclass
class HeadscaleAPIStatus:
    ok: bool
    message: str
    version: Optional[str] = None


class HeadscaleClient:
    """Small wrapper around the Headscale REST API."""

    def __init__(
        self, base_url: str, token: str, verify: bool = True, timeout: int = 3
    ):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.verify = verify
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs):
        if path.startswith("/"):
            path = path[1:]
        url = urljoin(f"{self.base_url}/", path)
        headers = kwargs.pop("headers", {})
        headers.setdefault("Authorization", f"Bearer {self.token}")
        headers.setdefault("Accept", "application/json")
        headers.setdefault("Content-Type", "application/json")
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify,
            **kwargs,
        )
        response.raise_for_status()
        if response.content:
            return response.json()
        return None

    @staticmethod
    def _extract_user(payload):
        if not isinstance(payload, dict):
            return None
        user_payload = payload.get("user")
        if isinstance(user_payload, dict):
            return user_payload
        users_payload = payload.get("users")
        if isinstance(users_payload, list):
            for candidate in users_payload:
                if isinstance(candidate, dict):
                    return candidate
        return None

    def get_status(self) -> HeadscaleAPIStatus:
        try:
            self._request("GET", "/api/v1/apikey")
        except requests.HTTPError as exc:
            status_code = exc.response.status_code if exc.response is not None else None
            logger.warning(
                "Headscale API status check failed with %s: %s", status_code, exc
            )
            if status_code == 401:
                return HeadscaleAPIStatus(
                    ok=False,
                    message="Authentication failed. Verify the Headscale API token.",
                )
            if status_code == 404:
                return HeadscaleAPIStatus(
                    ok=False,
                    message="Headscale API returned 404. Confirm the base URL.",
                )
            return HeadscaleAPIStatus(ok=False, message=str(exc))
        except requests.RequestException as exc:
            logger.warning("Failed to contact Headscale API: %s", exc)
            return HeadscaleAPIStatus(ok=False, message=str(exc))

        return HeadscaleAPIStatus(
            ok=True, message="Connected successfully (API key validated)"
        )

    def get_user_by_name(self, name: str):
        try:
            data = self._request("GET", "/api/v1/user", params={"name": name})
        except requests.HTTPError as exc:
            if exc.response is not None and exc.response.status_code == 404:
                return None
            raise
        return self._extract_user(data)

    def ensure_user(
        self, *, user_id: str, display_name: str, email: str, picture_url: str = ""
    ):
        existing = self.get_user_by_name(user_id)
        if existing is not None:
            return existing
        payload = {
            "name": user_id,
            "displayName": display_name,
            "email": email or "",
            "pictureUrl": picture_url or "",
        }
        data = self._request("POST", "/api/v1/user", json=payload)
        extracted = self._extract_user(data)
        if extracted is not None:
            return extracted
        if data:
            logger.debug(
                "Unexpected Headscale user payload when creating %s: %r", user_id, data
            )
        raise RuntimeError("Headscale did not return user details")

    def create_preauth_key(
        self,
        headscale_user_id: str,
        reusable: bool = True,
        ephemeral: bool = False,
        expiration: Optional[datetime.datetime] = None,
        acl_tags: Optional[List[str]] = None,
    ):
        payload = {
            "user": str(headscale_user_id),
            "reusable": reusable,
            "ephemeral": ephemeral,
        }
        if expiration:
            payload["expiration"] = expiration.isoformat() + "Z"
        if acl_tags is not None:
            payload["aclTags"] = acl_tags
        data = self._request("POST", "/api/v1/preauthkey", json=payload)
        preauth = data.get("preAuthKey") if isinstance(data, dict) else data
        if isinstance(preauth, dict):
            key_value = preauth.get("key")
            expiration_value = preauth.get("expiration")
        else:
            key_value = preauth
            expiration_value = None
        if not key_value:
            raise RuntimeError(
                "Headscale API returned an unexpected response when creating a preauth key"
            )
        return {
            "key": key_value,
            "expiration": expiration_value,
        }


def load(app):
    register_admin_plugin_menu_bar("Headscale Integration", "/admin/tailscale/")
    register_user_page_menu_bar("Tailscale", "/tailscale/key")

    admin_blueprint = Blueprint(
        "tailscale_admin",
        __name__,
        template_folder="templates",
        url_prefix="/admin/tailscale",
    )

    user_blueprint = Blueprint(
        "tailscale_plugin",
        __name__,
        template_folder="templates",
        url_prefix="/tailscale",
    )

    with app.app_context():
        HeadscaleUserKey.__table__.create(bind=db.engine, checkfirst=True)

        # Run migrations using CTFd's built-in migration system
        try:
            from CTFd.plugins.migrations import upgrade

            logger.info("Running database migrations for CTFd Tailscale plugin")
            upgrade()
        except Exception as e:
            logger.warning(
                "Failed to run automatic migrations: %s. "
                "You may need to run migrations manually.",
                e,
            )

    @admin_blueprint.route("/", methods=["GET", "POST"])
    @admins_only
    def admin_settings():
        formdata = request.form if request.method == "POST" else None
        settings_form = HeadscaleSettingsForm(formdata=formdata)
        enforcement_form = EnforcementSettingsForm(formdata=formdata)

        nonce_valid = True
        if request.method == "POST":
            nonce_value = request.form.get("nonce")
            nonce_valid = is_nonce_valid(nonce_value)
            if not nonce_valid:
                flash(
                    "Invalid session token. Please refresh the page and try again.",
                    "error",
                )

        if (
            nonce_valid
            and settings_form.save.data
            and settings_form.validate_on_submit()
        ):
            # Save settings
            set_ctfd_config(CONFIG_API_URL, settings_form.api_url.data.strip())
            set_ctfd_config(CONFIG_API_TOKEN, settings_form.api_token.data.strip())
            set_ctfd_config(
                CONFIG_VERIFY_TLS, "true" if settings_form.verify_tls.data else "false"
            )
            set_ctfd_config(
                CONFIG_SHOW_USER_KEYS,
                "true" if settings_form.show_user_keys.data else "false",
            )
            set_ctfd_config(
                CONFIG_TAG_STRATEGY, settings_form.tag_strategy.data or "auto"
            )
            lb_groups = settings_form.lb_groups.data or 0
            set_ctfd_config(CONFIG_LB_GROUPS, str(lb_groups))

            flash("Headscale settings saved successfully.", "success")
            return redirect(url_for("tailscale_admin.admin_settings"))

        if (
            nonce_valid
            and enforcement_form.update.data
            and enforcement_form.validate_on_submit()
        ):
            set_ctfd_config(
                CONFIG_ENFORCE_CONNECTION,
                "true" if enforcement_form.enforce_connection.data else "false",
            )
            allowed_cidrs = enforcement_form.allowed_cidrs.data or ""
            _set_list_config(CONFIG_ALLOWED_CIDRS, allowed_cidrs.split(","))
            flash("Enforcement policy updated.", "success")
            return redirect(url_for("tailscale_admin.admin_settings"))

        if not settings_form.is_submitted():
            settings_form.api_url.data = get_ctfd_config(CONFIG_API_URL) or ""
            settings_form.api_token.data = get_ctfd_config(CONFIG_API_TOKEN) or ""
            settings_form.verify_tls.data = _get_bool_config(CONFIG_VERIFY_TLS, True)
            settings_form.show_user_keys.data = _get_bool_config(
                CONFIG_SHOW_USER_KEYS, False
            )
            settings_form.tag_strategy.data = (
                get_ctfd_config(CONFIG_TAG_STRATEGY) or "auto"
            )
            settings_form.lb_groups.data = _get_lb_groups_count()

        if not enforcement_form.is_submitted():
            enforcement_form.enforce_connection.data = _get_bool_config(
                CONFIG_ENFORCE_CONNECTION, False
            )
            cidrs = _get_list_config(CONFIG_ALLOWED_CIDRS, DEFAULT_ALLOWED_CIDRS)
            enforcement_form.allowed_cidrs.data = ", ".join(cidrs)

        return render_template(
            "tailscale/admin_settings.html",
            settings_form=settings_form,
            enforcement_form=enforcement_form,
            nonce=generate_nonce(),
        )

    @admin_blueprint.route("/test-connection", methods=["POST"])
    @admins_only
    def test_connection():
        """Test the Headscale connection and return JSON result."""
        nonce_value = request.form.get("nonce")
        if not is_nonce_valid(nonce_value):
            return {"success": False, "message": "Invalid session token"}, 403

        success, message = _test_headscale_connection()
        return {"success": success, "message": message}

    @admin_blueprint.route("/users", methods=["GET", "POST"])
    @admins_only
    def admin_users():
        client = _build_headscale_client()
        if client is None:
            flash("Configure the Headscale API before managing user keys.", "warning")
            return redirect(url_for("tailscale_admin.admin_settings"))

        formdata = request.form if request.method == "POST" else None
        regenerate_form = RegenerateKeyForm(formdata=formdata)
        bulk_form = BulkProvisionForm(formdata=formdata)
        custom_tags_form = EditCustomTagsForm(formdata=formdata)
        nonce_valid = True
        if request.method == "POST":
            nonce_value = request.form.get("nonce")
            nonce_valid = is_nonce_valid(nonce_value)
            if not nonce_valid:
                flash(
                    "Invalid session token. Please refresh the page and try again.",
                    "error",
                )

        key_map = {record.user_id: record for record in HeadscaleUserKey.query.all()}
        users = Users.query.order_by(Users.id.asc()).all()

        if request.method == "POST" and nonce_valid:
            if bulk_form.provision_missing.data and bulk_form.validate_on_submit():
                missing_users = [
                    user
                    for user in users
                    if _needs_headscale_provision(key_map.get(user.id))
                ]
                if not missing_users:
                    flash("All users already have Headscale provisioning.", "info")
                else:
                    provisioned = 0
                    failures = []
                    for target_user in missing_users:
                        try:
                            existing_key = key_map.get(target_user.id)
                            key_record = _generate_and_store_preauth_key(
                                target_user,
                                client,
                                _determine_acl_tags(target_user, existing_key),
                            )
                            key_map[target_user.id] = key_record
                            provisioned += 1
                        except Exception as exc:  # noqa: BLE001
                            logger.exception(
                                "Bulk Headscale provisioning failed for user_id=%s",
                                target_user.id,
                            )
                            db.session.rollback()
                            failures.append((target_user, exc))
                    if provisioned:
                        flash(
                            f"Provisioned {provisioned} user(s) with Headscale keys.",
                            "success",
                        )
                    if failures:
                        failed_names = ", ".join(
                            f"{user.name} (id {user.id})" for user, _ in failures
                        )
                        flash(
                            f"Failed to provision {len(failures)} user(s): {failed_names}.",
                            "error",
                        )
                return redirect(url_for("tailscale_admin.admin_users"))
            if regenerate_form.validate_on_submit():
                try:
                    target_id = regenerate_form.user_id.data or ""
                    target_user = next(
                        (u for u in users if str(u.id) == target_id), None
                    )
                    if target_user is None:
                        raise ValueError("Selected user no longer exists.")
                    existing_key = key_map.get(target_user.id)
                    key_record = _generate_and_store_preauth_key(
                        target_user,
                        client,
                        _determine_acl_tags(target_user, existing_key),
                    )
                    key_map[target_user.id] = key_record
                    flash(
                        f"Generated a new pre-auth key for {target_user.name}.",
                        "success",
                    )
                    return redirect(url_for("tailscale_admin.admin_users"))
                except Exception as exc:  # noqa: BLE001
                    logger.exception(
                        "Failed to generate Headscale key from admin panel"
                    )
                    db.session.rollback()
                    flash(f"Failed to generate a Headscale key: {exc}", "error")
            if (
                custom_tags_form.update_tags.data
                and custom_tags_form.validate_on_submit()
            ):
                try:
                    target_id = custom_tags_form.user_id.data or ""
                    target_user = next(
                        (u for u in users if str(u.id) == target_id), None
                    )
                    if target_user is None:
                        raise ValueError("Selected user no longer exists.")
                    key_record = key_map.get(target_user.id)
                    if key_record is None:
                        flash(
                            f"User {target_user.name} must be provisioned before adding custom tags.",
                            "warning",
                        )
                    else:
                        # Parse and clean the custom tags input
                        tags_input = custom_tags_form.custom_tags.data or ""
                        tags_list = [
                            tag.strip() for tag in tags_input.split(",") if tag.strip()
                        ]
                        key_record.set_custom_tags_list(tags_list)
                        db.session.commit()

                        # Regenerate the preauth key with new tags
                        key_record = _generate_and_store_preauth_key(
                            target_user,
                            client,
                            _determine_acl_tags(target_user, key_record),
                        )
                        key_map[target_user.id] = key_record
                        flash(
                            f"Updated custom tags for {target_user.name} and regenerated key.",
                            "success",
                        )
                    return redirect(url_for("tailscale_admin.admin_users"))
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Failed to update custom tags from admin panel")
                    db.session.rollback()
                    flash(f"Failed to update custom tags: {exc}", "error")

        rows = []
        for user in users:
            key_entry = key_map.get(user.id)
            needs_provision = _needs_headscale_provision(key_entry)
            rows.append(
                {
                    "user": user,
                    "key": key_entry,
                    "acl_tags": _determine_acl_tags(user, key_entry),
                    "lb_group": _get_user_lb_group(user),
                    "headscale_name": _headscale_user_name(user),
                    "headscale_id": key_entry.headscale_user if key_entry else None,
                    "needs_provision": needs_provision,
                }
            )
        regenerate_form.user_id.data = ""
        missing_count = sum(1 for row in rows if row["needs_provision"])
        lb_groups_count = _get_lb_groups_count()
        lb_groups_enabled = lb_groups_count > 0
        return render_template(
            "tailscale/admin_users.html",
            rows=rows,
            regenerate_form=regenerate_form,
            bulk_form=bulk_form,
            custom_tags_form=custom_tags_form,
            missing_count=missing_count,
            lb_groups_enabled=lb_groups_enabled,
            lb_groups_count=lb_groups_count,
            nonce=generate_nonce(),
        )

    @user_blueprint.route("/key", methods=["GET"])
    @authed_only
    def user_key():
        user = get_current_user()
        if user is None:
            return redirect(url_for("auth.login"))

        client = _build_headscale_client()
        if client is None:
            flash("Headscale integration has not been configured yet.", "error")
            return redirect(url_for("views.profile"))

        key_record = HeadscaleUserKey.query.filter_by(user_id=user.id).one_or_none()
        allow_display = _get_bool_config(CONFIG_SHOW_USER_KEYS, False)
        login_server = _get_headscale_login_server()
        return render_template(
            "tailscale/user_key.html",
            key_record=key_record,
            allow_display=allow_display,
            login_server=login_server,
        )

    app.register_blueprint(admin_blueprint)
    app.register_blueprint(user_blueprint)

    csrf_protect = getattr(app, "csrf", None)
    if csrf_protect is not None:
        try:
            csrf_protect.exempt(admin_blueprint)
            csrf_protect.exempt(user_blueprint)
        except Exception:  # pragma: no cover - avoid failing if API changes
            logger.debug(
                "Unable to exempt Tailscale blueprints from CSRF protection",
                exc_info=True,
            )

    @app.before_request
    def auto_provision_tailscale_key():
        """
        Auto-provision Headscale keys for users.

        Uses short timeout and skip-if-in-progress logic to avoid blocking requests.
        """
        user = get_current_user()
        if user is None:
            return
        user_type = getattr(user, "type", None)
        if user_type and user_type.lower() != "user":
            return

        # Skip if already provisioned
        existing_key = HeadscaleUserKey.query.filter_by(user_id=user.id).one_or_none()
        if existing_key is not None:
            return

        # Skip if provisioning already in progress for this user (prevents duplicate attempts)
        if user.id in _provisioning_in_progress:
            logger.debug(
                "Skipping auto-provision for user %s - already in progress", user.id
            )
            return

        # Build client
        client = _build_headscale_client()
        if client is None:
            return

        # Mark as in progress
        _provisioning_in_progress.add(user.id)

        try:
            _generate_and_store_preauth_key(user, client, _determine_acl_tags(user))
            logger.info("Auto-provisioned Headscale key for user %s", user.id)
        except Exception:  # noqa: BLE001
            logger.exception(
                "Automatic Headscale key provisioning failed for user_id=%s", user.id
            )
            db.session.rollback()
            # Swallow the error so normal request handling continues
        finally:
            # Always remove from in-progress set
            _provisioning_in_progress.discard(user.id)

    @app.before_request
    def require_tailscale_for_challenges():
        if request.blueprint == "admin" or request.path.startswith(
            ("/admin", "/_ctfd")
        ):
            return

        # Defer to CTFd's built-in access controls first. If the user isn't authenticated
        # (e.g., the core app would redirect to login), we skip additional enforcement.
        user = get_current_user()
        if user is None:
            return

        if not _get_bool_config(CONFIG_ENFORCE_CONNECTION, False):
            return

        if not request.path.startswith(("/challenges", "/api/v1/challenges")):
            return

        allowed_cidrs = _get_list_config(CONFIG_ALLOWED_CIDRS, DEFAULT_ALLOWED_CIDRS)
        if not allowed_cidrs:
            return

        remote_addr = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        client_ip = remote_addr.split(",")[0].strip()
        if not client_ip:
            raise Forbidden("Unable to determine the client IP address.")

        try:
            ip = ipaddress.ip_address(client_ip)
        except ValueError:
            raise Forbidden("Invalid client IP address.")

        for cidr in allowed_cidrs:
            try:
                if ip in ipaddress.ip_network(cidr, strict=False):
                    return
            except ValueError:
                logger.warning(
                    "Invalid CIDR configured for Tailscale enforcement: %s", cidr
                )
                continue

        if request.is_json or request.path.startswith("/api/"):
            return {"success": False, "message": "Tailscale connection required."}, 403

        return render_template("tailscale/enforcement_blocked.html"), 403

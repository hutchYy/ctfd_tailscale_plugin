# CTFd Headscale Integration Plugin

This plugin connects a CTFd instance to a Headscale controller so that event organizers can distribute Tailscale pre-auth keys and optionally restrict challenge access to participants connected through Tailscale.

The implementation follows the [CTFd plugin development guidelines](https://docs.ctfd.io/docs/plugins/overview).

## Features

- Admin settings page for Headscale API URL, bearer token (hidden by default with a show/hide toggle), and TLS verification policy.
- Live connectivity probe against `/api/v1/apikey`, validating both API reachability and the configured token.
- Optional challenge enforcement that limits `/challenges` traffic to an approved set of Tailscale CIDR ranges.
- Automatic user provisioning: as soon as a contestant account exists (or logs in) the plugin ensures a Headscale user named `ctfd-user-<CTFd user ID>` exists and issues a reusable pre-auth key.
- Admin-controlled release window for pre-auth keys — organizers decide when the `/tailscale/key` page reveals the key by toggling **Expose pre-auth keys to contestants**.
- Contestant workflow that keeps commands hidden until the user clicks “Show commands”, then presents platform-specific `tailscale up --authkey=… --accept-routes` snippets (macOS, Linux, Windows) ready to copy/paste.
- Admin user management table with on-demand key reveal buttons for each contestant and a bulk “Provision missing users” action to backfill Headscale accounts/keys.

## Installation

1. Copy the `ctfd_tailscale_plugin` package into the CTFd `CTFd/plugins` directory.
2. Enable the plugin by adding `ctfd_tailscale_plugin` to the `plugins` list in `CTFd/config.py` or by setting the `plugins` environment variable.
3. Restart the CTFd service.

## Configuration

Visit **Admin > Headscale Integration** to configure the plugin.

The settings page links to **Headscale Users**, where administrators can inspect every contestant, view the stored Headscale user ID, and regenerate keys on their behalf.

### Headscale API

- **Headscale API URL**: Base URL to the Headscale server (for example `https://headscale.example.com`).
- **Headscale API Token**: Bearer token used when calling the Headscale REST API.
- **Verify TLS certificates**: Disable only when using self-signed certificates during development.
- **Expose pre-auth keys to contestants**: Controls whether `/tailscale/key` reveals the cached key. Leave this unchecked until you are ready to distribute keys.

Saving these settings triggers a connectivity check and displays the status banner at the top of the page.

### Challenge Enforcement

- **Require Tailscale for challenges**: Forces all requests to `/challenges` and `/api/v1/challenges` to originate from an allowed CIDR range.
- **Allowed CIDR ranges**: Comma-separated CIDR blocks. Defaults to `100.64.0.0/10`, the standard Tailscale CGNAT range.

Requests that fail the check receive a friendly HTML message, while API clients get a `403` JSON response.

## Contestant Experience

- The plugin provisions a Headscale user and pre-auth key automatically the first time a contestant account is created or signs in after the plugin is enabled.
- Organizers control disclosure: when **Expose pre-auth keys to contestants** is off, the `/tailscale/key` page explains that keys are withheld; when turned on, contestants click “Show commands” to reveal OS-specific instructions containing their personal `tailscale up` command (with `--accept-routes` and an optional `--login-server` argument).
- The page is read-only: contestants cannot re-issue keys themselves. They see creation/expiration timestamps and guidance on keeping the key private.

All Headscale usernames follow the `ctfd-user-<CTFd user ID>` pattern. When a key is generated, the plugin:

1. Calls `GET /api/v1/user?name=ctfd-user-<id>` and creates the user via `POST /api/v1/user` if missing (populating display name, email, and picture URL from CTFd).
2. Issues a reusable pre-auth key through `POST /api/v1/preauthkey`, automatically attaching ACL tags derived from the contestant’s team membership (for example, `tag:team-7`).
3. Stores the resulting Headscale user ID, key, timestamps, and optional expiration in CTFd’s `tailscale_user_keys` table for reuse.

## Implementation Overview

- **Configuration compatibility:** Utility helpers wrap `CTFd.config.get_config`/`set_config` so the plugin runs on multiple CTFd versions. The API token field stays masked until explicitly revealed.
- **Headscale client:** `HeadscaleClient` centralizes REST calls (`/api/v1/apikey`, `/api/v1/user`, `/api/v1/preauthkey`) with automatic JSON handling and error reporting.
- **Provisioning flow:** A `before_request` hook auto-provisions logged-in contestants lacking a key. The admin **Headscale Users** view exposes per-user regeneration plus a bulk action that iterates through every contestant missing a Headscale ID or key.
- **Contestant UI:** The `/tailscale/key` blueprint renders the read-only instructions, gating visibility on the admin toggle and ensuring commands include `--accept-routes` and the configured Headscale login server.
- **Challenge enforcement:** An additional `before_request` hook blocks access to challenge routes when enforcement is enabled, permitting only traffic from administrator-defined CIDR ranges (defaulting to the Tailscale CGNAT block).

## Operational Notes

- Headscale endpoints used: `GET /api/v1/apikey`, `GET /api/v1/user?name=…`, `POST /api/v1/user`, and `POST /api/v1/preauthkey`. Update `HeadscaleClient` if your deployment exposes different paths or parameters.
- Keys are reusable and cached inside CTFd. Auto-provision and bulk actions skip users who already possess a stored Headscale ID and key to avoid unnecessary API calls.
- The user-facing page never exposes the key until a contestant interacts with the page; similarly, the admin UI hides both API tokens and contestant keys behind reveal buttons to reduce accidental leakage.
- When enforcement is active, double-check that the allowed CIDR list covers all subnets your Headscale deployment assigns. Invalid entries are logged and ignored.

## Potential Improvements

1. Allow administrators to customize the Headscale user naming convention (currently `ctfd-user-<CTFd user ID>`).
2. Allow administrators to configure pre-auth key options (ephemeral, reusable, custom expiration) per event.
3. Sync device status from Headscale so only actively connected participants receive challenge access.
4. Surface pre-auth key usage metrics and audit logs inside the admin dashboard.

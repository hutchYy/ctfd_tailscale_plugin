# CTFd Headscale Integration Plugin

This plugin connects a CTFd instance to a Headscale controller so that event organizers can distribute Tailscale pre-auth keys and optionally restrict challenge access to participants connected through Tailscale.

The implementation follows the [CTFd plugin development guidelines](https://docs.ctfd.io/docs/plugins/overview).

> Tested with Headscale 0.27.0.

## Features

- Admin settings page for Headscale API URL, bearer token (hidden by default with a show/hide toggle), and TLS verification policy.
- Live connectivity probe against `/api/v1/apikey`, validating both API reachability and the configured token.
- Optional challenge enforcement that limits `/challenges` traffic to an approved set of Tailscale CIDR ranges.
- Automatic user provisioning: as soon as a contestant account exists (or logs in) the plugin ensures a Headscale user named `ctfd-user-<CTFd user ID>` exists and issues a reusable pre-auth key.
- **Flexible ACL tagging system** that automatically detects CTFd mode (user vs team) and applies appropriate tags:
  - Auto mode (default): In team mode, tags users with both user ID and team ID; in user mode, tags only with user ID
  - Manual control: Choose from user-only, team-only, both, or no automatic tags
- **Dynamic custom tags**: Add custom tags to individual users via the admin UI for operational needs (e.g., load balancing, feature tiers, regional routing)
- **Automatic load balancer distribution**: Configure N load balancer groups to automatically distribute users evenly across infrastructure with deterministic assignment
- Admin-controlled release window for pre-auth keys — organizers decide when the `/tailscale/key` page reveals the key by toggling **Expose pre-auth keys to contestants**.
- Contestant workflow that keeps commands hidden until the user clicks "Show commands", then presents platform-specific `tailscale up --authkey=… --accept-routes` snippets (macOS, Linux, Windows) ready to copy/paste.
- Admin user management table with on-demand key reveal buttons for each contestant and a bulk "Provision missing users" action to backfill Headscale accounts/keys.

## Installation

1. Copy the `ctfd_tailscale_plugin` package into the CTFd `CTFd/plugins` directory.
2. Enable the plugin by adding `ctfd_tailscale_plugin` to the `plugins` list in `CTFd/config.py` or by setting the `plugins` environment variable.
3. Restart the CTFd service.

The plugin will automatically create tables and run migrations on first load and during upgrades.

## Database Migrations

The plugin manages its database schema automatically:
- **New installations**: Tables are created automatically on first load
- **Upgrades**: Migrations run automatically when the plugin loads

If automatic migration fails, you can run migrations manually:

### Manual Migration (if needed)

If you're upgrading from an older version and need to add the `custom_tags` column:

**SQLite:**
```sql
ALTER TABLE tailscale_user_keys ADD COLUMN custom_tags TEXT;
```

**PostgreSQL:**
```sql
ALTER TABLE tailscale_user_keys ADD COLUMN custom_tags TEXT;
```

**MySQL/MariaDB:**
```sql
ALTER TABLE tailscale_user_keys ADD COLUMN custom_tags TEXT;
```

Alternatively, use the provided migration script in the `migrations/` directory (see below).

### Using the Migration Script

A migration script is provided in `migrations/001_add_custom_tags.py`:

```bash
cd /path/to/ctfd
python -m ctfd_tailscale_plugin.migrations.001_add_custom_tags
```

Or from within your CTFd environment:
```python
from ctfd_tailscale_plugin.migrations import run_migration
run_migration('001_add_custom_tags')
```

## Configuration

Visit **Admin > Headscale Integration** to configure the plugin.

The settings page links to **Headscale Users**, where administrators can inspect every contestant, view the stored Headscale user ID, and regenerate keys on their behalf.

### Headscale API

- **Headscale API URL**: Base URL to the Headscale server (for example `https://headscale.example.com`).
- **Headscale API Token**: Bearer token used when calling the Headscale REST API.
- **Verify TLS certificates**: Disable only when using self-signed certificates during development.
- **Expose pre-auth keys to contestants**: Controls whether `/tailscale/key` reveals the cached key. Leave this unchecked until you are ready to distribute keys.
- **ACL Tag Strategy**: Controls how users are tagged in Headscale ACLs:
  - **Auto** (default): Automatically adapts to CTFd mode — in team mode, tags with both user and team; in user mode, tags only with user
  - **User tags only**: Always tag with `tag:user-{user_id}` regardless of CTFd mode
  - **Team tags only**: Only tag with `tag:team-{team_id}` when user is in a team
  - **Both user and team tags**: Always apply both tags when available
  - **No tags**: Disable automatic tagging for manual ACL management
- **Load Balancer Groups**: Set to a number (1-100) to automatically distribute users across load balancer groups with tags like `tag:lb-group-1`, `tag:lb-group-2`, etc. Set to 0 to disable. Users are distributed evenly using deterministic assignment (user ID modulo group count).

Saving these settings triggers a connectivity check and displays the status banner at the top of the page.

### Challenge Enforcement

- **Require Tailscale for challenges**: Forces all requests to `/challenges` and `/api/v1/challenges` to originate from an allowed CIDR range.
- **Allowed CIDR ranges**: Comma-separated CIDR blocks. Defaults to `100.64.0.0/10`, the standard Tailscale CGNAT range.

Requests that fail the check receive a friendly HTML message, while API clients get a `403` JSON response.

## Managing Custom Tags and Load Balancing

### Custom Tags

Administrators can add custom tags to individual users through the **Headscale Users** page:

1. Click **Edit Tags** next to any user
2. Enter comma-separated tags (e.g., `premium, region-us-east, special-access`)
3. Click **Update tags** - the user's pre-auth key is automatically regenerated with the new tags

Custom tags are preserved when regenerating keys and are useful for:
- **Feature tiers**: Tag users as `premium`, `standard`, `trial`
- **Regional routing**: Tag users with `region-us-east`, `region-eu-west`, etc.
- **Temporary access**: Tag users with `beta-tester`, `early-access`, etc.
- **Manual load balancing**: Tag users with custom load balancer assignments

### Load Balancer Groups

The automatic load balancer feature distributes users evenly across N groups:

1. Go to **Admin > Headscale Integration > Settings**
2. Set **Load Balancer Groups** to the desired number (e.g., 3 for three load balancers)
3. Save settings
4. Users are automatically assigned to groups using `(user_id % N) + 1`
5. View assignments in the **LB Group** column on the **Headscale Users** page

**Example Headscale ACL for 3 load balancers:**
```json
{
  "groups": {
    "group:lb1-users": ["tag:lb-group-1"],
    "group:lb2-users": ["tag:lb-group-2"],
    "group:lb3-users": ["tag:lb-group-3"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["group:lb1-users"],
      "dst": ["loadbalancer1:*"]
    },
    {
      "action": "accept",
      "src": ["group:lb2-users"],
      "dst": ["loadbalancer2:*"]
    },
    {
      "action": "accept",
      "src": ["group:lb3-users"],
      "dst": ["loadbalancer3:*"]
    }
  ]
}
```

## Contestant Experience

- The plugin provisions a Headscale user and pre-auth key automatically the first time a contestant account is created or signs in after the plugin is enabled.
- Organizers control disclosure: when **Expose pre-auth keys to contestants** is off, the `/tailscale/key` page explains that keys are withheld; when turned on, contestants click “Show commands” to reveal OS-specific instructions containing their personal `tailscale up` command (with `--accept-routes` and an optional `--login-server` argument).
- The page is read-only: contestants cannot re-issue keys themselves. They see creation/expiration timestamps and guidance on keeping the key private.

All Headscale usernames follow the `ctfd-user-<CTFd user ID>` pattern. When a key is generated, the plugin:

1. Calls `GET /api/v1/user?name=ctfd-user-<id>` and creates the user via `POST /api/v1/user` if missing (populating display name, email, and picture URL from CTFd).
2. Determines ACL tags based on:
   - **Tag strategy** (auto/user-only/team-only/both/none)
   - **CTFd mode** (users vs teams) - automatically detected
   - **Load balancer groups** (if configured) - adds `tag:lb-group-{N}`
   - **Custom tags** (if set for the user) - adds any administrator-defined tags
3. Issues a reusable pre-auth key through `POST /api/v1/preauthkey`, automatically attaching the determined ACL tags.
4. Stores the resulting Headscale user ID, key, timestamps, custom tags, and optional expiration in CTFd's `tailscale_user_keys` table for reuse.

### ACL Tag Examples

**User mode with auto strategy:**
```
["tag:user-123"]
```

**Team mode with auto strategy:**
```
["tag:user-123", "tag:team-5"]
```

**With load balancer groups (3 groups) and custom tags:**
```
["tag:user-123", "tag:team-5", "tag:lb-group-2", "tag:premium"]
```

## Implementation Overview

- **Configuration compatibility:** Utility helpers wrap `CTFd.config.get_config`/`set_config` so the plugin runs on multiple CTFd versions. The API token field stays masked until explicitly revealed.
- **Headscale client:** `HeadscaleClient` centralizes REST calls (`/api/v1/apikey`, `/api/v1/user`, `/api/v1/preauthkey`) with automatic JSON handling and error reporting.
- **CTFd mode detection:** Automatically detects whether CTFd is running in "users" or "teams" mode by checking the `user_mode` configuration.
- **Flexible tagging system:** `_determine_acl_tags()` function combines strategy-based tags, load balancer group tags, and custom tags to create the final ACL tag list for each user.
- **Provisioning flow:** A `before_request` hook auto-provisions logged-in contestants lacking a key. The admin **Headscale Users** view exposes per-user regeneration plus a bulk action that iterates through every contestant missing a Headscale ID or key. Custom tags are preserved during key regeneration.
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

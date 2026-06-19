# DNF Security Update Console

A single runnable JAR that serves a browser UI and runs `dnf update --security` on remote Linux servers over SSH.

## Build

Requires JDK 17 or newer to build. The build script emits Java 17-compatible bytecode.

```powershell
.\build.ps1
```

The output is:

```text
dist\dnf-security-update-console.jar
```

## Run

Requires Java 17 or newer.

Put the two PPK files next to the JAR, then run:

```powershell
java -jar dnf-security-update-console.jar
```

On Linux servers, use the included launcher so Vault and JVM parameters are passed consistently:

```bash
chmod +x start.sh
VAULT_URI="https://vault.example.com" VAULT_ROLE_ID="..." VAULT_SECRET_ID="..." ./start.sh
```

Open:

```text
http://localhost:8080
```

Vault connection status is available at:

```text
http://localhost:8080/vault
```

The app has 14 built-in authorized patch passphrases. The UI requires one valid passphrase before it will start any patching job.

Every accepted patch launch is logged to `patch-audit.log` beside the JAR with the authorized member slot and target server list. The app stores only SHA-256 hashes of the passphrases in the JAR.

When started with `start.sh`, Vault AppRole settings are loaded from environment variables and matching JVM system properties:

- `VAULT_ENABLED`
- `VAULT_URI`
- `VAULT_ROLE_ID`
- `VAULT_SECRET_ID`
- `VAULT_CONTEXT`
- `VAULT_NAMESPACE`
- `VAULT_TECH_ACCOUNTS_PATH`

At startup the app connects to Vault with AppRole login and reports `UP`, `DOWN`, or `DISABLED` on `/vault`. Role ID and secret ID values are never shown in the UI.

For hard reboot recovery, store one or more technical accounts in the Vault secret referenced by `VAULT_TECH_ACCOUNTS_PATH` or, by default, `VAULT_CONTEXT`. The app searches the secret recursively for objects containing:

```json
{
  "cmaas_oauth_token_url": "oauth-token-url",
  "ocs_endpoints": [
    {
      "region": "paris-or-north",
      "ocs_servers_url": "ocs-server-detail-url",
      "ocs_server_action_url": "ocs-server-action-url-or-template-with-%s"
    }
  ],
  "technical_accounts": {
    "TRIG-DEV": {
      "account_id": "account-id",
      "client_id": "oauth-client-id",
      "client_secret": "oauth-client-secret"
    }
  }
}
```

The URL fields can be at the top level of the secret or nested anywhere inside it. Each key under `technical_accounts`, such as `TRIG-DEV`, becomes the account name displayed in the UI. An account object may alternatively provide an explicit `name` field.

For example, one Vault secret can contain shared cloud API URLs and multiple technical accounts:

```json
{
  "cmaas_oauth_token_url": "https://cmaas.example.com/oauth/token",
  "ocs_endpoints": [
    {
      "region": "paris",
      "ocs_servers_url": "https://ocs-paris.example.com/v1/servers",
      "ocs_server_action_url": "https://ocs-paris.example.com/v1/servers/%s/action"
    },
    {
      "region": "north",
      "ocs_servers_url": "https://ocs-north.example.com/v1/servers",
      "ocs_server_action_url": "https://ocs-north.example.com/v1/servers/%s/action"
    }
  ],
  "technical_accounts": {
    "TRIG-DEV": {
      "account_id": "technical-account-dev",
      "client_id": "oauth-client-id-dev",
      "client_secret": "replace-with-client-secret-dev"
    },
    "TRIG-INT": {
      "account_id": "technical-account-int",
      "client_id": "oauth-client-id-int",
      "client_secret": "replace-with-client-secret-int"
    },
    "TRIG-PROD": {
      "account_id": "technical-account-prod",
      "client_id": "oauth-client-id-prod",
      "client_secret": "replace-with-client-secret-prod"
    }
  }
}
```

Store this object at the path configured by `VAULT_TECH_ACCOUNTS_PATH`. Replace the example URLs and credentials with real values; do not commit client secrets to the repository. Before starting a job, select the account name that owns the submitted servers. During hard reboot recovery, the app uses only that selected account and searches the Paris and North OCS endpoints in their stored order. A legacy secret containing one top-level OCS URL pair remains supported.

When a server is not reachable over SSH after the normal reboot wait, the app:

1. Loads the technical account selected for the patch job.
2. Requests a CMAAS OAuth token for that account only.
3. Calls each Paris/North OCS servers URL fetched from Vault.
4. Matches the input server by `accessIPv4` or server `name`.
5. Calls the OCS server action URL fetched from Vault with `{"reboot":{"type":"HARD"}}`.
6. Checks SSH again every 10 seconds for up to 5 minutes.

When reboot is enabled, the app records the Linux boot ID, sends the reboot command in the background, then checks SSH every 10 seconds for up to 5 minutes. As soon as the server is reachable, it reads the boot ID again. After confirming the reboot, it runs `sudo -n systemctl enable otelcol-contrib.service` and `sudo -n systemctl start otelcol-contrib.service`, then performs the configured service health checks. If any configured health check returns HTTP 200, the service is marked up and only that working health check is shown.

Post-reboot machine and service status is stored in:

```text
status-checks.tsv
```

To browse post-reboot status checks from the app, open:

```text
http://localhost:8080/status
```

Each completed run also creates a timestamped HTML report beside the JAR:

```text
reports\patch-report-YYYYMMDD-HHMMSS-<run-id>.html
```

Patch reports include each server's status, RHSA advisories available to install, RHSA advisories corrected by the run, and all installed RHSA advisories reported by the OS.

Dry run mode generates the report without running `dnf update`, `sync`, `needs-restarting`, or reboot commands. It only checks what RHSA advisories are available to install and what RHSA advisories are already installed in the OS.

Dry run reports are saved as:

```text
reports\dryrun-report-YYYYMMDD-HHMMSS-<run-id>.html
```

Dry run report columns are:

- Server
- Status
- RHSA Available To Install
- All Installed RHSA In The OS

To browse reports from the app, open:

```text
http://localhost:8080/patching
```

Dry run reports are available at:

```text
http://localhost:8080/dryrun
```

Reports are listed newest first and can be opened directly from those pages.

To use another port:

```powershell
$env:DNF_UPDATE_PORT="9090"
java -jar dnf-security-update-console.jar
```

## Defaults

- SSH user: `cloud-user`
- Primary key: `key1.ppk`
- Fallback key: `key2.ppk`
- Command: `sudo -n dnf -y update --security`
- Pre-reboot cleanup: `sudo -n dnf -y remove --oldinstallonly`
- Reboot: enabled by default
- Post-reboot service commands: `sudo -n systemctl enable otelcol-contrib.service`, then `sudo -n systemctl start otelcol-contrib.service`
- Audit log: `patch-audit.log`
- Post-reboot status log: `status-checks.tsv`
- HTML reports: `reports\patch-report-YYYYMMDD-HHMMSS-<run-id>.html`
- Dry run reports: `reports\dryrun-report-YYYYMMDD-HHMMSS-<run-id>.html`

The app expects `cloud-user` to have passwordless sudo for `dnf` cleanup/update, reboot, and the post-reboot `systemctl` commands. If the primary PPK key cannot authenticate, it automatically tries the fallback key.

## UI Features

- One server IP or hostname per line
- Live per-server command output
- Per-server status pills
- Success and failure counters
- Optional DNF cache refresh
- Optional `--skip-broken`
- Dry run report mode with no patching or reboot
- Required patch passphrase
- Timestamped HTML report after each run
- `/patching` report browser ordered by date
- `/dryrun` dry run report browser ordered by date
- `/status` post-reboot machine and service status ordered by date
- `/vault` Vault AppRole connection status
- Configurable SSH port, timeout, key filenames, and parallel server count

# dnfupdate

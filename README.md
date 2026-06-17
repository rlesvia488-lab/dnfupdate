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

Open:

```text
http://localhost:8080
```

The app has 14 built-in authorized patch passphrases. The UI requires one valid passphrase before it will start any patching job.

Every accepted patch launch is logged to `patch-audit.log` beside the JAR with the authorized member slot and target server list. The app stores only SHA-256 hashes of the passphrases in the JAR.

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
- Reboot: enabled by default
- Audit log: `patch-audit.log`
- HTML reports: `reports\patch-report-YYYYMMDD-HHMMSS-<run-id>.html`
- Dry run reports: `reports\dryrun-report-YYYYMMDD-HHMMSS-<run-id>.html`

The app expects `cloud-user` to have passwordless sudo for `dnf` and reboot commands. If the primary PPK key cannot authenticate, it automatically tries the fallback key.

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
- Configurable SSH port, timeout, key filenames, and parallel server count

# dnfupdate

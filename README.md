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

On first startup, the app creates 14 patch passphrases next to the JAR:

```text
patch-passphrases.txt
```

Give one passphrase to each authorized member. The UI requires a valid passphrase before it will start any patching job. Keep this file private; delete it and restart the app to generate a new set.

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
- Passphrase file: `patch-passphrases.txt`

The app expects `cloud-user` to have passwordless sudo for `dnf` and reboot commands. If the primary PPK key cannot authenticate, it automatically tries the fallback key.

## UI Features

- One server IP or hostname per line
- Live per-server command output
- Per-server status pills
- Success and failure counters
- Optional DNF cache refresh
- Optional `--skip-broken`
- Required patch passphrase
- Configurable SSH port, timeout, key filenames, and parallel server count

# dnfupdate

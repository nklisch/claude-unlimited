# Installing and maintaining this fork

This is a fork of [DevDock-AI/claude-unlimited](https://github.com/DevDock-AI/claude-unlimited),
based on upstream version 1.3.1. The first fork build is 1.3.2. The upstream
license and attribution are preserved.

## Install or update

Linux and macOS need Python 3.10+, git, and Claude Code on `PATH`:

```bash
curl -fsSL https://raw.githubusercontent.com/nklisch/claude-unlimited/main/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/nklisch/claude-unlimited/main/install.ps1 | iex
```

To read the code before installing:

```bash
git clone https://github.com/nklisch/claude-unlimited.git
cd claude-unlimited
./install.sh
```

Re-run the same installer to update to the fork's `main` branch. It replaces
the installed application, installs the package, and restarts the daemon.
Schedule an update between requests: restarting the proxy interrupts requests
currently passing through it. Existing accounts, credentials, thresholds,
and usage history under `~/.claude-unlimited/` are preserved. No new logins
are required just to reinstall on the same machine.

The shell installer supports `CLAUDE_UNLIMITED_BRANCH` to select a branch or
tag and `CLAUDE_UNLIMITED_REPO` to override its clone URL. Windows supports
`CLAUDE_UNLIMITED_BRANCH`. The defaults download this fork.

The dashboard updater checks **published releases in this fork only**. It
does not install upstream releases or track commits on `main`. Until fork
releases are published, use the install command above for updates. The macOS
HUD additionally needs a binary asset attached to the corresponding fork
release; no new HUD binaries are supplied with this initial source build.

On Linux, installation enables the user service and attempts to enable
lingering so it survives logout. The generated service uses `Restart=always`
with a two-second delay. An explicit `systemctl --user stop
claude-unlimited.service` still leaves it stopped.

## Changes carried by the fork

- Quota routing preserves weekly exhaustion independently of the five-hour
  window. Each profile has separate five-hour and weekly switch thresholds;
  new profiles default to 98% for both. Older configurations inherit their
  existing threshold for the weekly setting.
- Enabled subscription accounts' usage is polled about every five minutes,
  including while idle or handling requests, using read-only endpoints. The
  polling clock survives restarts, requests are staggered, and provider and
  account backoff remain. Settings can disable these reads.
- The dashboard shows each window's reset countdown and exact local reset
  time. A missing timestamp means the provider has not reported one for
  that window. A zero-usage five-hour window may have no reset time.
- Request bodies can be up to 128 MiB. Upstream socket timeouts are 900
  seconds. Retryable failures get up to three attempts with backoff before
  considering another account. Inference retries wait out `Retry-After`
  values up to 900 seconds; a longer wait ends the same-account retry loop
  without retrying early. Usage polling preserves longer provider waits.
  This is not a guarantee that a client or provider will wait that long.
- Streaming reads forward available chunks promptly. Bounded diagnostics
  record incomplete streams and rotation/retry reasons without logging
  request bodies or credentials. Partial streamed output is not replayed.
- Dashboard reads retry once if a response cannot be decoded as JSON.
  Persistent failures show a readable message and log the failing endpoint,
  status, and attempt in the browser console, without response contents.
  Writes are never replayed by this recovery path.
- Linux credentials use disk storage first, so keyring outages do not
  break ordinary requests. See the storage policy below.

Use `claude-unlimited code` (or `cu code`) to launch Claude Code through the
pool. For the same 15-minute client timeout as the upstream socket timeout:

```bash
API_TIMEOUT_MS=900000 claude-unlimited code
```

Pointing ordinary `claude` sessions at the pool through Claude Code's own
settings remains a per-machine choice. The installer does not overwrite
`~/.claude/settings.json` or include anyone's local settings.

## Credentials and moving machines

On Linux, complete credential records are plaintext files under
`~/.claude-unlimited/secrets/`. The directory is mode 0700 and files are
mode 0600. Filenames are hashes of profile IDs; hashing the filename does
not encrypt the content. Secret Service is consulted only for a missing
disk entry, and new writes are mirrored to the keyring as a best effort.
Deletion markers prevent stale keyring entries from restoring a removed
credential. macOS Keychain and Windows DPAPI keep their upstream behavior.

To move accounts, use the dashboard's passphrase-encrypted Export on the
old machine, install this fork on the new one, and Import the bundle.
Keep the passphrase separate from the bundle. Provider-side token expiry
or revocation can still require a login. This repository contains source
code only, with no accounts, credentials, logs, or machine configuration.

## Maintenance and verification

`origin` should be this fork and `upstream` should be DevDock-AI's repository.
Merge upstream deliberately and retain the fork's installer/updater source,
storage policy, quota handling, and reliability changes. Do not replace the
installed package from upstream when refreshing the fork.

The initial fork imports code already used in the owner's Linux installation.
The source and installation wiring were reviewed; no tests, syntax checks,
provider probes, or fresh installation were run for this import, at the
owner's request. macOS and Windows have not been exercised for these changes.
Existing upstream tests are retained, but importing the changes does not
establish that the suite passes. Some inherited usage-polling tests still
reference the previous polling interface; reconcile those before using the
test-gated release workflow.

"""Linux implementation of the secret-store interface: credential FILES on
disk, with the Secret Service (through the `secret-tool` CLI from libsecret)
kept as a best-effort mirror and as the source of the one-time migration.

This fork uses a plaintext disk copy on Linux so ordinary requests do not
depend on D-Bus or a running keyring provider. The disk copy is authoritative
once it exists:

  * Location: <config.APP_DIR>/secrets/ (resolved at CALL time), directory
    0700, one file per profile, mode 0600. The file name is the SHA-256 of the
    profile id's UTF-8 bytes in hex plus ".cred", so any id maps to one safe,
    collision-free name. The content is the exact credential string.
  * get_token reads the file; a request never touches secret-tool/D-Bus. Only
    when no file exists is the keyring consulted, and what it returns is
    persisted (create-only, never over an existing file) so that is done once.
  * set_token writes the file atomically (temp file in the same directory,
    fsync, os.replace) BEFORE the best-effort keyring mirror; a missing or
    failing keyring never fails a successful disk write.
  * delete_token replaces the file with a tombstone, then clears the keyring
    as a best effort. The tombstone STAYS until a later set_token overwrites
    it: a keyring lookup already in flight, or a keyring that could not be
    cleared (or a secret-tool that returns later), must never be able to
    bring the deleted secret back through the migration path. It is a tiny
    file; deleting it is not worth that risk.
  * An unreadable or corrupt file is reported as a disk error. It is never
    papered over with a possibly stale (refresh-token-bearing) keyring copy.

Every keyring call is bounded by a timeout. Failures are logged to the
Activity log as metadata only (return code, exception class, errno, and a
fixed category matched from stderr) — never stdout, stderr, arguments, tokens
or exception text.

See docs/adr/0002-pluggable-secret-store-and-daemon-installer.md — this is
still the ONLY file that shells out to `secret-tool`. Callers use
claude_unlimited.secret_store, never this module directly.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Optional

from .. import config

SERVICE = "claude-unlimited.oauth"

# Longest any single secret-tool call may take. A locked keyring waiting on a
# prompt would otherwise hold an add, a token refresh or a delete indefinitely.
KEYRING_TIMEOUT_SECONDS = 5.0

# Written in place of a credential when it is deleted, and kept until a later
# set_token overwrites it. NUL bytes cannot occur in a real credential string.
_TOMBSTONE = b"\x00claude-unlimited:deleted\x00"

# Serialises every disk read-modify-write of a credential file in this process
# (set, delete, and the check-then-persist step of the keyring migration), so a
# migration can never overwrite a newer set_token/delete_token. Not held across
# keyring calls, so a stuck keyring never blocks a request's get_token.
_LOCK = threading.Lock()
# Serialises keyring mirror calls so they converge on the latest disk state.
# Always taken BEFORE _LOCK, never the other way round.
_MIRROR_LOCK = threading.Lock()

# At most one Activity line per (profile, action, reason) per this long.
_LOG_INTERVAL_SECONDS = 300.0
_logged_at: dict = {}


class SecretStoreError(RuntimeError):
    pass


# ---- paths -------------------------------------------------------------------

def _path_for(profile_id: str):
    digest = hashlib.sha256(profile_id.encode("utf-8", "surrogatepass")).hexdigest()
    return config.APP_DIR / "secrets" / f"{digest}.cred"


def _disk_error(profile_id: str, what: str, exc: BaseException) -> SecretStoreError:
    # Class and errno only: an exception's own text is not logged or surfaced.
    return SecretStoreError(
        f"The stored credential for profile {profile_id!r} {what} "
        f"({type(exc).__name__}, errno {getattr(exc, 'errno', None)})."
    )


def _read_state(profile_id: str, path) -> tuple:
    """("value", text) | ("deleted", "") | ("absent", ""). A file that exists but
    cannot be read, is empty, or is not UTF-8 is a disk error, not a miss."""
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return "absent", ""
    except OSError as exc:
        raise _disk_error(profile_id, "could not be read from disk", exc) from None
    if raw == _TOMBSTONE:
        return "deleted", ""
    if not raw:
        raise SecretStoreError(f"The stored credential file for profile {profile_id!r} is empty.")
    try:
        return "value", raw.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        raise SecretStoreError(
            f"The stored credential file for profile {profile_id!r} is not valid text.") from None


def _fsync_dir(directory) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write(profile_id: str, path, data: bytes, exclusive: bool = False) -> bool:
    """Atomically puts `data` at `path`: a temp file in the same directory,
    fsync'd, then os.replace. Directory 0700, file 0600. With exclusive=True
    nothing is ever replaced (a hard link is the create-only step, atomic even
    across the daemon and CLI processes): it returns False if the file already
    exists, and a link that fails for any other reason is a disk error. Caller
    holds _LOCK."""
    directory = path.parent
    tmp = None
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-")
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        if exclusive:
            try:
                os.link(tmp, path)          # create-only: never replaces what is there
            except FileExistsError:
                return False
        else:
            os.replace(tmp, path)
            tmp = None
        _fsync_dir(directory)
        return True
    except OSError as exc:
        raise _disk_error(profile_id, "could not be written to disk", exc) from None
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


# ---- keyring (secret-tool), always bounded and always quiet ---------------------

# First match wins. Matched against lower-cased stderr, which is never kept.
_STDERR_CATEGORIES = (
    ("locked", ("locked", "unlock", "dismissed", "cancelled", "canceled")),
    ("session_missing", ("can't find session", "can\u2019t find session", "cannot find session",
                         "no session", "dbus_session_bus_address", "autolaunch", "$display")),
    ("no_provider", ("not provided by any", "serviceunknown", "org.freedesktop.secrets")),
    ("bus_unavailable", ("connection refused", "failed to connect", "could not connect",
                         "cannot connect", "dbus", "d-bus", "no such file or directory", "socket")),
)


def _stderr_category(stderr: str) -> str:
    text = (stderr or "").lower()
    for category, needles in _STDERR_CATEGORIES:
        if any(needle in text for needle in needles):
            return category
    return "other"


def _keyring_call(args: list, stdin: Optional[str] = None) -> tuple:
    """One bounded secret-tool call -> (kind, stdout, reason).

    kind: "ok" | "missing" (non-zero exit with nothing on stderr: the lookup's
    way of saying "no such item") | "absent" (secret-tool is not installed) |
    "error". `reason` is a safe description — return code, exception class and
    errno, or a fixed category — never output text."""
    if shutil.which("secret-tool") is None:
        return "absent", "", "secret-tool not installed"
    try:
        result = subprocess.run(args, input=stdin, capture_output=True, text=True,
                                timeout=KEYRING_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return "error", "", f"timeout after {KEYRING_TIMEOUT_SECONDS:.0f}s"
    except OSError as exc:
        return "error", "", f"{type(exc).__name__} errno={exc.errno}"
    except Exception as exc:  # noqa: BLE001 - e.g. a ValueError from the arguments
        return "error", "", type(exc).__name__
    if result.returncode == 0:
        return "ok", result.stdout or "", ""
    if not (result.stderr or "").strip():
        return "missing", "", f"returncode={result.returncode}"
    return "error", "", f"returncode={result.returncode}, category={_stderr_category(result.stderr)}"


def _note(profile_id: str, action: str, reason: str, category: str = "error") -> None:
    """One metadata-only Activity line, at most once per interval for the same
    thing. Never raises."""
    key = (profile_id, action, reason)
    now = time.monotonic()
    last = _logged_at.get(key)
    if last is not None and now - last < _LOG_INTERVAL_SECONDS:
        return
    _logged_at[key] = now
    try:
        from .. import activity   # lazy: keeps this module free of import-order concerns
        activity.record(
            category, "Linux credential store: keyring problem (the disk copy is authoritative)",
            meta=json.dumps({"action": action, "profile_id": profile_id, "reason": reason},
                            separators=(",", ":")))
    except Exception:  # noqa: BLE001 - diagnostics must never break the operation
        pass


def _mirror(profile_id: str) -> None:
    """Best effort: bring the keyring in line with the disk state. A value is
    stored; a tombstone clears the keyring entry. The tombstone itself is never
    removed here — only a later set_token replaces it. Never raises: a
    successful disk write must stay successful."""
    try:
        path = _path_for(profile_id)
        with _MIRROR_LOCK:
            with _LOCK:
                state, value = _read_state(profile_id, path)
            if state == "value":
                kind, _, reason = _keyring_call(
                    ["secret-tool", "store", "--label", f"Claude Unlimited: {profile_id}",
                     "service", SERVICE, "account", profile_id], stdin=value)
                if kind not in ("ok", "absent"):
                    _note(profile_id, "keyring_store_failed", reason)
                return
            kind, _, reason = _keyring_call(["secret-tool", "clear", "service", SERVICE, "account", profile_id])
            if kind not in ("ok", "absent"):
                _note(profile_id, "keyring_clear_failed", reason)
    except Exception:  # noqa: BLE001
        pass


# ---- the interface -------------------------------------------------------------

def set_token(profile_id: str, token: str) -> None:
    path = _path_for(profile_id)
    with _LOCK:
        _write(profile_id, path, token.encode("utf-8", "surrogatepass"))
    _mirror(profile_id)


def get_token(profile_id: str) -> str:
    path = _path_for(profile_id)
    with _LOCK:
        state, value = _read_state(profile_id, path)
    if state == "value":
        return value
    if state == "deleted":
        raise SecretStoreError(f"No stored credential found for profile {profile_id!r}.")

    # No file: the first use after this backend was installed (or no
    # credential at all). Ask the keyring once, outside any lock.
    kind, stdout, reason = _keyring_call(["secret-tool", "lookup", "service", SERVICE, "account", profile_id])
    # secret-tool lookup prints the secret with no trailing newline; strip
    # defensively, matching macos_keychain.get_token.
    secret = stdout.strip() if kind == "ok" else ""
    if not secret:
        if kind == "error":
            _note(profile_id, "keyring_lookup_failed", reason)
            raise SecretStoreError(
                f"No stored credential found for profile {profile_id!r}; "
                f"the system keyring could not be read ({reason}).")
        raise SecretStoreError(f"No stored credential found for profile {profile_id!r}.")

    with _LOCK:
        for _ in range(3):
            # Re-check: a set_token or delete_token (here, or in another
            # process) may have run while the keyring was being asked, and its
            # result is newer than this lookup. Only an absent file may be
            # filled from the keyring, and only by a create-only write.
            state, value = _read_state(profile_id, path)
            if state == "value":
                return value
            if state == "deleted":
                raise SecretStoreError(f"No stored credential found for profile {profile_id!r}.")
            try:
                created = _write(profile_id, path, secret.encode("utf-8", "surrogatepass"), exclusive=True)
            except SecretStoreError as exc:
                # Could not persist it (disk full, read-only, no hard links).
                # The credential is still good: serve it from the keyring, as
                # before, and say why. The message holds only a class and errno.
                _note(profile_id, "migration_write_failed", str(exc))
                return secret
            if created:
                return secret
            # The file appeared between the check and the write: look again.
        raise SecretStoreError(
            f"The stored credential for profile {profile_id!r} kept changing while it was being read; try again.")


def delete_token(profile_id: str) -> None:
    path = _path_for(profile_id)
    with _LOCK:
        # If the tombstone cannot be written the deletion has not happened: the
        # error propagates and the previous state is left exactly as it was
        # (unlinking the copy instead could let a keyring that failed to clear
        # bring the old secret back).
        _write(profile_id, path, _TOMBSTONE)
    _mirror(profile_id)


def has_token(profile_id: str) -> bool:
    try:
        return bool(get_token(profile_id))
    except Exception:
        return False

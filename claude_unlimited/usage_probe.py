"""Keeps enabled subscription accounts' usage numbers fresh, including idle
accounts and accounts serving continuous traffic.

Usage percentages normally arrive passively, in the rate-limit headers of real
responses, so an account nobody has routed to lately shows a stale number or
"not yet observed". This reads the providers' own read-only usage endpoints —
the ones Claude Code's `/usage` and the Codex CLI read — which report the same
windows without sending a message.

It is automated traffic against third-party APIs on the user's own
credentials, so it is deliberately gentle (ADR 0001, amended 2026-09-15):

  * Read each account about every five minutes, even while idle. Endpoint
    poll times are separate from passive response observations, so continuous
    traffic cannot postpone a read. At most two accounts are read per tick.
  * Hard, escalating, persisted backoff. A 429 honours Retry-After, waits at
    least 15 minutes, doubles up to 6 hours (longer if requested by the
    provider), and pauses that whole provider. A
    401/403 (for example a token without the usage scope) waits hours and never
    marks the account itself broken — only a real request does that. Anything
    else backs off from 5 minutes to an hour. The state survives restarts, so
    restarting the daemon can never produce a burst.

`Scheduler` is bookkeeping only (injectable clock; its one side effect is a
small state file). The HTTP calls are fetch_anthropic_usage/fetch_codex_usage,
and `_urlopen` is the single network seam, which the test suite replaces.
"""

from __future__ import annotations

import json
import math
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Callable, Optional

from . import config

ANTHROPIC_USAGE_URL = "https://api.anthropic.com/api/oauth/usage"
ANTHROPIC_OAUTH_BETA = "oauth-2025-04-20"
# The client string this read is sent with. Upstream-watch item: if these reads
# start failing after a Claude Code release, re-check it against the release.
CLAUDE_CODE_USER_AGENT = "claude-cli/2.1.272 (external, cli)"
CODEX_USAGE_URL = "https://chatgpt.com/backend-api/wham/usage"

PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"

BASE_INTERVAL_SECONDS = 300.0
MAX_PROBES_PER_TICK = 2             # spreads a burst of due accounts over ticks
TICK_SECONDS = 30.0
REQUEST_TIMEOUT_SECONDS = 10.0

RATE_LIMIT_BACKOFF_SECONDS = 900.0
RATE_LIMIT_BACKOFF_CEILING_SECONDS = 6 * 3600.0
AUTH_BACKOFF_SECONDS = 3600.0
AUTH_BACKOFF_CEILING_SECONDS = 24 * 3600.0
FAILURE_BACKOFF_SECONDS = 300.0
FAILURE_BACKOFF_CEILING_SECONDS = 3600.0
FAILURES_BEFORE_LOGGING = 3

_BACKOFF = {
    "rate_limited": (RATE_LIMIT_BACKOFF_SECONDS, RATE_LIMIT_BACKOFF_CEILING_SECONDS),
    "auth": (AUTH_BACKOFF_SECONDS, AUTH_BACKOFF_CEILING_SECONDS),
    "failure": (FAILURE_BACKOFF_SECONDS, FAILURE_BACKOFF_CEILING_SECONDS),
}

_urlopen = urllib.request.urlopen  # the one network seam


def provider_for(profile) -> Optional[str]:
    """Which usage endpoint can serve this Profile — or None when none can
    without spending quota: API-key Profiles have no subscription windows."""
    if profile.kind == "oauth":
        return PROVIDER_ANTHROPIC
    if profile.kind == "codex" and profile.auth_mode != "api_key":
        return PROVIDER_OPENAI
    return None


@dataclass(frozen=True)
class ProbeResult:
    status: Optional[int]           # None: no HTTP response at all
    headers: Optional[dict] = None  # synthesized rate-limit headers, on a readable 200
    retry_after: Optional[float] = None
    # Per-model windows. Headers cannot express these, so they ride beside
    # them. None when the source has none.
    model_windows: Optional[tuple] = None


@dataclass(frozen=True)
class Candidate:
    profile_id: str
    provider: str


# ---- HTTP -------------------------------------------------------------------

def _number(value) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except OverflowError:
        return None
    return number if math.isfinite(number) else None


def _percentage(value) -> Optional[float]:
    number = _number(value)
    # An over-limit reading still means spent; do not discard the account's
    # other usage windows just because the provider reports an overshoot.
    return number if number is not None and number >= 0 else None


def _parse_retry_after(value) -> Optional[float]:
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        if not isinstance(value, str):
            return None
        try:
            retry_at = parsedate_to_datetime(value)
            if retry_at.tzinfo is None:
                retry_at = retry_at.replace(tzinfo=timezone.utc)
            seconds = retry_at.timestamp() - time.time()
        except (TypeError, ValueError, OverflowError, OSError):
            return None
    return seconds if math.isfinite(seconds) and seconds > 0 else None


def _get(url: str, headers: dict) -> tuple[Optional[int], Optional[float], Optional[object]]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with _urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            raw = response.read()
            status = response.status
    except urllib.error.HTTPError as exc:
        return exc.code, _parse_retry_after(exc.headers.get("retry-after") if exc.headers else None), None
    except (urllib.error.URLError, OSError, ValueError):
        return None, None, None
    try:
        return status, None, json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return status, None, None


def fetch_anthropic_usage(access_token: str) -> ProbeResult:
    status, retry_after, body = _get(ANTHROPIC_USAGE_URL, {
        "Authorization": f"Bearer {access_token}",
        "anthropic-beta": ANTHROPIC_OAUTH_BETA,
        "anthropic-version": "2023-06-01",
        "User-Agent": CLAUDE_CODE_USER_AGENT,
        "Accept": "application/json",
    })
    if status != 200:
        return ProbeResult(status=status, retry_after=retry_after)
    return ProbeResult(status=200, headers=anthropic_usage_headers(body),
                       model_windows=anthropic_model_windows(body))


def fetch_codex_usage(credential) -> ProbeResult:
    from . import openai_bridge

    headers = {
        "Authorization": f"Bearer {credential.access_token}",
        "originator": openai_bridge.ORIGINATOR,
        "User-Agent": openai_bridge._codex_user_agent(),
        "Accept": "application/json",
    }
    if credential.account_id:
        headers["ChatGPT-Account-ID"] = credential.account_id
    status, retry_after, body = _get(CODEX_USAGE_URL, headers)
    if status != 200:
        return ProbeResult(status=status, retry_after=retry_after)
    return ProbeResult(status=200, headers=codex_usage_headers(body),
                       model_windows=codex_model_windows(body))


# ---- response -> the headers the existing classifiers read ------------------

def anthropic_usage_headers(body) -> Optional[dict]:
    """`/api/oauth/usage` -> the `anthropic-ratelimit-unified-*` headers that
    observation.classify() already understands, so a reading here lands in
    exactly the pipeline a real response does. The endpoint reports
    utilization as a percentage (46.0 means 46%); the headers carry 0-1.
    Current limits[] account rows take precedence over legacy window fields.
    None when the 5-hour account window is unreadable: the existing classifier
    needs it to accept a snapshot, so never invent zero usage for it."""
    if not isinstance(body, dict):
        return None
    headers: dict = {}
    entries = {}
    for window, prefix in (("five_hour", "5h"), ("seven_day", "7d")):
        entry = body.get(window)
        if isinstance(entry, dict) and _percentage(entry.get("utilization")) is not None:
            entries[prefix] = (entry["utilization"], entry.get("resets_at"))
    if isinstance(body.get("limits"), list):
        for row in body["limits"]:
            if not isinstance(row, dict):
                continue
            kind = row.get("kind")
            prefix = "5h" if kind == "session" else "7d" if kind == "weekly_all" else None
            utilization = _percentage(row.get("percent"))
            if prefix is not None and utilization is not None:
                entries[prefix] = (utilization, row.get("resets_at"))
    for prefix, (utilization, resets_at) in entries.items():
        headers[f"anthropic-ratelimit-unified-{prefix}-utilization"] = str(utilization / 100)
        reset = _epoch_or_iso(resets_at) if isinstance(resets_at, str) else None
        if reset is not None:
            headers[f"anthropic-ratelimit-unified-{prefix}-reset"] = str(int(reset.timestamp()))
    return headers if "anthropic-ratelimit-unified-5h-utilization" in headers else None


def anthropic_model_windows(body) -> tuple:
    """`limits[]` rows of kind `weekly_scoped` with a model display name ->
    ModelWindow, e.g. Fable at 26%. The same numbers Claude Code's `/usage`
    prints as "Current week (Fable)".

    `percent` is already 0-100 here. `scope.model.id` is null upstream, so the
    display name is the only identifier and is kept verbatim. Anything
    unreadable is skipped — never an exception, never a guessed name."""
    from .observation import ModelWindow

    if not isinstance(body, dict) or not isinstance(body.get("limits"), list):
        return ()
    windows = []
    seen = set()
    for row in body["limits"]:
        if not isinstance(row, dict) or row.get("kind") != "weekly_scoped":
            continue
        scope = row.get("scope") if isinstance(row.get("scope"), dict) else {}
        model = scope.get("model") if isinstance(scope.get("model"), dict) else {}
        name = model.get("display_name")
        percent = _percentage(row.get("percent"))
        if not isinstance(name, str) or not name.strip() or percent is None:
            continue
        name = name.strip()
        if name.lower() in seen:
            continue
        seen.add(name.lower())
        resets_at = None
        if isinstance(row.get("resets_at"), str):
            try:
                resets_at = datetime.fromisoformat(row["resets_at"].replace("Z", "+00:00"))
                if resets_at.tzinfo is None:
                    resets_at = resets_at.replace(tzinfo=timezone.utc)
            except ValueError:
                resets_at = None
        windows.append(ModelWindow(name=name, percent=round(percent, 2), resets_at=resets_at,
                                   active=row.get("is_active") is True))
    return tuple(windows)


def codex_model_windows(body) -> tuple:
    """`model_usage` from `/wham/usage` -> ModelWindow, the Codex counterpart
    of anthropic_model_windows().

    The two providers report fundamentally different things and the shape here
    reflects that. Anthropic gives a PERCENTAGE per model; OpenAI gives only
    availability:

        "model_usage": {"gpt-6-astra": {"available": true,
                                         "available_at": null,
                                         "credits_would_enable": false}}

    There is no "astra is at 62%" anywhere in that payload, so a Codex bucket
    is binary: 0 when the model is available, 100 when it is not. That still
    drives the same "is this model blocked on this account" question the
    routing rule asks — the percentage is merely how an Anthropic bucket
    answers it.

    Named by the OpenAI model id, because that is what the provider said is
    unavailable and what a user needs to see. Anything unreadable is skipped;
    never an exception."""
    from .observation import ModelWindow

    if not isinstance(body, dict) or not isinstance(body.get("model_usage"), dict):
        return ()
    windows = []
    for name, entry in body["model_usage"].items():
        if not isinstance(name, str) or not name.strip() or not isinstance(entry, dict):
            continue
        available = entry.get("available")
        if not isinstance(available, bool):
            continue  # unknown availability is not the same as unavailable
        windows.append(ModelWindow(
            name=name.strip(),
            percent=0.0 if available else 100.0,
            resets_at=_epoch_or_iso(entry.get("available_at")),
            # The provider naming a model unavailable IS the binding limit on
            # this account, which is what `active` means for the display.
            active=not available,
        ))
    return tuple(windows)


def _epoch_or_iso(value) -> Optional[datetime]:
    """`available_at` has been seen as null on an unconstrained account and is
    undocumented otherwise, so accept both an epoch number and an ISO string
    rather than guessing one and dropping the other."""
    number = _number(value)
    if number is not None:
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    return None


def codex_usage_headers(body) -> Optional[dict]:
    """`/wham/usage` -> the `x-codex-*` headers openai_observation.classify()
    reads from a real Codex response. None when neither window is present."""
    if not isinstance(body, dict) or not isinstance(body.get("rate_limit"), dict):
        return None
    rate_limit = body["rate_limit"]
    headers: dict = {}
    for slot in ("primary", "secondary"):
        window = rate_limit.get(f"{slot}_window")
        if not isinstance(window, dict) or _percentage(window.get("used_percent")) is None:
            continue
        headers[f"x-codex-{slot}-used-percent"] = str(_number(window["used_percent"]))
        if _number(window.get("reset_at")) is not None:
            headers[f"x-codex-{slot}-reset-at"] = str(int(window["reset_at"]))
        if _number(window.get("reset_after_seconds")) is not None:
            headers[f"x-codex-{slot}-reset-after-seconds"] = str(int(window["reset_after_seconds"]))
        if _number(window.get("limit_window_seconds")) is not None:
            headers[f"x-codex-{slot}-window-minutes"] = str(round(window["limit_window_seconds"] / 60))
    if not headers:
        return None
    if isinstance(body.get("plan_type"), str):
        headers["x-codex-plan-type"] = body["plan_type"]
    return headers


# ---- scheduling ---------------------------------------------------------------

def _human(seconds: float) -> str:
    minutes = round(seconds / 60)
    return f"{minutes} min" if minutes < 90 else f"{round(seconds / 3600, 1):g} h"


class Scheduler:
    def __init__(self, clock: Callable[[], float] = time.time, state_file: Optional[Path] = None):
        self._clock = clock
        self._state_file = state_file
        self._lock = threading.Lock()
        self._activity_seen = False
        self._state: Optional[dict] = None  # loaded lazily, never at import

    # -- initial activity wakeup --
    def note_activity(self) -> bool:
        """Wake an initial check on first activity; later reads use the timer."""
        with self._lock:
            first = not self._activity_seen
            self._activity_seen = True
        return first

    # -- what to read now --
    def due(self, candidates: list[Candidate]) -> list[str]:
        now = self._clock()
        with self._lock:
            state = self._loaded()
            ready = []
            for c in candidates:
                if state["providers"].get(c.provider, 0) > now:
                    continue
                entry = state["profiles"].get(c.profile_id)
                if entry and entry.get("not_before", 0) > now:
                    continue
                polled_at = state["last_polled_at"].get(c.profile_id)
                if polled_at is not None and now - polled_at < BASE_INTERVAL_SECONDS:
                    continue
                ready.append((c.profile_id, polled_at))
        ready.sort(key=lambda entry: -1.0 if entry[1] is None else entry[1])
        return [profile_id for profile_id, _ in ready[:MAX_PROBES_PER_TICK]]

    def provider_paused(self, provider: str) -> bool:
        """Recheck between reads: the previous account may have received 429."""
        with self._lock:
            return self._loaded()["providers"].get(provider, 0) > self._clock()

    # -- what happened --
    def record(self, profile_id: str, provider: str, result: ProbeResult) -> Optional[str]:
        """Applies backoff for a non-success. Returns a short message when the
        outcome is worth one line in Activity (the start of a rate limit or a
        refusal, or a run of failures); None otherwise."""
        now = self._clock()
        if result.status == 200 and result.headers:
            outcome = "ok"
        elif result.status == 429:
            outcome = "rate_limited"
        elif result.status in (401, 403):
            outcome = "auth"
        else:
            outcome = "failure"
        with self._lock:
            state = self._loaded()
            state["last_polled_at"][profile_id] = now
            entry = state["profiles"].get(profile_id)
            if outcome == "ok":
                if entry is not None:
                    del state["profiles"][profile_id]
                self._save()
                return None
            streak = entry["streak"] + 1 if entry and entry.get("kind") == outcome else 1
            base, ceiling = _BACKOFF[outcome]
            wait = min(base * 2 ** (streak - 1), ceiling)
            if outcome == "rate_limited" and result.retry_after:
                wait = max(wait, result.retry_after)
            not_before = now + wait
            state["profiles"][profile_id] = {"kind": outcome, "streak": streak, "not_before": not_before}
            if outcome == "rate_limited":
                # Whatever limited this account's read may be limiting the
                # client or the address, so give the whole provider a rest.
                state["providers"][provider] = max(state["providers"].get(provider, 0), not_before)
            self._save()
        if outcome == "rate_limited":
            return f"rate limited — usage checks for this provider resume in {_human(wait)}"
        if outcome == "auth" and streak == 1:
            return (f"HTTP {result.status} from the usage endpoint — retrying in {_human(wait)}; "
                    "requests through this account are unaffected")
        if outcome == "failure" and streak == FAILURES_BEFORE_LOGGING:
            detail = f"HTTP {result.status}" if result.status else "no response"
            return f"{detail} {streak} times in a row — retrying in {_human(wait)}"
        return None

    # -- persistence --
    def _file(self) -> Path:
        return self._state_file or (config.APP_DIR / "usage_probe_state.json")

    def _loaded(self) -> dict:
        if self._state is None:
            state = {"profiles": {}, "providers": {}, "last_polled_at": {}}
            try:
                data = json.loads(self._file().read_text())
                if isinstance(data, dict):
                    for key in ("profiles", "providers", "last_polled_at"):
                        if isinstance(data.get(key), dict):
                            state[key] = data[key]
            except (OSError, json.JSONDecodeError):
                pass
            self._state = state
        return self._state

    def _save(self) -> None:
        try:
            path = self._file()
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._state))
            tmp.replace(path)
        except OSError:
            pass  # backoff still holds in memory for this run

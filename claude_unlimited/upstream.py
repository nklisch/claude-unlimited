"""The one module allowed to open a real socket to Anthropic (or a gateway).

Kept separate from proxy.py's pure request-building so that tests never need
a real network connection: proxy.py is tested against fixtures, and this
module is exercised against a local fake HTTPS server, never api.anthropic.com.
"""

from __future__ import annotations

import contextlib
import contextvars
import email.utils
import http.client
import json
import math
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterator, Optional
from urllib.parse import urlsplit

from . import activity, net_scope
from .observation import ShortRateLimit, classify
from .proxy import UpstreamRequest, filter_response_headers


@dataclass
class UpstreamResponse:
    status: int
    headers: dict[str, str]
    body_chunks: Iterator[bytes]
    connection: http.client.HTTPConnection  # caller must close() after draining body_chunks


DEFAULT_TIMEOUT_SECONDS = 900  # 15 minutes: a large request can legitimately take that long to answer
CHUNK_SIZE = 65536

# send_with_retry(): how a request that fails BEFORE any output reaches the
# client is retried on the same account. Three attempts in all, 2s then 4s
# apart. A provider Retry-After lengthens that wait (it is waited in full, never
# cut short), but one longer than MAX_RETRY_AFTER_SECONDS — the same 15 minutes
# a single attempt may take — is more patience than a request has: the
# response is handed back at once, with the reason logged, so the Gateway's
# normal cooldown and fallback apply instead of an open-ended wait.
MAX_ATTEMPTS = 3
RETRY_BACKOFF_SECONDS = (2.0, 4.0)
MAX_RETRY_AFTER_SECONDS = 900.0
# 429 is judged separately (only a bare rate limit is transient; an exhausted
# 5-hour or weekly window is not).
TRANSIENT_STATUSES = (500, 502, 503, 504, 529)


# ---- diagnostics (Activity log, metadata only) ----------------------------------
# Everything logged about a retried or failed request is an id, a number or a
# short fixed word: never a body, a header set, a credential, or an exception's
# message (which can carry hosts, URLs or request details).

# The only response headers read for diagnostics: the provider's own id for the
# response, which tells an HTTP rejection (it has one) from a transport failure
# that never reached the provider.
_PROVIDER_REQUEST_ID_HEADERS = ("request-id", "x-request-id")
_NOT_ID_CHARS = re.compile(r"[^A-Za-z0-9._:-]")


def provider_request_id(headers: dict) -> Optional[str]:
    lower = {k.lower(): v for k, v in headers.items()}
    for name in _PROVIDER_REQUEST_ID_HEADERS:
        value = lower.get(name)
        if isinstance(value, str) and value.strip():
            return _NOT_ID_CHARS.sub("", value.strip())[:64] or None
    return None


def failure_fields(exc: BaseException) -> dict:
    """What to record about a network failure: the exception CLASS and its
    numeric errno (None when it has none)."""
    errno = getattr(exc, "errno", None)
    return {"error": type(exc).__name__,
            "errno": errno if isinstance(errno, int) and not isinstance(errno, bool) else None}


def trace_meta(**fields) -> str:
    """Activity `meta` for a diagnostic event: compact JSON of the fields that
    have a value."""
    return json.dumps({k: v for k, v in fields.items() if v is not None}, separators=(",", ":"))


@dataclass
class Trace:
    """Diagnostics context of ONE proxied request. `request_id` is generated
    locally by the Gateway and stays the same across same-account retries and
    account failover, so every Activity line about the request can be joined on
    it. The account fields are re-pointed for each account tried
    (start_account); send_with_retry writes back how many attempts it made and
    why it stopped. One Trace belongs to one request thread."""
    request_id: str = ""
    started: float = field(default_factory=time.monotonic)
    profile_id: str = ""
    profile_name: str = ""
    model: Optional[str] = None
    timeout_s: float = DEFAULT_TIMEOUT_SECONDS
    attempts: int = 0                  # attempts made on the current account
    give_up: Optional[str] = None      # "attempts_exhausted" | "retry_after_exceeds_patience"

    def start_account(self, profile_id: str, profile_name: str, model: Optional[str]) -> None:
        self.profile_id, self.profile_name = profile_id, profile_name
        self.model = model[:80] if model else None
        self.attempts, self.give_up = 0, None

    def elapsed(self) -> float:
        return round(time.monotonic() - self.started, 1)

    def meta(self, **fields) -> str:
        return trace_meta(rid=self.request_id or None, profile=self.profile_name[:60] or None,
                          profile_id=self.profile_id or None, model=self.model,
                          timeout_s=self.timeout_s, elapsed_s=self.elapsed(), **fields)


# The Gateway calls its transport with just the request (tests inject fakes of
# that shape), so the Trace travels beside it, per thread, instead of as an
# argument.
_current_trace: contextvars.ContextVar = contextvars.ContextVar("upstream_trace", default=None)


@contextlib.contextmanager
def tracing(trace: Trace):
    token = _current_trace.set(trace)
    try:
        yield trace
    finally:
        _current_trace.reset(token)


def send(req: UpstreamRequest, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> UpstreamResponse:
    parts = urlsplit(req.url)
    plaintext = parts.scheme == "http" and net_scope.is_local_host(parts.hostname)
    if parts.scheme != "https" and not plaintext:
        raise ValueError(
            f"Refusing to send an upstream request over {parts.scheme!r} to {parts.hostname} — "
            "a credential would cross the network in the clear. Plain http is allowed only for "
            "a local address (see net_scope, the same rule profiles.py validates a base_url with)."
        )

    if plaintext:
        # A model server on this machine or on the LAN: the request never
        # leaves the local network, so there is nobody new to hide it from.
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    else:
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=timeout)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"

    try:
        conn.request(req.method, path, body=req.body, headers=req.headers)
        resp = conn.getresponse()
    except BaseException:
        # A failed attempt owns a socket nobody else holds; close it here
        # rather than leaving it to the garbage collector.
        conn.close()
        raise

    headers = dict(resp.getheaders())
    status = resp.status
    provider_id = provider_request_id(headers)
    opened = time.monotonic()
    # The request this body belongs to. Captured now: the context variable is
    # reset by the time the body is read, so it cannot be looked up then.
    trace = _current_trace.get()

    # Only a request with a Trace has anywhere to log to, so only that one is watched.
    observer = (_SseObserver() if trace is not None and _is_messages_event_stream(parts.path, status, headers)
                else None)

    def _chunks() -> Iterator[bytes]:
        watch = observer
        try:
            while True:
                # read1, not read: read(n) keeps gathering HTTP chunks until it
                # holds n bytes (or EOF), which would sit on an event stream's
                # first events; read1 hands over what has arrived, at most n.
                chunk = resp.read1(CHUNK_SIZE)
                if not chunk:
                    break
                if watch is not None:
                    try:
                        new_error = watch.feed(chunk)
                    except Exception:
                        # Diagnostics are best effort and never break the stream they watch.
                        watch, new_error = None, False
                    if new_error:
                        _log_stream_error_event(trace, status, provider_id, opened, watch)
                yield chunk
        except (OSError, http.client.HTTPException) as exc:
            # Output may already have reached the client, so there is no retry
            # from here: log it and let the failure through.
            _log_stream_failed(trace, status, provider_id, opened, exc, watch)
            raise
        finally:
            conn.close()   # one-shot connection: done on EOF, error, or an abandoned stream
        if watch is not None:
            # Reached only when the provider itself ended the body: a failure
            # propagates past here, and a client that walks away raises
            # GeneratorExit at the yield, so neither is reported as an early end.
            _log_stream_ended(trace, status, provider_id, opened, watch)

    return UpstreamResponse(
        status=status,
        headers=headers,
        body_chunks=_chunks(),
        connection=conn,
    )


def _log_stream_failed(trace: Optional[Trace], status: int, provider_id: Optional[str], opened: float,
                       exc: BaseException, observer: Optional["_SseObserver"] = None) -> None:
    """A response whose body broke while it was being read. Only a request with
    a Trace is logged (a bare send(), e.g. the connection test, has none).
    `observer`, when the stream was watched, adds how far it had got."""
    if trace is None:
        return
    activity.record(
        "error",
        f"{_who(trace)} — response stream failed ({type(exc).__name__}); not replayed",
        meta=trace.meta(action="stream_failed", replayed=False, status=status, provider_request_id=provider_id,
                        attempts=trace.attempts or None, body_s=round(time.monotonic() - opened, 1),
                        **failure_fields(exc), **(observer.fields() if observer is not None else {})))


# ---- watching an event stream ----------------------------------------------------
# A /v1/messages answer that is 200 and text/event-stream should finish with a
# message_stop event (or an `error` event). One that simply ends — empty, only
# pings, or cut off between events — reaches Claude Code as a stream that closed
# early, and until now left nothing in the log because no exception was raised.
# _SseObserver is handed a copy of each chunk after it was read and before it is
# forwarded; it never alters or holds back the bytes, keeps only counters and a
# few flags (never any body text), and its memory is bounded by the two caps
# below however long the stream or any one line is.
_SSE_MAX_LINE_BYTES = 4096    # longest part of one line kept; the rest of a longer line is dropped
_SSE_MAX_DATA_BYTES = 4096    # largest event payload parsed to find its `type`
_SSE_MAX_NAME_BYTES = 48      # longest `event:` name kept


def _is_messages_event_stream(path: str, status: int, headers: dict) -> bool:
    """A successful Anthropic Messages answer that is a server-sent event
    stream. Anything else (a custom SSE endpoint, JSON, an error) has no
    terminal event to expect. The path rule is proxy.py's _is_messages_path."""
    if status != 200 or not path.rstrip("/").endswith("/v1/messages"):
        return False
    content_type = next((v for k, v in headers.items() if k.lower() == "content-type"), "")
    return isinstance(content_type, str) and content_type.split(";", 1)[0].strip().lower() == "text/event-stream"


def _json_object(data: bytes) -> Optional[dict]:
    try:
        value = json.loads(data)
    except (ValueError, RecursionError):   # not JSON, or nested past the parser's depth
        return None
    return value if isinstance(value, dict) else None


class _SseObserver:
    """Incremental server-sent-event framing over the bytes of one response.
    Lines end at LF (a CR before it is dropped, so CRLF works and a CRLF split
    across two chunks does too); a blank line ends a frame. Only a COMPLETE
    frame is counted: a frame still open at the end of the body was cut off.
    A frame's kind is its `event:` name, or — for a data-only frame, or the
    SSE default name `message` — the `type` of its JSON payload."""

    def __init__(self) -> None:
        self.byte_count = 0
        self.chunk_count = 0
        self.frames = 0                         # complete frames that carried an event
        self.pings = 0
        self.message_start = False
        self.message_stop = False
        self.error_events = 0
        self.error_type: Optional[str] = None   # the first error event's error.type, as a short id
        self._line = bytearray()
        self._line_cut = False                  # the open line was longer than the cap
        self._name = b""
        self._data = bytearray()
        self._data_cut = False
        self._open = False                      # the open frame has an event or data field

    def feed(self, chunk: bytes) -> bool:
        """Takes the next chunk of the body. True when this chunk completed the
        first upstream error event of the stream."""
        self.byte_count += len(chunk)
        self.chunk_count += 1
        had_error = self.error_type is not None
        pieces = chunk.split(b"\n")
        for piece in pieces[:-1]:
            self._extend_line(piece)
            self._end_line()
        self._extend_line(pieces[-1])
        return self.error_type is not None and not had_error

    def partial_frame(self) -> bool:
        """Whether bytes of an unfinished line or frame are pending."""
        return bool(self._line) or self._open

    def fields(self) -> dict:
        """The observation as Activity `meta` fields: counts, flags and one
        short error id; nothing taken from the body's text."""
        return {"body_bytes": self.byte_count, "chunks": self.chunk_count, "sse_events": self.frames,
                "sse_pings": self.pings, "message_start": self.message_start,
                "message_stop": self.message_stop, "error_events": self.error_events or None,
                "error_event_type": self.error_type, "partial_frame": self.partial_frame()}

    def _extend_line(self, piece: bytes) -> None:
        room = _SSE_MAX_LINE_BYTES - len(self._line)
        if len(piece) > room:
            piece, self._line_cut = piece[:room], True
        self._line += piece

    def _end_line(self) -> None:
        line, cut = bytes(self._line).removesuffix(b"\r"), self._line_cut
        self._line.clear()
        self._line_cut = False
        if not line:
            self._end_frame()
            return
        if line.startswith(b":"):        # an SSE comment
            return
        field, _, value = line.partition(b":")
        value = value.removeprefix(b" ")
        if field == b"event":
            self._name, self._open = value[:_SSE_MAX_NAME_BYTES], True
        elif field == b"data":
            self._open = True
            if cut or len(self._data) + len(value) + 1 > _SSE_MAX_DATA_BYTES:
                self._data_cut = True
            else:
                if self._data:
                    self._data += b"\n"
                self._data += value

    def _end_frame(self) -> None:
        name, data, data_cut, was_open = self._name, bytes(self._data), self._data_cut, self._open
        self._name, self._data_cut, self._open = b"", False, False
        self._data.clear()
        if not was_open:
            return
        self.frames += 1
        kind = name.decode("ascii", "ignore")
        # The payload is read only where its `type` or error is needed: a
        # data-only frame, the default `message` name, and `error` frames.
        payload = _json_object(data) if kind in ("", "message", "error") and data and not data_cut else None
        if kind in ("", "message") and payload is not None and isinstance(payload.get("type"), str):
            kind = payload["type"]
        if kind == "ping":
            self.pings += 1
        elif kind == "message_start":
            self.message_start = True
        elif kind == "message_stop":
            self.message_stop = True
        elif kind == "error":
            self.error_events += 1
            if self.error_type is None:
                detail = payload.get("error") if payload is not None else None
                error_type = detail.get("type") if isinstance(detail, dict) else None
                self.error_type = (_NOT_ID_CHARS.sub("", error_type)[:40] if isinstance(error_type, str) else "") \
                    or "unknown"


def _log_stream_error_event(trace: Trace, status: int, provider_id: Optional[str], opened: float,
                            observer: "_SseObserver") -> None:
    """The provider answered HTTP 200 and then sent an `error` event in the
    stream (overloaded, api_error, ...). Logged once, when the event is
    complete; the event itself is forwarded to the client untouched."""
    activity.record(
        "error",
        f"{_who(trace)} — upstream sent an error event in a 200 response stream "
        f"({observer.error_type}); delivered as received, not replayed",
        meta=trace.meta(action="stream_error_event", replayed=False, status=status,
                        provider_request_id=provider_id, attempts=trace.attempts or None,
                        body_s=round(time.monotonic() - opened, 1), **observer.fields()))


def _log_stream_ended(trace: Trace, status: int, provider_id: Optional[str], opened: float,
                      observer: "_SseObserver") -> None:
    """The provider ended a 200 Messages event stream cleanly (no network
    error). Quiet when it finished with message_stop; an error event was
    already logged when it arrived, so it is not logged again as incomplete."""
    if observer.message_stop or observer.error_type is not None:
        return
    if observer.byte_count == 0:
        reason, what = "empty_body", "an empty body"
    elif observer.frames == 0:
        reason, what = "no_events", "no complete event"
    elif observer.frames == observer.pings:
        reason, what = "only_pings", "only pings"
    else:
        reason, what = "no_message_stop", "no message_stop event"
    activity.record(
        "error",
        f"{_who(trace)} — response stream ended with {what}; delivered as received, not replayed",
        meta=trace.meta(action="stream_incomplete", reason=reason, replayed=False, status=status,
                        provider_request_id=provider_id, attempts=trace.attempts or None,
                        body_s=round(time.monotonic() - opened, 1), **observer.fields()))


def send_with_retry(req: UpstreamRequest, timeout: float = DEFAULT_TIMEOUT_SECONDS) -> UpstreamResponse:
    """send(), retried on the SAME account while nothing has reached the
    client. Retries a transport failure (OSError / http.client.HTTPException)
    and a transient HTTP answer (429 that is only a rate limit, 500, 502, 503,
    504, 529). Never retries anything else: a rejected credential, an
    exhausted quota window, 400/403 and other permanent errors come straight
    back for the Gateway to act on.

    Safe to replay because send() returns once the response HEADERS are in and
    the body has not been read: a response that is retried is closed unread,
    and none of it has been delivered anywhere. The last attempt's outcome is
    returned (or raised) untouched; the Gateway then cools the account down and
    falls back as it always did. Nothing is shared and no lock is held, so
    other requests keep using the account meanwhile.

    Each retry, a recovery after one, and a refusal to wait out a long
    Retry-After is written to the Activity log (see Trace). A raised failure
    carries `upstream_attempts`; the Trace's `attempts` / `give_up` say how it
    ended, for the Gateway's own line about the account."""
    trace = _current_trace.get() or Trace()
    trace.timeout_s = timeout
    for attempt in range(1, MAX_ATTEMPTS + 1):
        last = attempt == MAX_ATTEMPTS
        trace.attempts = attempt
        began = time.monotonic()
        try:
            resp = send(req, timeout=timeout)
        except (OSError, http.client.HTTPException) as exc:
            if last:
                trace.give_up = "attempts_exhausted"
                exc.upstream_attempts = attempt
                raise
            _retry_after_wait(trace, attempt, began, None, failure_fields(exc))
            continue
        if not _is_transient(resp):
            if attempt > 1:
                _log_recovered(trace, attempt, began, resp)
            return resp
        if last:
            trace.give_up = "attempts_exhausted"
            return resp
        retry_after = retry_after_seconds(resp.headers)
        outcome = {"status": resp.status, "provider_request_id": provider_request_id(resp.headers)}
        if retry_after is not None and retry_after > MAX_RETRY_AFTER_SECONDS:
            trace.give_up = "retry_after_exceeds_patience"
            activity.record(
                "error",
                f"{_who(trace)} — HTTP {resp.status}, Retry-After {retry_after:.0f}s is longer than the "
                f"{MAX_RETRY_AFTER_SECONDS:.0f}s limit; not waiting",
                meta=trace.meta(action="give_up_no_retry", attempt=attempt, max_attempts=MAX_ATTEMPTS,
                                retry_after_s=round(retry_after, 1), retry_after_honored=False,
                                attempt_s=round(time.monotonic() - began, 1), **outcome))
            return resp
        resp.connection.close()
        _retry_after_wait(trace, attempt, began, retry_after, outcome)
    raise AssertionError("unreachable: the last attempt returns or raises")


def _who(trace: Trace) -> str:
    return trace.profile_name or "Upstream"


def _is_transient(resp: UpstreamResponse) -> bool:
    if resp.status in TRANSIENT_STATUSES:
        return True
    if resp.status == 429:
        observation = classify(429, filter_response_headers(resp.headers), datetime.now(timezone.utc))
        return isinstance(observation, ShortRateLimit)
    return False


def _retry_after_wait(trace: Trace, attempt: int, began: float, retry_after: Optional[float],
                      outcome: dict) -> None:
    """Logs, then sleeps, before attempt number `attempt + 1`. `outcome` is the
    HTTP status (+ provider request id) or the exception class (+ errno) that
    failed this attempt — nothing from the request or an error's message."""
    wait = RETRY_BACKOFF_SECONDS[attempt - 1]
    if retry_after is not None:
        wait = max(wait, retry_after)
    reason = outcome.get("error") or f"HTTP {outcome.get('status')}"
    activity.record(
        "error",
        f"{_who(trace)} — {reason}; retrying the same account in {wait:.0f}s "
        f"(attempt {attempt + 1} of {MAX_ATTEMPTS}; account not cooled down)",
        meta=trace.meta(action="retry_same_account", account_cooled_down=False, attempt=attempt,
                        max_attempts=MAX_ATTEMPTS, backoff_s=round(wait, 1),
                        retry_after_s=None if retry_after is None else round(retry_after, 1),
                        retry_after_honored=retry_after is not None,
                        attempt_s=round(time.monotonic() - began, 1), **outcome))
    time.sleep(wait)


def _log_recovered(trace: Trace, attempt: int, began: float, resp: UpstreamResponse) -> None:
    text = (f"{_who(trace)} — recovered on retry (attempt {attempt} of {MAX_ATTEMPTS})" if resp.status < 400
            else f"{_who(trace)} — answered HTTP {resp.status} on retry (attempt {attempt} of {MAX_ATTEMPTS})")
    activity.record("session", text,
                     meta=trace.meta(action="recovered_same_account", account_cooled_down=False, attempt=attempt,
                                     max_attempts=MAX_ATTEMPTS, status=resp.status,
                                     provider_request_id=provider_request_id(resp.headers),
                                     attempt_s=round(time.monotonic() - began, 1)))


def retry_after_seconds(headers: dict) -> Optional[float]:
    """A valid Retry-After (delay-seconds or an HTTP-date) as seconds from now,
    or None when absent or not valid."""
    raw = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    if raw is None:
        return None
    raw = raw.strip()
    try:
        seconds = float(raw)
    except ValueError:
        try:
            when = email.utils.parsedate_to_datetime(raw)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return seconds

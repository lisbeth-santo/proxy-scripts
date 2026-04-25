import json
import threading
import time
from collections import defaultdict
from urllib.request import Request, urlopen
from urllib.error import URLError
from mitmproxy import http

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
LOKI_URL             = "http://localhost:3100/loki/api/v1/push"
BATCH_MAX_SIZE       = 150   # flush when this many entries are queued
BATCH_INTERVAL_SEC   = 5     # flush at least every N seconds

BINARY_SIZE_LIMIT    = 10_240  # 10 KB
MAX_BODY_SIZE        = 10_240  # skip requests with body larger than 10 KB
MEDIA_CONTENT        = ("audio/", "image/", "video/")

# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------
_lock    = threading.Lock()
_buffer  = []          # list of (labels_tuple, value) pairs; value is [ts, line] or [ts, line, metadata]
_stop    = threading.Event()

_domain_to_skip = ["gaamsihei.io"]


def _ns_now() -> str:
    return str(int(time.time() * 1_000_000_000))


def _flush():
    """Drain the buffer and push one request to Loki, grouping by label set."""
    with _lock:
        if not _buffer:
            return
        entries, _buffer[:] = list(_buffer), []

    # Group entries by their label frozenset so each unique label combo
    # becomes one stream object in the payload.
    streams_map: dict[tuple, list] = defaultdict(list)
    for labels_tuple, value in entries:
        streams_map[labels_tuple].append(value)

    payload = {
        "streams": [
            {
                "stream": dict(labels_tuple),
                "values": values,
            }
            for labels_tuple, values in streams_map.items()
        ]
    }

    body = json.dumps(payload).encode("utf-8")
    req  = Request(
        LOKI_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=10) as resp:
            if resp.status not in (200, 204):
                print(f"[loki] unexpected status {resp.status}")
    except URLError as exc:
        print(f"[loki] push failed: {exc}")


def _flush_loop():
    """Background thread: flush every BATCH_INTERVAL_SEC seconds."""
    while not _stop.wait(timeout=BATCH_INTERVAL_SEC):
        _flush()
    _flush()   # final drain on shutdown


_thread = threading.Thread(target=_flush_loop, daemon=True, name="loki-flush")
_thread.start()


def _enqueue(labels: dict, line: str, metadata: dict | None = None):
    labels_tuple = tuple(sorted(labels.items()))
    value = [_ns_now(), line] if not metadata else [_ns_now(), line, metadata]
    with _lock:
        _buffer.append((labels_tuple, value))
        should_flush = len(_buffer) >= BATCH_MAX_SIZE

    if should_flush:
        threading.Thread(target=_flush, daemon=True).start()


# ---------------------------------------------------------------------------
# Helpers (unchanged from original)
# ---------------------------------------------------------------------------
def _is_binary_body(body: bytes) -> bool:
    if not body:
        return False
    if b"\x00" in body:
        return True
    try:
        body.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def _should_skip(flow: http.HTTPFlow) -> bool:
    if flow.request.method == "OPTIONS":
        return True
    if "googlevideo.com/videoplayback" in flow.request.pretty_url:
        return True
    for ct in (
        flow.request.headers.get("content-type", ""),
        flow.response.headers.get("content-type", ""),
    ):
        if any(ct.startswith(p) for p in MEDIA_CONTENT):
            return True
    body = flow.request.content or b""
    if _is_binary_body(body) and len(body) > BINARY_SIZE_LIMIT:
        return True
    return False


# ---------------------------------------------------------------------------
# mitmproxy hooks
# ---------------------------------------------------------------------------
def response(flow: http.HTTPFlow):
    if _should_skip(flow):
        return

    client_ip  = flow.client_conn.peername[0] if flow.client_conn.peername else ""
    method     = flow.request.method
    status     = str(flow.response.status_code)

    body = flow.request.get_text(strict=False)
    if body and len(body) > MAX_BODY_SIZE:
        return

    domain = flow.client_conn.sni

    if domain in _domain_to_skip:
        return

    labels = {
        "app":    "mitmproxy",
        "method": method,
        "status": status,
    }

    line = json.dumps({
        # "domain": flow.request.host,
        "domain": domain,
        "path":   flow.request.path,
        "body":   body,
    }, ensure_ascii=False)

    metadata = {"client_ip": client_ip}

    _enqueue(labels, line, metadata)


def done():
    """Called by mitmproxy on shutdown — flush any remaining entries."""
    _stop.set()
    _thread.join(timeout=15)

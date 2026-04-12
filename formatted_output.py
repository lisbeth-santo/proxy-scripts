import csv
import io
import os
import threading
from datetime import date, datetime
from mitmproxy import http

BINARY_SIZE_LIMIT = 10_240          # 10KB
MAX_FILE_SIZE     = 100 * 1024 * 1024  # 100MB
BUFFER_ROWS       = 500
FLUSH_INTERVAL    = 30              # seconds

CSV_HEADER = ["Method", "URL", "Status", "Body"]


def is_binary_body(body: bytes) -> bool:
    if not body:
        return False
    if b'\x00' in body:
        return True
    try:
        body.decode('utf-8')
        return False
    except UnicodeDecodeError:
        return True


def should_skip(flow) -> bool:
    if flow.request.method == "OPTIONS":
        return True
    url = flow.request.pretty_url
    if "googlevideo.com/videoplayback" in url:
        return True
    content_type = flow.request.headers.get("content-type", "")
    if any(content_type.startswith(prefix) for prefix in ("audio/", "image/", "video/")):
        return True
    body = flow.request.content or b""
    if is_binary_body(body) and len(body) > BINARY_SIZE_LIMIT:
        return True
    return False


class CsvWriter:
    def __init__(self):
        self._lock         = threading.Lock()
        self._buffer       = []
        self._file         = None   # open file handle
        self._writer       = None   # csv.writer
        self._current_date = None   # date object for day-rollover detection
        self._current_size = 0      # bytes written to current file
        self._flush_thread = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self):
        """Call once when mitmproxy loads the addon."""
        self._flush_thread = threading.Thread(target=self._periodic_flush, daemon=True)
        self._flush_thread.start()

    def append(self, row: list):
        """Buffer a row; flush if buffer is full."""
        with self._lock:
            self._buffer.append(row)
            if len(self._buffer) >= BUFFER_ROWS:
                self._flush_locked()

    def stop(self):
        """Final flush on mitmproxy shutdown."""
        with self._lock:
            self._flush_locked()
            if self._file:
                self._file.close()
                self._file = None

    # ------------------------------------------------------------------
    # Internal helpers (must be called with _lock held unless noted)
    # ------------------------------------------------------------------

    def _periodic_flush(self):
        """Background thread: flush every FLUSH_INTERVAL seconds."""
        import time
        while True:
            time.sleep(FLUSH_INTERVAL)
            with self._lock:
                self._flush_locked()

    def _flush_locked(self):
        """Write buffered rows to disk. Lock must already be held."""
        if not self._buffer:
            return

        self._ensure_file_locked()

        # Measure bytes by writing through a counting wrapper
        rows = self._buffer
        self._buffer = []

        for row in rows:
            # Encode the row to estimate byte size without a second syscall
            buf = io.StringIO()
            csv.writer(buf).writerow(row)
            line = buf.getvalue()
            self._file.write(line)
            self._current_size += len(line.encode("utf-8"))

        self._file.flush()

        # Rotate if over size limit (next write opens a fresh file)
        if self._current_size >= MAX_FILE_SIZE:
            self._file.close()
            self._file   = None
            self._writer = None
            # _current_size reset happens in _open_new_file_locked

    def _ensure_file_locked(self):
        """Open or rotate the file if needed."""
        today = date.today()

        # Day rollover or first call
        if self._current_date != today:
            if self._file:
                self._file.close()
                self._file   = None
                self._writer = None
            self._current_date = today
            self._current_size = 0

        if self._file is None:
            self._open_file_locked()

    def _day_dir(self) -> str:
        return os.path.join("output", self._current_date.strftime("%Y_%m_%d"))

    def _open_file_locked(self):
        """
        Open a file for the current day. On startup/restart, resume the
        latest existing file if it is under the size limit; otherwise
        (or after rotation) create a new timestamped file.
        """
        day_dir = self._day_dir()
        os.makedirs(day_dir, exist_ok=True)

        # Find the most recent .csv in today's dir (one-time stat on startup)
        existing = sorted(
            [f for f in os.listdir(day_dir) if f.endswith(".csv")],
            reverse=True,
        )

        if existing:
            candidate = os.path.join(day_dir, existing[0])
            size = os.path.getsize(candidate)
            if size < MAX_FILE_SIZE:
                # Resume writing into the existing file
                self._current_size = size
                self._file = open(candidate, "a", newline="")
                self._writer = csv.writer(self._file)
                return

        # Create a brand-new timestamped file
        self._open_new_file_locked(day_dir)

    def _open_new_file_locked(self, day_dir: str):
        fname  = datetime.now().strftime("%H%M%S") + ".csv"
        fpath  = os.path.join(day_dir, fname)
        self._file         = open(fpath, "a", newline="")
        self._writer       = csv.writer(self._file)
        self._current_size = 0
        # Write header; track its byte cost
        header_buf = io.StringIO()
        csv.writer(header_buf).writerow(CSV_HEADER)
        self._file.write(header_buf.getvalue())
        self._current_size += len(header_buf.getvalue().encode("utf-8"))


# ---------------------------------------------------------------------------
# mitmproxy addon
# ---------------------------------------------------------------------------

_writer = CsvWriter()


class Addon:
    def load(self, loader):
        _writer.start()

    def response(self, flow: http.HTTPFlow):
        if should_skip(flow):
            return
        _writer.append([
            flow.request.method,
            flow.request.pretty_url,
            flow.response.status_code,
            flow.request.get_text(strict=False),
        ])

    def done(self):
        _writer.stop()


addons = [Addon()]

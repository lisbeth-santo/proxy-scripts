import csv
import os
from mitmproxy import http

BINARY_SIZE_LIMIT = 10_240  # 10KB

media_content = ("audio/", "image/", "video/")

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
    if any(content_type.startswith(prefix) for prefix in media_content):
        return True
    content_type = flow.response.headers.get("content-type", "")
    if any(content_type.startswith(prefix) for prefix in media_content):
        return True
    body = flow.request.content or b""
    if is_binary_body(body) and len(body) > BINARY_SIZE_LIMIT:
        return True
    return False

def response(flow: http.HTTPFlow):
    if should_skip(flow):
        return
    file_exists = os.path.exists("output.csv")
    with open("output.csv", "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Method", "ClientIP", "Domain", "Path", "Status", "Body"])
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else ""
        writer.writerow([
            flow.request.method,
            client_ip,
            flow.request.host,
            flow.request.path,
            flow.response.status_code,
            flow.request.get_text(strict=False)
        ])

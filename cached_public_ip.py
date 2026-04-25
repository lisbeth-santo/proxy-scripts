import time
import threading
import urllib.request
CACHE_DURATION_SECONDS = 30 * 60
# CACHE_DURATION_SECONDS = 2 * 60
my_public_ip = ""
last_updated_at = None
_lock = threading.Lock()
def get_public_ip() -> str:
    global my_public_ip, last_updated_at
    current_time = time.time()
    if not my_public_ip or (last_updated_at and current_time - last_updated_at > CACHE_DURATION_SECONDS):
        with _lock:
            # Re-check after acquiring lock (double-checked locking)
            current_time = time.time()
            if not my_public_ip or (last_updated_at and current_time - last_updated_at > CACHE_DURATION_SECONDS):
                try:
                    with urllib.request.urlopen("https://ifconfig.me/ip", timeout=5) as response:
                        my_public_ip = response.read().decode().strip()
                        last_updated_at = current_time
                        return my_public_ip
                except Exception:
                    pass
                try:
                    with urllib.request.urlopen("https://ipinfo.io/ip", timeout=5) as response:
                        my_public_ip = response.read().decode().strip()
                        last_updated_at = current_time
                        return my_public_ip
                except Exception:
                    pass
    return my_public_ip

def ip_to_bytes(ip_str: str) -> bytes:
    return bytes(int(x) for x in ip_str.split('.'))

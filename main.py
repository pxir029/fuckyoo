# ============================================================
# PXPanel 13.7.1
# Railway Ready
# ============================================================

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import string
import time

from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, parse_qs

import aiofiles
import httpx
import uvicorn

from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
)
from fastapi.responses import (
    Response,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# APP
# ============================================================

APP_NAME = "PXPanel"
APP_VERSION = "13.7.1"

SUPPORT_USERNAME = "@logic_sec"
SUPPORT_URL = "https://t.me/logic_sec"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(APP_NAME)


# ============================================================
# TIMEZONE
# ============================================================

try:
    from zoneinfo import ZoneInfo

    IRAN_TZ = ZoneInfo("Asia/Tehran")

except Exception:
    IRAN_TZ = None


# ============================================================
# RAILWAY
# ============================================================

PORT = int(
    os.environ.get(
        "PORT",
        "8000",
    )
)

DATA_DIR = Path(
    os.environ.get(
        "RAILWAY_VOLUME_MOUNT_PATH",
        os.environ.get(
            "DATA_DIR",
            "./data",
        ),
    )
)

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DATA_FILE = DATA_DIR / "pixonpanel_state.json"
SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LOCKS
# ============================================================

SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()


# ============================================================
# SECRET
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")

    if env_secret:
        return env_secret

    try:
        if SECRET_FILE.exists():
            existing = (
                SECRET_FILE
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )

            if existing:
                return existing

        generated = secrets.token_urlsafe(48)

        SECRET_FILE.write_text(
            generated,
            encoding="utf-8",
        )

        return generated

    except Exception as exc:
        logger.warning(
            "Could not persist SECRET_KEY: %s",
            exc,
        )

        return secrets.token_urlsafe(48)


SECRET_KEY = load_or_create_secret()


# ============================================================
# CONFIG
# ============================================================

CONFIG = {
    "port": PORT,
    "secret": SECRET_KEY,
    "host": os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN",
        "localhost",
    ),
}


# ============================================================
# STATE
# ============================================================

LINKS: dict = {}
SUBS: dict = {}
SESSIONS: dict = {}
connections: dict = {}
CATEGORIES: dict = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs = deque(maxlen=100)
activity_logs = deque(maxlen=250)

hourly_traffic = defaultdict(int)

http_client: httpx.AsyncClient | None = None


# ============================================================
# PROTOCOL
# ============================================================

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
    "vmess-ws",
    "trojan-ws",
    "shadowsocks",
    "socks5",
    "http",
    "hysteria2",
    "tuic",
    "wireguard",
    "highspeed-demo",
    "gaming-lite-demo",
)

PROTOCOL_LABELS = {
    "vless-ws": "VLESS WebSocket",
    "xhttp-packet-up": "XHTTP Packet Up",
    "xhttp-stream-up": "XHTTP Stream Up",
    "xhttp-stream-one": "XHTTP Stream One",
    "vmess-ws": "VMess WebSocket",
    "trojan-ws": "Trojan WebSocket",
    "shadowsocks": "Shadowsocks",
    "socks5": "SOCKS5",
    "http": "HTTP Proxy",
    "hysteria2": "Hysteria 2",
    "tuic": "TUIC",
    "wireguard": "WireGuard",
    "highspeed-demo": "HighSpeed Upload/Download (دمو)",
    "gaming-lite-demo": "Gaming Lite (دمو)",
}

PROTOCOL_ALIASES = {
    "vmess": "vmess-ws", "trojan": "trojan-ws", "ss": "shadowsocks",
    "socks": "socks5", "hy2": "hysteria2", "hysteria": "hysteria2",
}

DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = (
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
)

DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}

DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_SPEED_LIMIT = 0


def normalize_protocol(protocol: str | None) -> str:
    value = str(protocol or DEFAULT_PROTOCOL).strip().lower()
    value = PROTOCOL_ALIASES.get(value, value)
    return value if value in PROTOCOLS else DEFAULT_PROTOCOL


# ============================================================
# LOGGING
# ============================================================

def log_activity(
    kind: str,
    message: str,
    level: str = "info",
):
    activity_logs.append(
        {
            "kind": kind,
            "level": level,
            "message": message,
            "time": datetime.now().isoformat(),
        }
    )


# ============================================================
# HELPERS
# ============================================================

def escape_html(value) -> str:
    return (
        str(
            value
            if value is not None
            else ""
        )
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def safe_int(
    value,
    default=0,
    minimum=0,
    maximum=None,
):
    try:
        number = int(value)
    except Exception:
        number = default

    if number < minimum:
        number = minimum

    if maximum is not None and number > maximum:
        number = maximum

    return number


def safe_float(
    value,
    default=0.0,
    minimum=0.0,
):
    try:
        number = float(value)
    except Exception:
        number = default

    return max(
        minimum,
        number,
    )


def generate_uuid():
    value = secrets.token_hex(16)

    return (
        f"{value[:8]}-"
        f"{value[8:12]}-"
        f"{value[12:16]}-"
        f"{value[16:20]}-"
        f"{value[20:32]}"
    )


def random_config_name(existing=None):
    existing = existing or set()
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(80):
        length = secrets.randbelow(6) + 8
        name = "".join(secrets.choice(alphabet) for _ in range(length))
        if name not in existing and name and not name[0].isdigit():
            return name
    return secrets.token_hex(6)

def sanitize_config_name(name: str) -> str:
    if not name:
        return random_config_name()
    cleaned = "".join(ch for ch in str(name) if ch.isascii() and ch.isalnum())
    if not cleaned or cleaned[0].isdigit():
        cleaned = ("a" + cleaned) if cleaned else random_config_name()
    return cleaned[:40]

def auto_config_name() -> str:
    return random_config_name()


def now_ir():
    if IRAN_TZ:
        return datetime.now(IRAN_TZ)

    return datetime.now()


def uptime():
    seconds = int(
        time.time()
        - stats["start_time"]
    )

    h = seconds // 3600

    m = (
        seconds
        % 3600
    ) // 60

    s = (
        seconds
        % 60
    )

    return (
        f"{h:02d}:"
        f"{m:02d}:"
        f"{s:02d}"
    )


def fmt_bytes(value: int):
    value = int(
        value or 0
    )

    if value < 1024:
        return f"{value} B"

    if value < 1024 ** 2:
        return (
            f"{value / 1024:.1f} KB"
        )

    if value < 1024 ** 3:
        return (
            f"{value / 1024 ** 2:.2f} MB"
        )

    return (
        f"{value / 1024 ** 3:.2f} GB"
    )


def parse_size_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "GB"
    ).upper()

    if unit == "TB":
        return int(
            value
            * 1024 ** 4
        )

    if unit == "GB":
        return int(
            value
            * 1024 ** 3
        )

    if unit == "MB":
        return int(
            value
            * 1024 ** 2
        )

    if unit == "KB":
        return int(
            value
            * 1024
        )

    return int(value)


def parse_speed_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "MBIT"
    ).upper()

    if unit == "MBIT":
        return int(
            value
            * 1024
            * 1024
            / 8
        )

    if unit == "KB":
        return int(
            value * 1024
        )

    if unit == "MB":
        return int(
            value
            * 1024
            * 1024
        )

    return int(value)


def is_link_expired(
    link: dict,
):
    expiry = link.get(
        "expires_at"
    )

    if not expiry:
        return False

    try:
        return (
            datetime.now()
            > datetime.fromisoformat(
                expiry
            )
        )

    except Exception:
        return False


def is_link_allowed(
    link: dict | None,
):
    if link is None:
        return False

    if not link.get(
        "active",
        True,
    ):
        return False

    if is_link_expired(link):
        return False

    limit = int(
        link.get(
            "limit_bytes",
            0,
        )
        or 0
    )

    used = int(
        link.get(
            "used_bytes",
            0,
        )
        or 0
    )

    if (
        limit > 0
        and used >= limit
    ):
        return False

    return True


def unique_ips_for_uuid(
    uuid: str,
):
    return {
        connection.get("ip")
        for connection in connections.values()
        if connection.get("uuid") == uuid
        and connection.get("ip")
    }


def client_ip(
    request: Request,
):
    forwarded = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded:
        return (
            forwarded
            .split(",")[0]
            .strip()
        )

    real = request.headers.get(
        "x-real-ip"
    )

    if real:
        return real.strip()

    if request.client:
        return request.client.host

    return "unknown"


def is_ip_allowed(
    link: dict | None,
    uuid: str,
    ip: str,
):
    if link is None:
        return False

    limit = int(
        link.get(
            "ip_limit",
            0,
        )
        or 0
    )

    if limit <= 0:
        return True

    ips = unique_ips_for_uuid(uuid)

    if ip in ips:
        return True

    return len(ips) < limit


def get_host(
    request: Request | None = None,
) -> str:

    if request is not None:
        forwarded = request.headers.get(
            "x-forwarded-host"
        )

        normal = request.headers.get(
            "host"
        )

        host = (
            forwarded
            or normal
        )

        if host:
            host = host.split(":")[0].strip()

            CONFIG["host"] = host

            return host

    railway_domain = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway_domain:
        return railway_domain

    return CONFIG["host"]


# ============================================================
# PASSWORD
# ============================================================

def hash_password(
    password: str,
) -> str:

    payload = (
        password
        + SECRET_KEY
    ).encode("utf-8")

    return hashlib.sha256(
        payload
    ).hexdigest()


DEFAULT_ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "pxpanel2026",
)

AUTH = {
    "password_hash":
        hash_password(
            DEFAULT_ADMIN_PASSWORD
        )
}


# ============================================================
# LOGIN BRUTE-FORCE PROTECTION
# ============================================================
# Maximum failed login attempts per IP inside the rolling window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60
LOGIN_MIN_PASSWORD_LENGTH = 6

LOGIN_FAILURES = defaultdict(deque)
LOGIN_LOCKED_UNTIL = {}


def _cleanup_login_state(ip: str, now: float | None = None):
    now = now if now is not None else time.time()

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until and locked_until <= now:
        LOGIN_LOCKED_UNTIL.pop(ip, None)

    failures = LOGIN_FAILURES.get(ip)
    if not failures:
        return

    cutoff = now - LOGIN_WINDOW_SECONDS
    while failures and failures[0] <= cutoff:
        failures.popleft()

    if not failures:
        LOGIN_FAILURES.pop(ip, None)


def login_is_blocked(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until > now:
        return True, max(1, int(locked_until - now))

    return False, 0


def register_login_failure(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    failures = LOGIN_FAILURES.setdefault(ip, deque())
    failures.append(now)

    if len(failures) >= LOGIN_MAX_ATTEMPTS:
        LOGIN_LOCKED_UNTIL[ip] = now + LOGIN_LOCKOUT_SECONDS
        failures.clear()
        log_activity(
            "auth",
            f"IP به دلیل تلاش‌های متعدد ورود ناموفق به مدت {LOGIN_LOCKOUT_SECONDS // 60} دقیقه مسدود شد: {ip}",
            "err",
        )
        return True, LOGIN_LOCKOUT_SECONDS

    return False, max(0, LOGIN_MAX_ATTEMPTS - len(failures))


def clear_login_failures(ip: str):
    LOGIN_FAILURES.pop(ip, None)
    LOGIN_LOCKED_UNTIL.pop(ip, None)


# ============================================================
# SESSION
# ============================================================

SESSION_COOKIE = "pixonpanel_session"

SESSION_TTL = (
    60
    * 60
    * 24
    * 365
)


async def create_session() -> str:

    token = secrets.token_urlsafe(48)

    async with SESSIONS_LOCK:
        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )

    return token


async def is_valid_session(
    token: str | None,
) -> bool:

    if not token:
        return False

    async with SESSIONS_LOCK:

        expiry = SESSIONS.get(token)

        if expiry is None:
            return False

        if expiry < time.time():

            SESSIONS.pop(
                token,
                None,
            )

            return False

        return True


async def destroy_session(
    token: str | None,
):
    if not token:
        return

    async with SESSIONS_LOCK:
        SESSIONS.pop(
            token,
            None,
        )


async def require_auth(
    request: Request,
):
    token = request.cookies.get(
        SESSION_COOKIE
    )

    if not await is_valid_session(
        token
    ):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )

    return token


def set_auth_cookie(
    response,
    request: Request,
    token: str,
):
    forwarded_proto = (
        request.headers
        .get(
            "x-forwarded-proto",
            "",
        )
        .lower()
    )

    is_https = (
        forwarded_proto == "https"
        or request.url.scheme == "https"
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=is_https,
    )


# ============================================================
# VLESS LINK GENERATION
# ============================================================

def generate_vless_link(
    uuid: str, host: str, remark: str = "PXPanel",
    protocol: str = DEFAULT_PROTOCOL, fingerprint: str | None = None,
    alpn: str | None = None, port: int | None = None,
):
    protocol = normalize_protocol(protocol)
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fp not in FINGERPRINTS: fp = DEFAULT_FINGERPRINT
    port_value = safe_int(port, DEFAULT_PORT, MIN_PORT, MAX_PORT)
    alpn_value = (alpn or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")).strip()
    label = quote(str(remark or "PXPanel"), safe="")
    if protocol == "vless-ws":
        q = {"encryption":"none","security":"tls","type":"ws","host":host,"path":f"/ws/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol.startswith("xhttp-"):
        mode = protocol.replace("xhttp-", "")
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":mode,"host":host,"path":f"/xhttp-siz10/{mode}/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol == "vmess-ws":
        raw = {"v":"2","ps":remark,"add":host,"port":port_value,"id":uuid,"aid":0,"scy":"auto","net":"ws","type":"none","host":host,"path":f"/ws/{uuid}","tls":"tls","sni":host,"fp":fp}
        return "vmess://" + base64.b64encode(json.dumps(raw,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if protocol == "trojan-ws":
        return f"trojan://{uuid}@{host}:{port_value}?security=tls&type=ws&host={quote(host)}&path={quote('/ws/'+uuid)}&sni={quote(host)}#{label}"
    if protocol == "shadowsocks":
        method = os.getenv("SS_METHOD", "aes-256-gcm")
        userinfo = base64.urlsafe_b64encode(f"{method}:{uuid}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port_value}#{label}"
    if protocol == "socks5": return f"socks5://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "http": return f"http://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "hysteria2": return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0#{label}"
    if protocol == "tuic": return f"tuic://{uuid}:{uuid}@{host}:{port_value}?sni={quote(host)}&alpn=h3#{label}"
    if protocol == "wireguard": return f"wireguard://{uuid}@{host}:{port_value}?publicKey={uuid}#{label}"
    if protocol == "highspeed-demo":
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":"stream-up","host":host,"path":f"/xhttp-siz10/stream-up/{uuid}","sni":host,"fp":fp,"alpn":"h2,http/1.1"}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k,v in q.items()) + "#" + label
    if protocol == "gaming-lite-demo":
        return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0&obfs=salamander#{label}"
    return f"vless://{uuid}@{host}:{port_value}"

def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
):
    return generate_vless_link(
        uid,
        host,
        remark=str(link.get("label") or "Config"),
        protocol=link.get(
            "protocol",
            DEFAULT_PROTOCOL,
        ),
        fingerprint=link.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        ),
        alpn=link.get(
            "alpn"
        ),
        port=link.get(
            "port",
            DEFAULT_PORT,
        ),
    )


def get_link_info(
    link: dict,
    uid: str,
    host: str,
):
    connected_count = len(unique_ips_for_uuid(uid))
    is_active = is_link_allowed(link)
    limit_b = int(link.get("limit_bytes", 0) or 0)
    used_b = int(link.get("used_bytes", 0) or 0)
    is_expired = is_link_expired(link) or (limit_b > 0 and used_b >= limit_b)
    if not is_active or is_expired:
        status_color = "red"
    elif connected_count > 0:
        status_color = "green"
    else:
        status_color = "gray"
    clean_ips = link.get("clean_ips") or []
    cfg_count = int(link.get("config_count") or 1)
    show_vless = len(clean_ips) <= 1 and cfg_count <= 1
    cat = CATEGORIES.get(str(link.get("category_id") or "0")) or {}
    return {
        "uuid": uid,
        "name": link.get("label", ""),
        "label": link.get("label", ""),
        "protocol": link.get("protocol", DEFAULT_PROTOCOL),
        "active": is_active,
        "used_bytes": used_b,
        "limit_bytes": limit_b,
        "expires_at": link.get("expires_at"),
        "ip_limit": int(link.get("ip_limit", 0) or 0),
        "speed_limit_bytes": int(link.get("speed_limit_bytes", 0) or 0),
        "connection_limit": int(link.get("connection_limit", 0) or 0),
        "fragment": link.get("fragment", "off"),
        "fingerprint": link.get("fingerprint", DEFAULT_FINGERPRINT),
        "alpn": link.get("alpn", ""),
        "port": link.get("port", DEFAULT_PORT),
        "note": link.get("note", ""),
        "clean_ips": clean_ips,
        "alarm_enabled": bool(link.get("alarm_enabled", False)),
        "category_id": str(link.get("category_id") or "0"),
        "category_number": int(cat.get("number", 0)),
        "category_name": str(cat.get("name", "عمومی")),
        "config_count": cfg_count,
        "status_color": status_color,
        "connected_ips": connected_count,
        "show_vless": show_vless,
        "vless": vless_link_for_link(link, uid, host) if show_vless else "",
        "vless_full": vless_link_for_link(link, uid, host),
        "sub": f"https://{host}/sub/{uid}",
        "info": f"https://{host}/info/{uid}",
        "support": SUPPORT_USERNAME,
    }


# ============================================================
# PERSISTENCE
# ============================================================

async def load_state():

    global AUTH

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            raw = await file.read()

        data = json.loads(raw)

        LINKS.update(
            data.get(
                "links",
                {},
            )
        )

        SUBS.update(
            data.get(
                "subs",
                {},
            )
        )

        CATEGORIES.update(
            data.get(
                "categories",
                {},
            )
        )

        stored_password = data.get(
            "password_hash"
        )

        if stored_password:
            AUTH[
                "password_hash"
            ] = stored_password

        # Compatibility for older records
        for uid, link in LINKS.items():

            link.setdefault(
                "protocol",
                DEFAULT_PROTOCOL,
            )

            link.setdefault(
                "fingerprint",
                DEFAULT_FINGERPRINT,
            )

            link.setdefault(
                "alpn",
                "",
            )

            link.setdefault(
                "port",
                DEFAULT_PORT,
            )

            link.setdefault(
                "ip_limit",
                0,
            )

            link.setdefault(
                "speed_limit_bytes",
                0,
            )

            link.setdefault(
                "connection_limit",
                0,
            )

            link.setdefault(
                "fragment",
                "off",
            )

            link.setdefault(
                "used_bytes",
                0,
            )
            link.setdefault("clean_ips", [])
            link.setdefault("alarm_enabled", False)
            link.setdefault("category_id", "0")
            link.setdefault("config_count", 1)
            link.setdefault("usage_history", [])

        logger.info(
            "State loaded: %d links / %d subscriptions",
            len(LINKS),
            len(SUBS),
        )

    except Exception as exc:

        logger.exception(
            "Could not load state: %s",
            exc,
        )


async def save_state():

    async with SAVE_LOCK:

        try:

            DATA_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = {
                "links":
                    dict(LINKS),

                "subs":
                    dict(SUBS),

                "categories":
                    dict(CATEGORIES),

                "password_hash":
                    AUTH[
                        "password_hash"
                    ],

                "saved_at":
                    datetime.now().isoformat(),
            }

            temp_file = (
                DATA_FILE.with_suffix(
                    ".tmp"
                )
            )

            async with aiofiles.open(
                temp_file,
                "w",
                encoding="utf-8",
            ) as file:

                await file.write(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        indent=2,
                    )
                )

            temp_file.replace(
                DATA_FILE
            )

        except Exception as exc:

            logger.exception(
                "Could not save state: %s",
                exc,
            )


# ============================================================
# DEFAULT LINK
# ============================================================

_default_link_created = False



async def ensure_default_categories():
    if CATEGORIES:
        return
    CATEGORIES["0"] = {
        "id": "0", "name": "عمومی", "number": 0,
        "limit_bytes": 0, "expires_days": 0, "connection_limit": 0,
        "speed_limit_bytes": 0, "ip_limit": 0, "clean_ips": [],
        "random_name": False, "single_user": False,
        "created_at": datetime.now().isoformat(),
    }
    CATEGORIES["1"] = {
        "id": "1", "name": "VIP", "number": 1,
        "limit_bytes": 0, "expires_days": 0, "connection_limit": 1,
        "speed_limit_bytes": 0, "ip_limit": 1, "clean_ips": [],
        "random_name": False, "single_user": True,
        "created_at": datetime.now().isoformat(),
    }
    asyncio.create_task(save_state())

async def ensure_default_link():

    global _default_link_created

    if _default_link_created:
        return

    async with LINKS_LOCK:

        if not any(
            item.get("is_default")
            for item in LINKS.values()
        ):

            digest = hashlib.sha256(
                (
                    "default"
                    + SECRET_KEY
                ).encode("utf-8")
            ).hexdigest()

            uid = (
                f"{digest[:8]}-"
                f"{digest[8:12]}-"
                f"{digest[12:16]}-"
                f"{digest[16:20]}-"
                f"{digest[20:32]}"
            )

            LINKS[uid] = {
                "label":
                    "لینک پیش‌فرض",

                "limit_bytes":
                    0,

                "used_bytes":
                    0,

                "created_at":
                    datetime.now().isoformat(),

                "active":
                    True,

                "expires_at":
                    None,

                "note":
                    "",

                "is_default":
                    True,

                "sub_id":
                    None,

                "protocol":
                    DEFAULT_PROTOCOL,

                "fingerprint":
                    DEFAULT_FINGERPRINT,

                "alpn":
                    "http/1.1",

                "port":
                    DEFAULT_PORT,

                "ip_limit":
                    0,

                "speed_limit_bytes":
                    DEFAULT_SPEED_LIMIT,

                "connection_limit":
                    0,

                "fragment":
                    "off",
            }

            asyncio.create_task(
                save_state()
            )

    _default_link_created = True


# ============================================================
# LINK MANAGEMENT
# ============================================================

async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    connection_limit: int = 0,
    fragment: str = "off",
    clean_ips=None,
    alarm_enabled: bool = False,
    category_id: str = "0",
    config_count: int = 1,
):

    protocol = normalize_protocol(protocol)

    fingerprint = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    if not (
        MIN_PORT
        <= port
        <= MAX_PORT
    ):
        port = DEFAULT_PORT

    uid = generate_uuid()

    record = {
        "label":
            sanitize_config_name((label or "").strip() or random_config_name()),

        "limit_bytes":
            max(
                0,
                int(limit_bytes),
            ),

        "used_bytes":
            0,

        "created_at":
            datetime.now().isoformat(),

        "active":
            True,

        "expires_at":
            expires_at,

        "note":
            (
                note
                or ""
            ).strip()[:500],

        "is_default":
            False,

        "sub_id":
            sub_id,

        "protocol":
            protocol,

        "fingerprint":
            fingerprint,

        "alpn":
            (
                alpn
                or ""
            ).strip()[:100],

        "port":
            port,

        "ip_limit":
            max(
                0,
                int(ip_limit),
            ),

        "speed_limit_bytes":
            max(
                0,
                int(speed_limit_bytes),
            ),

        "connection_limit":
            max(
                0,
                int(connection_limit),
            ),

        "fragment":
            (
                fragment
                or "off"
            ).strip().lower(),

        "security_profile": "balanced",
        "multi_login": False,
        "protocol_label": PROTOCOL_LABELS.get(protocol, protocol),
        "clean_ips": list(clean_ips or []),
        "alarm_enabled": bool(alarm_enabled),
        "category_id": str(category_id or "0"),
        "config_count": max(1, min(40, int(config_count or 1))),
        "usage_history": [],
    }

    async with LINKS_LOCK:
        LINKS[uid] = record

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return uid, record


async def remove_link(
    uid: str,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

        sub_id = LINKS[
            uid
        ].get(
            "sub_id"
        )

        del LINKS[uid]

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"حذف شد"
        ),
        "warn",
    )

    return label


async def set_link_active(
    uid: str,
    active: bool,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        LINKS[
            uid
        ][
            "active"
        ] = bool(active)

        record = LINKS[uid]

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"{'فعال' if active else 'غیرفعال'} شد"
        ),
        "ok"
        if active
        else "warn",
    )

    return record


# ============================================================
# SUB GROUPS
# ============================================================

async def create_sub_group(
    name: str = "گروه جدید",
    desc: str = "",
    password: str = "",
):

    name = (
        name
        or "گروه جدید"
    ).strip()[:60]

    desc = (
        desc
        or ""
    ).strip()[:200]

    password = (
        password
        or ""
    ).strip()

    sub_id = generate_uuid()

    uuid_key = secrets.token_urlsafe(16)

    record = {
        "name":
            name,

        "desc":
            desc,

        "password_hash":
            (
                hash_password(password)
                if password
                else None
            ),

        "uuid_key":
            uuid_key,

        "created_at":
            datetime.now().isoformat(),

        "link_ids":
            [],
    }

    async with SUBS_LOCK:
        SUBS[sub_id] = record

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return (
        sub_id,
        record,
    )


async def set_link_sub(
    uid: str,
    sub_id: str | None,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return False

        old_sub = LINKS[
            uid
        ].get(
            "sub_id"
        )

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

    if sub_id is not None:

        async with SUBS_LOCK:

            if sub_id not in SUBS:
                return False

    async with SUBS_LOCK:

        if (
            old_sub
            and old_sub in SUBS
        ):

            ids = SUBS[
                old_sub
            ].get(
                "link_ids",
                [],
            )

            if uid in ids:
                ids.remove(uid)

        if (
            sub_id
            and sub_id in SUBS
        ):

            ids = SUBS[
                sub_id
            ].setdefault(
                "link_ids",
                [],
            )

            if uid not in ids:
                ids.append(uid)

    async with LINKS_LOCK:

        if uid in LINKS:

            LINKS[
                uid
            ][
                "sub_id"
            ] = sub_id

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"{'به گروه اضافه شد' if sub_id else 'از گروه خارج شد'}"
        ),
        "info",
    )

    return True


async def remove_sub_group(
    sub_id: str,
):

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            return None

        name = SUBS[
            sub_id
        ].get(
            "name",
            sub_id,
        )

        del SUBS[sub_id]

    async with LINKS_LOCK:

        for link in LINKS.values():

            if (
                link.get("sub_id")
                == sub_id
            ):
                link["sub_id"] = None

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"حذف شد"
        ),
        "warn",
    )

    return name


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    global http_client

    limits = httpx.Limits(
        max_connections=500,
        max_keepalive_connections=100,
    )

    timeout = httpx.Timeout(
        30.0,
        connect=10.0,
    )

    http_client = httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )

    await load_state()

    await ensure_default_categories()
    await ensure_default_link()

    log_activity(
        "system",
        (
            f"{APP_NAME} "
            f"v{APP_VERSION} "
            f"راه‌اندازی شد"
        ),
        "ok",
    )

    logger.info(
        "%s v%s started on 0.0.0.0:%s",
        APP_NAME,
        APP_VERSION,
        PORT,
    )

    logger.info(
        "Data directory: %s",
        DATA_DIR,
    )


@app.on_event("shutdown")
async def shutdown():

    await save_state()

    if http_client:
        await http_client.aclose()


# ============================================================
# LANDING
# ============================================================

LANDING_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>PX Panel</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<link
href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
rel="stylesheet">

<style>
*{
    box-sizing:border-box;
}

html,body{
    margin:0;
    min-height:100%;
}

body{
    min-height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    padding:20px;
    color:#fff;
    font-family:"Vazirmatn",sans-serif;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(37,99,235,.22),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 85%,
            rgba(59,130,246,.18),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:580px;
    padding:32px;
    border-radius:28px;

    border:1px solid rgba(255,255,255,.09);

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.07),
            rgba(255,255,255,.025)
        );

    backdrop-filter:blur(28px) saturate(150%);

    box-shadow:
        0 30px 90px rgba(0,0,0,.45);
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;
}

.logo{
    width:48px;
    height:48px;
    border-radius:15px;

    display:flex;
    justify-content:center;
    align-items:center;

    font-size:18px;
    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

.brand-name{
    font-size:17px;
    font-weight:900;
}

.version{
    margin-top:4px;
    font-size:11px;
    color:#60a5fa;
}

.status{
    display:inline-block;
    margin-top:23px;
    padding:7px 11px;
    border-radius:999px;

    color:#86efac;
    background:rgba(34,197,94,.07);
    border:1px solid rgba(34,197,94,.15);

    font-size:11px;
}

h1{
    margin:18px 0 0;
    font-size:28px;
    line-height:1.55;
}

.desc{
    margin-top:12px;
    color:rgba(255,255,255,.52);
    line-height:2;
    font-size:13px;
}

.path{
    margin-top:22px;
    padding:15px;
    border-radius:15px;

    background:rgba(0,0,0,.18);
    border:1px solid rgba(255,255,255,.07);

    direction:ltr;
    text-align:left;
    font-family:Consolas,monospace;
    color:#93c5fd;
}

.actions{
    display:flex;
    gap:10px;
    margin-top:20px;
}

.btn{
    flex:1;
    padding:13px;
    border-radius:14px;
    text-align:center;
    text-decoration:none;

    font-size:12px;
    font-weight:800;
}

.primary{
    color:#fff;
    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

.secondary{
    color:#fff;
    background:rgba(255,255,255,.035);
    border:1px solid rgba(255,255,255,.08);
}

.footer{
    margin-top:22px;
    padding-top:16px;
    border-top:1px solid rgba(255,255,255,.07);

    display:flex;
    justify-content:space-between;

    font-size:10px;
    color:rgba(255,255,255,.35);
}

.support{
    color:#60a5fa;
    text-decoration:none;
}

@media(max-width:600px){
    .card{
        padding:24px;
        border-radius:22px;
    }

    h1{
        font-size:23px;
    }

    .actions{
        flex-direction:column;
    }
}

/* PXPanel 13.0.1 responsive system */
html{scroll-behavior:smooth} body{overflow-x:hidden} button,input,select,textarea{touch-action:manipulation} .modal{overscroll-behavior:contain}
@media(max-width:900px){.container,.shell,.dashboard,.main,.content{max-width:100%!important;width:100%!important}.grid,.stats-grid,.cards-grid,.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}.sidebar{z-index:1000}}
@media(max-width:640px){body{padding:10px!important;font-size:14px}.grid,.stats-grid,.cards-grid,.form-grid{grid-template-columns:1fr!important}.card,.panel,.section,.modal{border-radius:18px!important}.modal{max-height:92vh;overflow:auto;padding:14px!important}.header,.topbar,.toolbar,.actions{flex-wrap:wrap!important}.header>* ,.topbar>*{max-width:100%}.btn,button{min-height:44px}.field input,.field select,.field textarea,input,select,textarea{min-height:44px;font-size:16px;max-width:100%}table{display:block;overflow-x:auto;white-space:nowrap}.link-row,.config-row{flex-direction:column!important;align-items:stretch!important}.brand-name{font-size:15px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}

/* Toggle switch */
.switch{position:relative;display:inline-block;width:42px;height:24px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:rgba(255,255,255,.12);border-radius:24px;transition:.2s}
.slider:before{position:absolute;content:"";height:18px;width:18px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(18px)}

</style>
</head>

<body>

<div class="card">

<div class="brand">

<div class="logo">P</div>

<div>
<div class="brand-name">
PX Panel
</div>

<div class="version">
13.7.1
</div>
</div>

</div>

<div class="status">
● سیستم آنلاین و فعال است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<div class="desc">
این صفحه، درگاه عمومی PX Panel است.
برای دسترسی به داشبورد مدیریت از مسیر ورود استفاده کنید.
</div>

<div class="path">
/login
</div>

<div class="actions">

<a
href="/login"
class="btn primary"
>
ورود به پنل
</a>

<a
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
class="btn secondary"
>
پشتیبانی
</a>

</div>

<div class="footer">

<span>
PX Panel · 13.7.1
</span>

<a
href="https://t.me/Pixonal"
target="_blank"
class="support"
>
@Pixonal
</a>

</div>

</div>

</body>
</html>
"""


@app.get(
    "/",
    response_class=HTMLResponse,
)
async def root(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LANDING_HTML
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "connections": len(connections),
        "uptime": uptime(),
    }


# ============================================================
# LOGIN
# ============================================================

LOGIN_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>ورود | PX Panel</title>

<link
rel="preconnect"
href="https://fonts.googleapis.com"
>

<link
rel="preconnect"
href="https://fonts.gstatic.com"
crossorigin
>

<link
href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap"
rel="stylesheet"
>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;

    display:flex;
    align-items:center;
    justify-content:center;

    padding:20px;

    font-family:"Vazirmatn",sans-serif;
    color:#fff;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(37,99,235,.20),
            transparent 32%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:420px;
    padding:30px;
    border-radius:26px;

    background:rgba(255,255,255,.045);
    border:1px solid rgba(255,255,255,.09);

    backdrop-filter:blur(28px);

    box-shadow:
        0 30px 90px rgba(0,0,0,.45);
}

.logo{
    width:49px;
    height:49px;

    display:flex;
    align-items:center;
    justify-content:center;

    border-radius:16px;
    margin-bottom:20px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

h1{
    margin:0;
    font-size:25px;
}

.version{
    margin-top:5px;
    color:#60a5fa;
    font-size:11px;
}

.desc{
    margin-top:9px;
    color:rgba(255,255,255,.48);
    line-height:1.9;
    font-size:12px;
}

form{
    margin-top:21px;
}

label{
    display:block;
    margin-bottom:8px;
    font-size:12px;
    color:rgba(255,255,255,.55);
}

input{
    width:100%;
    padding:14px;

    border:1px solid rgba(255,255,255,.08);
    outline:none;
    border-radius:14px;

    color:#fff;
    background:rgba(0,0,0,.18);

    direction:ltr;
    text-align:left;

    font-family:"Vazirmatn",sans-serif;
}

input:focus{
    border-color:rgba(129,140,248,.6);
}

button{
    width:100%;
    margin-top:13px;
    padding:14px;

    border:0;
    border-radius:14px;

    color:#fff;
    cursor:pointer;

    font-family:"Vazirmatn",sans-serif;
    font-weight:800;

    background:
        linear-gradient(
            135deg,
            #2563eb,
            #3b82f6
        );
}

.error{
    margin-top:12px;
    padding:11px;

    border-radius:12px;

    color:#fca5a5;
    background:rgba(239,68,68,.08);
    border:1px solid rgba(239,68,68,.15);

    font-size:11px;
}

.support{
    display:block;
    margin-top:18px;
    text-align:center;

    color:#60a5fa;
    text-decoration:none;

    font-size:11px;
}

</style>

</head>

<body>

<div class="card">

<div class="logo">
P
</div>

<h1>
ورود به PX Panel
</h1>

<div class="version">
13.7.1
</div>

<div class="desc">
برای ادامه رمز عبور پنل مدیریت را وارد کنید.
</div>

<form
method="post"
action="/login"
>

<label>
رمز عبور
</label>

<input
type="password"
name="password"
autocomplete="current-password"
autofocus
placeholder="رمز عبور"
>

<button type="submit">
ورود به پنل
</button>

</form>

<a
href="https://t.me/Pixonal"
target="_blank"
class="support"
>
پشتیبانی @Pixonal
</a>

</div>

</body>
</html>
"""


def login_error_html(
    message: str,
):
    safe_message = escape_html(
        message
    )

    return LOGIN_HTML.replace(
        "</form>",
        (
            f"""
            <div class="error">
                {safe_message}
            </div>
            </form>
            """
        ),
    )


@app.get(
    "/login",
    response_class=HTMLResponse,
)
async def login_page(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LOGIN_HTML
    )


@app.post("/login")
async def login_form(
    request: Request,
):

    try:

        content_type = (
            request.headers
            .get(
                "content-type",
                "",
            )
            .lower()
        )

        if "application/json" in content_type:

            body = await request.json()

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

        else:

            raw = await request.body()

            parsed = parse_qs(
                raw.decode(
                    "utf-8",
                    errors="ignore",
                )
            )

            password = (
                parsed.get(
                    "password",
                    [""],
                )[0]
                .strip()
            )

    except Exception as exc:

        logger.exception(
            "Login parser error: %s",
            exc,
        )

        return HTMLResponse(
            login_error_html(
                "خطا در پردازش اطلاعات ورود."
            ),
            status_code=400,
        )

    ip = client_ip(request)

    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        minutes = max(1, (retry_after + 59) // 60)
        return HTMLResponse(
            login_error_html(
                f"به دلیل تلاش‌های ناموفق متعدد، ورود موقتاً مسدود شده است. حدود {minutes} دقیقه دیگر دوباره تلاش کنید."
            ),
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    if not password:
        register_login_failure(ip)
        return HTMLResponse(
            login_error_html(
                "رمز عبور را وارد کنید."
            ),
            status_code=400,
        )

    if (
        hash_password(password)
        != AUTH["password_hash"]
    ):

        locked, value = register_login_failure(ip)
        if locked:
            return HTMLResponse(
                login_error_html(
                    "تعداد تلاش‌های ناموفق بیش از حد مجاز بود. این IP برای ۱۵ دقیقه مسدود شد."
                ),
                status_code=429,
                headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)},
            )

        remaining = value
        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق از {ip}؛ "
                f"{remaining} تلاش باقی مانده"
            ),
            "err",
        )

        return HTMLResponse(
            login_error_html(
                f"رمز عبور اشتباه است. {remaining} تلاش دیگر باقی مانده است."
            ),
            status_code=401,
        )

    clear_login_failures(ip)

    token = await create_session()

    response = RedirectResponse(
        "/dashboard?login=1",
        status_code=303,
    )

    set_auth_cookie(
        response,
        request,
        token,
    )

    log_activity(
        "auth",
        (
            f"ورود موفق به پنل "
            f"از {client_ip(request)}"
        ),
        "ok",
    )

    return response


@app.post("/api/login")
async def api_login(
    request: Request,
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    password = str(
        body.get(
            "password",
            "",
        )
    ).strip()

    ip = client_ip(request)

    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail=f"ورود موقتاً مسدود است. حدود {max(1, (retry_after + 59) // 60)} دقیقه دیگر تلاش کنید.",
            headers={"Retry-After": str(retry_after)},
        )

    if not password:
        register_login_failure(ip)
        raise HTTPException(
            status_code=400,
            detail="رمز عبور را وارد کنید",
        )

    if (
        hash_password(password)
        != AUTH["password_hash"]
    ):

        locked, value = register_login_failure(ip)
        if locked:
            raise HTTPException(
                status_code=429,
                detail="تعداد تلاش‌های ناموفق بیش از حد مجاز بود. این IP برای ۱۵ دقیقه مسدود شد.",
                headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)},
            )

        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق از {ip}؛ "
                f"{value} تلاش باقی مانده"
            ),
            "err",
        )

        raise HTTPException(
            status_code=401,
            detail=f"رمز عبور اشتباه است؛ {value} تلاش دیگر باقی مانده است",
        )

    clear_login_failures(ip)

    token = await create_session()

    response = JSONResponse(
        {
            "ok": True,
            "authenticated": True,
        }
    )

    set_auth_cookie(
        response,
        request,
        token,
    )

    return response


# ============================================================
# LOGOUT
# ============================================================

@app.get("/logout")
async def logout_page(
    request: Request,
):

    await destroy_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    )

    response = RedirectResponse(
        "/login"
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
    )

    return response


@app.post("/api/logout")
async def api_logout(
    request: Request,
):

    await destroy_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    )

    response = JSONResponse(
        {
            "ok": True
        }
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
    )

    return response


@app.get("/api/me")
async def api_me(
    request: Request,
):

    return {
        "authenticated":
            await is_valid_session(
                request.cookies.get(
                    SESSION_COOKIE
                )
            )
    }


# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.post("/api/change-password")
async def api_change_password(
    request: Request,
    token=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    current_password = str(
        body.get(
            "current_password",
            "",
        )
    )

    if (
        hash_password(current_password)
        != AUTH["password_hash"]
    ):
        raise HTTPException(
            status_code=400,
            detail="رمز فعلی اشتباه است",
        )

    new_password = str(
        body.get(
            "new_password",
            "",
        )
    )

    repeat_password = str(
        body.get(
            "repeat_password",
            "",
        )
    )

    if len(new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="رمز جدید باید حداقل ۶ کاراکتر باشد",
        )

    if new_password != repeat_password:
        raise HTTPException(
            status_code=400,
            detail="تکرار رمز عبور یکسان نیست",
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )

    async with SESSIONS_LOCK:

        SESSIONS.clear()

        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )

    await save_state()

    log_activity(
        "auth",
        "رمز عبور پنل تغییر کرد",
        "ok",
    )

    return {
        "ok": True
    }


# ============================================================
# CREATE LINK
# ============================================================

@app.post("/api/links")
async def create_link_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()

        if not isinstance(body, dict):
            raise ValueError(
                "body is not object"
            )

    except Exception as exc:

        logger.exception(
            "Create link JSON error: %s",
            exc,
        )

        raise HTTPException(
            status_code=400,
            detail="اطلاعات ارسال‌شده معتبر نیست.",
        )

    limit_value = safe_float(
        body.get(
            "limit_value",
            0,
        )
    )

    limit_unit = str(
        body.get(
            "limit_unit",
            "GB",
        )
        or "GB"
    ).upper()

    limit_bytes = (
        0
        if limit_value <= 0
        else parse_size_to_bytes(
            limit_value,
            limit_unit,
        )
    )

    expires_days = safe_int(
        body.get(
            "expires_days",
            0,
        ),
        minimum=0,
    )

    expires_at = (
        (
            datetime.now()
            + timedelta(
                days=expires_days
            )
        ).isoformat()
        if expires_days > 0
        else None
    )

    port = safe_int(
        body.get(
            "port",
            DEFAULT_PORT,
        ),
        default=DEFAULT_PORT,
        minimum=MIN_PORT,
        maximum=MAX_PORT,
    )

    ip_limit = safe_int(
        body.get(
            "ip_limit",
            0,
        ),
        minimum=0,
    )

    speed_value = safe_float(
        body.get(
            "speed_limit_value",
            0,
        )
    )

    speed_unit = str(
        body.get(
            "speed_limit_unit",
            "MBIT",
        )
        or "MBIT"
    ).upper()

    speed_bytes = (
        0
        if speed_value <= 0
        else parse_speed_to_bytes(
            speed_value,
            speed_unit,
        )
    )

    connection_limit = safe_int(
        body.get(
            "connection_limit",
            0,
        ),
        minimum=0,
    )

    protocol = str(
        body.get(
            "protocol",
            DEFAULT_PROTOCOL,
        )
        or DEFAULT_PROTOCOL
    ).strip()

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        )
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    fragment = str(
        body.get(
            "fragment",
            "off",
        )
        or "off"
    ).strip().lower()

    allowed_fragments = {
        "off",
        "safe",
        "balanced",
        "aggressive",
    }

    if fragment not in allowed_fragments:
        fragment = "off"

    raw_clean = body.get("clean_ips") or body.get("clean_ip") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    alarm_enabled = bool(body.get("alarm_enabled", False))
    category_id = str(body.get("category_id") or "0")
    if category_id not in CATEGORIES:
        category_id = "0"
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    cat = CATEGORIES.get(category_id) or {}
    if cat.get("limit_bytes") and limit_bytes <= 0:
        limit_bytes = int(cat["limit_bytes"])
    if cat.get("expires_days") and expires_days <= 0:
        expires_days = int(cat["expires_days"])
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
    if cat.get("connection_limit") and connection_limit <= 0:
        connection_limit = int(cat["connection_limit"])
    if cat.get("speed_limit_bytes") and speed_bytes <= 0:
        speed_bytes = int(cat["speed_limit_bytes"])
    if cat.get("ip_limit") and ip_limit <= 0:
        ip_limit = int(cat["ip_limit"])
    if cat.get("clean_ips") and not clean_ips:
        clean_ips = list(cat["clean_ips"])
    if cat.get("single_user"):
        if ip_limit == 0: ip_limit = 1
        if connection_limit == 0: connection_limit = 1
    label_val = body.get("label", "")
    if cat.get("random_name") or not str(label_val).strip():
        label_val = random_config_name()
    else:
        label_val = sanitize_config_name(str(label_val))

    uid, link = await make_link(
        label=label_val,
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get(
            "note",
            "",
        ),
        sub_id=body.get(
            "sub_id"
        ),
        protocol=protocol,
        fingerprint=fingerprint,
        alpn=body.get(
            "alpn",
            DEFAULT_ALPN_BY_PROTOCOL.get(
                protocol,
                "http/1.1",
            ),
        ),
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_bytes,
        connection_limit=connection_limit,
        fragment=fragment,
        clean_ips=clean_ips,
        alarm_enabled=alarm_enabled,
        category_id=category_id,
        config_count=config_count,
    )

    host = get_host(request)

    result = {
        **get_link_info(
            link,
            uid,
            host,
        ),
        "ok": True,
    }

    return result


# ============================================================
# AUTO CREATE
# ============================================================

@app.post("/api/links/auto")
async def create_auto_link(
    request: Request,
    _=Depends(require_auth),
):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict): body = {}
    host = get_host(request)
    protocol = normalize_protocol(body.get("protocol", DEFAULT_PROTOCOL))
    profile = str(body.get("profile", "balanced")).strip().lower()
    profiles = {
        "normal": {"ip":0,"conn":0,"speed":0,"fp":"chrome","fragment":"off"},
        "balanced": {"ip":2,"conn":4,"speed":0,"fp":"chrome","fragment":"safe"},
        "gaming": {"ip":1,"conn":2,"speed":0,"fp":"chrome","fragment":"safe"},
        "maximum": {"ip":0,"conn":0,"speed":0,"fp":"randomized","fragment":"safe"},
    }
    cfg = profiles.get(profile, profiles["balanced"])
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    uid, link = await make_link(
        label=auto_config_name(), limit_bytes=0, expires_at=None,
        ip_limit=cfg["ip"], speed_limit_bytes=cfg["speed"], connection_limit=cfg["conn"],
        note=f"Auto generated by PXPanel | profile={profile}",
        protocol=protocol, fingerprint=cfg["fp"],
        alpn=DEFAULT_ALPN_BY_PROTOCOL.get(protocol, ""), port=443, fragment=cfg["fragment"],
        config_count=config_count,
    )
    link["security_profile"] = profile
    result = {**get_link_info(link, uid, host), "ok": True, "profile": profile}
    log_activity("link", f"کانفیگ خودکار «{link['label']}» با {PROTOCOL_LABELS.get(protocol, protocol)} ساخته شد", "ok")
    return result


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/protocols")
async def api_protocols(request: Request):
    require_auth(request)
    return {"protocols": [{"id": p, "label": PROTOCOL_LABELS.get(p, p)} for p in PROTOCOLS], "default": DEFAULT_PROTOCOL}


@app.get("/api/links")
async def list_links(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    result = []

    for uid, link in snapshot.items():

        info = get_link_info(
            link,
            uid,
            host,
        )

        result.append(
            {
                **info,

                "created_at":
                    link.get(
                        "created_at"
                    ),

                "expired":
                    is_link_expired(
                        link
                    ),

                "sub_url":
                    f"https://{host}/sub/{uid}",

                "info_url":
                    f"https://{host}/info/{uid}",

                "connected_ips":
                    len(
                        unique_ips_for_uuid(
                            uid
                        )
                    ),
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "links": result
    }


# ============================================================
# LINK INFO API
# ============================================================

@app.get("/api/links/{uid}/info")
async def link_info_api(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        snapshot = dict(link)

    host = get_host(request)

    return {
        "ok": True,
        **get_link_info(
            snapshot,
            uid,
            host,
        ),
    }


# ============================================================
# UPDATE LINK
# ============================================================

@app.patch("/api/links/{uid}")
async def update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    async with LINKS_LOCK:

        if uid not in LINKS:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link = LINKS[uid]

        old_sub = link.get(
            "sub_id"
        )

        label = link.get(
            "label",
            uid,
        )

        if "active" in body:
            link["active"] = bool(
                body["active"]
            )

        if "label" in body:

            value = str(
                body["label"]
            ).strip()

            if value:
                link["label"] = value[:60]

        if "note" in body:

            link["note"] = str(
                body.get(
                    "note",
                    "",
                )
            )[:500]

        if "reset_usage" in body:

            if body.get(
                "reset_usage"
            ):
                link[
                    "used_bytes"
                ] = 0

        if "limit_value" in body:

            value = safe_float(
                body.get(
                    "limit_value",
                    0,
                )
            )

            unit = str(
                body.get(
                    "limit_unit",
                    "GB",
                )
                or "GB"
            )

            link[
                "limit_bytes"
            ] = (
                0
                if value <= 0
                else parse_size_to_bytes(
                    value,
                    unit,
                )
            )

        if "expires_days" in body:

            days = safe_int(
                body.get(
                    "expires_days",
                    0,
                ),
                minimum=0,
            )

            link[
                "expires_at"
            ] = (
                (
                    datetime.now()
                    + timedelta(
                        days=days
                    )
                ).isoformat()
                if days > 0
                else None
            )

        if "fingerprint" in body:

            fingerprint = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).strip().lower()

            link[
                "fingerprint"
            ] = (
                fingerprint
                if fingerprint in FINGERPRINTS
                else DEFAULT_FINGERPRINT
            )

        if "alpn" in body:

            link["alpn"] = str(
                body.get(
                    "alpn",
                    "",
                )
            )[:100]

        if "port" in body:

            p = safe_int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                ),
                default=DEFAULT_PORT,
                minimum=MIN_PORT,
                maximum=MAX_PORT,
            )

            link["port"] = p

        if "ip_limit" in body:

            link["ip_limit"] = safe_int(
                body.get(
                    "ip_limit",
                    0,
                ),
                minimum=0,
            )

        if "connection_limit" in body:

            link[
                "connection_limit"
            ] = safe_int(
                body.get(
                    "connection_limit",
                    0,
                ),
                minimum=0,
            )

        if "speed_limit_value" in body:

            speed_value = safe_float(
                body.get(
                    "speed_limit_value",
                    0,
                )
            )

            speed_unit = str(
                body.get(
                    "speed_limit_unit",
                    "MBIT",
                )
                or "MBIT"
            )

            link[
                "speed_limit_bytes"
            ] = (
                0
                if speed_value <= 0
                else parse_speed_to_bytes(
                    speed_value,
                    speed_unit,
                )
            )

        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                )
            ).strip()

            link["protocol"] = (
                protocol
                if protocol in PROTOCOLS
                else DEFAULT_PROTOCOL
            )

        if "fragment" in body:

            fragment = str(
                body.get(
                    "fragment",
                    "off",
                )
                or "off"
            ).strip().lower()

            if fragment not in {
                "off",
                "safe",
                "balanced",
                "aggressive",
            }:
                fragment = "off"

            link["fragment"] = fragment

        if "sub_id" in body:

            link[
                "sub_id"
            ] = (
                body.get(
                    "sub_id"
                )
                or None
            )

        new_sub = body.get(
            "sub_id",
            "UNCHANGED",
        )

    if new_sub != "UNCHANGED":

        async with SUBS_LOCK:

            if (
                old_sub
                and old_sub in SUBS
            ):

                ids = SUBS[
                    old_sub
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

            if (
                new_sub
                and new_sub in SUBS
            ):

                ids = SUBS[
                    new_sub
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"ویرایش شد"
        ),
        "info",
    )

    return {
        "ok": True
    }


# ============================================================
# RESET USAGE
# ============================================================

@app.post(
    "/api/links/{uid}/reset-usage"
)
async def reset_link_usage(
    uid: str,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link["used_bytes"] = 0

        label = link.get(
            "label",
            uid,
        )

    await save_state()

    log_activity(
        "link",
        (
            f"مصرف کانفیگ "
            f"«{label}» ریست شد"
        ),
        "info",
    )

    return {
        "ok": True,
        "uuid": uid,
        "used_bytes": 0,
    }


# ============================================================
# LINK ACTION
# ============================================================

@app.post(
    "/api/links/{uid}/action"
)
async def link_action(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    action = str(
        body.get(
            "action",
            "",
        )
    ).strip().lower()

    if action == "reset":

        await reset_link_usage(
            uid,
            _
        )

        return {
            "ok": True,
            "action": "reset",
        }

    if action == "enable":

        result = await set_link_active(
            uid,
            True,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "enable",
        }

    if action == "disable":

        result = await set_link_active(
            uid,
            False,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "disable",
        }

    raise HTTPException(
        status_code=400,
        detail="unknown action",
    )


# ============================================================
# DELETE LINK
# ============================================================

@app.delete("/api/links/{uid}")
async def delete_link(
    uid: str,
    _=Depends(require_auth),
):

    label = await remove_link(uid)

    if label is None:
        raise HTTPException(
            status_code=404,
            detail="link not found",
        )

    return {
        "ok": True,
        "deleted": uid,
    }




def subscription_metadata_headers(used_bytes: int, limit_bytes: int, expires_at, host: str, info_url: str, title: str):
    """Standard subscription headers understood by v2rayNG/v2rayN/Hiddify and similar clients."""
    used_bytes = max(0, int(used_bytes or 0))
    limit_bytes = max(0, int(limit_bytes or 0))

    expire_unix = 0
    if expires_at:
        try:
            dt = datetime.fromisoformat(str(expires_at))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IRAN_TZ) if IRAN_TZ else dt
            expire_unix = max(0, int(dt.timestamp()))
        except Exception:
            expire_unix = 0

    userinfo = f"upload=0; download={used_bytes}; total={limit_bytes}; expire={expire_unix}"

    return {
        "profile-title": quote(title, safe=""),
        "profile-web-page-url": info_url,
        "support-url": SUPPORT_URL,
        "profile-update-interval": "12",
        "subscription-userinfo": userinfo,
        "content-disposition": 'inline; filename="subscription.txt"',
    }

# ============================================================
# SINGLE SUB
# ============================================================

@app.get("/sub/{uuid}")
async def subscription_single(
    uuid: str,
    request: Request,
):

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        raise HTTPException(
            status_code=404,
            detail="not found or inactive",
        )

    host = get_host(request)
    clean_ips = link.get("clean_ips") or []
    used = int(link.get("used_bytes", 0) or 0)
    limit = int(link.get("limit_bytes", 0) or 0)
    remaining = max(0, limit - used) if limit > 0 else 0
    volume_text = f"{fmt_bytes(used)}/{fmt_bytes(limit)} (باقی {fmt_bytes(remaining)})" if limit > 0 else f"{fmt_bytes(used)}/∞"
    expires_at = link.get("expires_at")
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(exp_dt.tzinfo) if getattr(exp_dt, "tzinfo", None) else datetime.now()
            secs = int((exp_dt - now_dt).total_seconds())
            if secs <= 0:
                time_text = "منقضی"
            else:
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                mins = rem // 60
                time_text = f"{days}د {hours}س" if days else (f"{hours}س {mins}د" if hours else f"{mins}د")
        except Exception:
            time_text = str(expires_at)[:16]
    else:
        time_text = "∞"
    label = str(link.get("label") or "Config")
    stats_remark = f"{label} | {volume_text} | {time_text}"
    stats_line = generate_vless_link(uuid, "0.0.0.0", remark=stats_remark, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT))
    lines = [stats_line]
    used_names = set()
    cfg_count = max(1, min(40, int(link.get("config_count") or 1)))
    if clean_ips:
        hosts = list(clean_ips)
        while len(hosts) < cfg_count:
            hosts.extend(clean_ips)
        hosts = hosts[:cfg_count]
        for cip in hosts:
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, cip, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    else:
        for i in range(cfg_count):
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, host, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    content = base64.b64encode("\n".join(lines).encode()).decode()
    profile_title = f"0.0.0.0 | {stats_remark}"
    headers = subscription_metadata_headers(
        used,
        limit,
        link.get("expires_at"),
        host,
        f"https://{host}/info/{uuid}",
        profile_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )

# ============================================================
# SUB ALL
# ============================================================

@app.get("/sub-all")
async def subscription_all(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:

        lines = [
            vless_link_for_link(
                link,
                uid,
                host,
            )

            for uid, link
            in LINKS.items()

            if is_link_allowed(link)
        ]

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    return Response(
        content=content,
        media_type="text/plain",
    )


# ============================================================
# INFO PAGE
# ============================================================

@app.get(
    "/info/{uid}",
    response_class=HTMLResponse,
)
async def info_page(
    uid: str,
    request: Request,
):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return HTMLResponse("<html lang=\"fa\" dir=\"rtl\"><body style=\"margin:0;background:#07070a;color:#fff;font-family:sans-serif;padding:40px\"><h2>کانفیگ پیدا نشد</h2></body></html>", status_code=404)
        snapshot = dict(link)

    host = get_host(request)
    vless_url = vless_link_for_link(snapshot, uid, host)
    sub_url = f"https://{host}/sub/{uid}"
    used = int(snapshot.get("used_bytes", 0) or 0)
    limit = int(snapshot.get("limit_bytes", 0) or 0)
    if limit > 0:
        usage_percent = max(0, min(100, round((used / limit) * 100, 1)))
        usage_value = f"{fmt_bytes(used)} / {fmt_bytes(limit)}"
        remaining_value = fmt_bytes(max(0, limit - used))
    else:
        usage_percent = 0
        usage_value = f"{fmt_bytes(used)} / نامحدود"
        remaining_value = "نامحدود"

    expires_at = snapshot.get("expires_at")
    if expires_at:
        try:
            expiry_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(expiry_dt.tzinfo) if expiry_dt.tzinfo else datetime.now()
            seconds = int((expiry_dt - now_dt).total_seconds())
            if seconds <= 0:
                expiry_remaining = "منقضی شده"
            else:
                days, rem = divmod(seconds, 86400)
                hours, rem = divmod(rem, 3600)
                minutes, _ = divmod(rem, 60)
                expiry_remaining = f"{days} روز و {hours} ساعت" if days else (f"{hours} ساعت و {minutes} دقیقه" if hours else f"{minutes} دقیقه")
        except Exception:
            expiry_remaining = "نامشخص"
        expiry_display = str(expires_at)
    else:
        expiry_remaining = "نامحدود"
        expiry_display = "نامحدود"

    status_text = "فعال" if is_link_allowed(snapshot) else "غیرفعال"
    status_class = "good" if status_text == "فعال" else "bad"
    ip_limit = "نامحدود" if not snapshot.get("ip_limit", 0) else str(snapshot.get("ip_limit"))
    connection_limit = "نامحدود" if not snapshot.get("connection_limit", 0) else str(snapshot.get("connection_limit"))
    speed_limit = "نامحدود" if not snapshot.get("speed_limit_bytes", 0) else fmt_bytes(snapshot.get("speed_limit_bytes", 0)) + "/s"

    usage_history = snapshot.get("usage_history", [])
    svg_points = "0,50 300,50"
    if usage_history and len(usage_history) > 1:
        max_hist = max(usage_history) if max(usage_history) > 0 else 1
        pts = []
        step = 300 / (len(usage_history) - 1)
        for i, val in enumerate(usage_history):
            x = i * step
            y = 60 - min(60, max(4, (val / max_hist) * 52))
            pts.append(f"{x:.1f},{y:.1f}")
        svg_points = " ".join(pts)
    elif usage_history and len(usage_history) == 1:
        svg_points = f"0,50 300,{60 - min(60, max(4, (usage_history[0] / (limit if limit > 0 else max(used, 1))) * 52)):.1f}"

    status_badge_html = 'text-emerald-300 border border-emerald-400/25 bg-emerald-400/10' if status_class == 'good' else 'text-rose-300 border border-rose-400/25 bg-rose-400/10'
    label_escaped = escape_html(snapshot.get("label", "PXpanel"))
    uid_escaped = escape_html(uid)
    app_version_str = escape_html(str(APP_VERSION))
    used_bytes_str = escape_html(fmt_bytes(used))
    limit_bytes_str = escape_html(fmt_bytes(limit)) if limit > 0 else '∞'
    remaining_value_escaped = escape_html(remaining_value)
    expiry_remaining_escaped = escape_html(expiry_remaining)
    expiry_display_escaped = escape_html(expiry_display)
    ip_limit_escaped = escape_html(ip_limit)
    connection_limit_escaped = escape_html(connection_limit)
    speed_limit_escaped = escape_html(speed_limit)
    protocol_escaped = escape_html(snapshot.get("protocol", "vless-ws"))
    fingerprint_escaped = escape_html(snapshot.get("fingerprint", "chrome"))
    vless_url_escaped = escape_html(vless_url)
    sub_url_escaped = escape_html(sub_url)
    dash_calc_offset = f"{339.29 - (339.29 * min(usage_percent, 100) / 100):.1f}"

    info_html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{label_escaped} | INFO</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<script>
  tailwind.config = {{
    theme: {{
      extend: {{
        fontFamily: {{ vazir: ['Vazirmatn','system-ui','sans-serif'] }}
      }}
    }}
  }}
</script>
<style>
  :root {{
    --bg-main: #05060a;
    --bg-card: rgba(255, 255, 255, 0.04);
    --bg-card-hover: rgba(255, 255, 255, 0.07);
    --border-color: rgba(255, 255, 255, 0.1);
    --text-main: #f1f5f9;
    --text-muted: rgba(255, 255, 255, 0.4);
    --bg-sub-card: rgba(0, 0, 0, 0.2);
    --grad-1: rgba(96,165,250,.16);
    --grad-2: rgba(96,165,250,.13);
    --grad-3: rgba(52,211,153,.08);
  }}

  body.theme-lighter {{
    --bg-main: #131722;
    --bg-card: rgba(255, 255, 255, 0.075);
    --bg-card-hover: rgba(255, 255, 255, 0.115);
    --border-color: rgba(255, 255, 255, 0.16);
    --text-main: #ffffff;
    --text-muted: rgba(255, 255, 255, 0.6);
    --bg-sub-card: rgba(0, 0, 0, 0.35);
    --grad-1: rgba(96,165,250,.24);
    --grad-2: rgba(96,165,250,.20);
    --grad-3: rgba(52,211,153,.13);
  }}

  html,body{{background:var(--bg-main); transition: background 0.3s ease, color 0.3s ease;}}
  body{{
    background:
      radial-gradient(ellipse 80% 50% at 10% -10%, var(--grad-1), transparent 50%),
      radial-gradient(ellipse 60% 40% at 95% 15%, var(--grad-2), transparent 45%),
      radial-gradient(ellipse 55% 35% at 60% 100%, var(--grad-3), transparent 40%),
      var(--bg-main);
  }}
  .status-dot{{box-shadow:0 0 10px currentColor}}
  ::-webkit-scrollbar{{width:8px;height:8px}}
  ::-webkit-scrollbar-thumb{{background:rgba(255,255,255,.12);border-radius:99px}}
  * {{ box-shadow: none !important; }}
  .copy-btn svg{{transition:none}}
  
  .dynamic-card {{
    background-color: var(--bg-card);
    border-color: var(--border-color);
    transition: background-color 0.3s ease, border-color 0.3s ease;
  }}
  .dynamic-card:hover {{
    background-color: var(--bg-card-hover);
  }}
  .sub-box {{
    background-color: var(--bg-sub-card);
  }}
</style>
</head>
<body class="font-vazir text-slate-100 antialiased min-h-screen py-8 px-3 sm:px-4 md:py-14">

<div class="w-full max-w-4xl mx-auto space-y-5 sm:space-y-6 md:space-y-8">

  <!-- Top Bar Theme Toggle Button -->
  <div class="flex justify-end">
    <button type="button" onclick="toggleTheme()" class="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-extrabold text-amber-300 border border-amber-400/30 bg-amber-400/10 hover:bg-amber-400/20 transition-colors shadow-lg">
      <svg id="themeIcon" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
      تغییر تم
    </button>
  </div>

  <!-- Hero -->
  <section class="rounded-[26px] sm:rounded-[28px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-8">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-5">
      <div class="flex items-center gap-4">
        <div class="w-13 h-13 sm:w-14 sm:h-14 shrink-0 rounded-2xl grid place-items-center bg-gradient-to-br from-blue-400/20 to-purple-400/10 border border-blue-400/25 text-blue-300">
          <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5.2-3.4 9-8 10-4.6-1-8-4.8-8-10V6l8-4z"/><path d="M9.5 12l1.8 1.8L15 10"/></svg>
        </div>
        <div class="min-w-0">
          <h1 class="text-lg sm:text-xl md:text-2xl font-black tracking-tight truncate">{label_escaped}</h1>
          <p class="mt-1.5 text-[10.5px] sm:text-[11px] text-white/40 break-all">UUID: {uid_escaped} &nbsp;·&nbsp; PXpanel {app_version_str}</p>
        </div>
      </div>
      <div class="flex items-center gap-2.5 self-start md:self-auto flex-wrap">
        <button type="button" onclick="openQrModal()" class="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-extrabold text-purple-300 border border-purple-400/30 bg-purple-400/10 hover:bg-purple-400/20 transition-colors">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          QR Code
        </button>
        <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-extrabold {status_badge_html}">
          <span class="status-dot w-2 h-2 rounded-full bg-current"></span>
          {status_text}
        </div>
      </div>
    </div>
  </section>

  <!-- Usage overview -->
  <section class="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-5 sm:gap-6">

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><path d="M3 3v18h18"/><path d="M7 15l4-6 3 3 4-7"/></svg>
        <div>
          <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Traffic Overview</p>
          <p class="mt-0.5 text-sm font-black">مصرف سرویس</p>
        </div>
      </div>

      <div class="mt-6 flex flex-col sm:flex-row items-center sm:items-start gap-6">
        <div class="relative shrink-0 w-[128px] h-[128px]">
          <svg width="128" height="128" viewBox="0 0 132 132" class="-rotate-90">
            <circle cx="66" cy="66" r="54" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="10"/>
            <circle cx="66" cy="66" r="54" fill="none" stroke="url(#usageRingGradient)" stroke-width="10" stroke-linecap="round"
              stroke-dasharray="339.29" stroke-dashoffset="{dash_calc_offset}"/>
            <defs>
              <linearGradient id="usageRingGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#34d399"/>
                <stop offset="100%" stop-color="#f59e0b"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="absolute inset-0 grid place-items-center">
            <div class="text-center">
              <p class="text-xl font-black leading-none">{usage_percent}%</p>
              <p class="mt-1.5 text-[10px] text-white/40">مصرف‌شده</p>
            </div>
          </div>
        </div>

        <div class="flex-1 w-full min-w-0">
          <div class="text-xl sm:text-2xl font-black tracking-tight">
            {used_bytes_str}
            <span class="text-sm font-semibold text-white/40"> / {limit_bytes_str}</span>
          </div>

          <div class="mt-4 rounded-xl border border-white/[0.05] sub-box px-3 pt-3 pb-1.5">
            <p class="flex items-center gap-1.5 text-[10px] text-white/35 mb-1">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l6-6 4 4 8-8"/><path d="M17 7h4v4"/></svg>
              روند مصرف
            </p>
            <svg viewBox="0 0 300 64" class="w-full h-14" preserveAspectRatio="none">
              <defs>
                <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#60a5fa" stop-opacity="0.35"/>
                  <stop offset="100%" stop-color="#60a5fa" stop-opacity="0"/>
                </linearGradient>
              </defs>
              <path d="M0,64 L{svg_points} L300,64 Z" fill="url(#trendFill)"/>
              <path d="M{svg_points}" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>

          <div class="mt-4 flex items-center justify-between text-[11px] text-white/40 flex-wrap gap-2">
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
              باقی‌مانده: <b class="text-white/70 font-bold">{remaining_value_escaped}</b>
            </span>
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
              زمان: <b class="text-white/70 font-bold">{expiry_remaining_escaped}</b>
            </span>

          </div>
        </div>
      </div>
    </div>

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 2"/></svg>
        <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Service</p>
      </div>
      <div class="mt-4 divide-y divide-white/[0.06]">
        <div class="flex items-center justify-between py-3 first:pt-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
            انقضا
          </span>
          <span class="text-xs font-extrabold">{expiry_display_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14 0"/><path d="M8.5 16a6 6 0 0 1 7 0"/><path d="M12 20h.01"/></svg>
            IP Limit
          </span>
          <span class="text-xs font-extrabold">{ip_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2"/><rect x="2" y="9" width="20" height="8" rx="2"/><path d="M6 17v2M18 17v2"/></svg>
            Connection
          </span>
          <span class="text-xs font-extrabold">{connection_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3 last:pb-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg>
            Speed
          </span>
          <span class="text-xs font-extrabold">{speed_limit_escaped}</span>
        </div>
      </div>
    </div>

  </section>

  <!-- Stats -->
  <section class="grid grid-cols-2 md:grid-cols-4 gap-3.5 sm:gap-4 md:gap-5">

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-emerald-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-emerald-400/10 border border-emerald-400/20 text-emerald-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M18 9l-5 5-3-3-4 4"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">مصرف فعلی</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-emerald-300 break-words">{used_bytes_str}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-amber-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-amber-400/10 border border-amber-400/20 text-amber-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-amber-300 break-words">{remaining_value_escaped}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-blue-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 4v16M4 9h16"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">اتصالات فعال</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-blue-300 break-words">{len(unique_ips_for_uuid(uid))}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-purple-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-purple-400/10 border border-purple-400/20 text-purple-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l9 4.5v6c0 5-3.6 8.7-9 9.5-5.4-.8-9-4.5-9-9.5v-6L12 2z"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">زمان باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-purple-300 break-words">{expiry_remaining_escaped}</p>
    </div>

  </section>

  <!-- Technical details -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M4 21v-7M4 10V3M12 21v-11M12 6V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg>
        جزئیات فنی
      </p>
      <p class="text-[11px] text-white/40">Configuration Details</p>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Protocol</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{protocol_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Fingerprint</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{fingerprint_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">IP Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{ip_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Connection Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{connection_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Speed Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{speed_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">تاریخ انقضا</p>
        <p class="mt-2 text-xs font-bold text-white/85">{expiry_display_escaped}</p>
      </div>
    </div>
  </section>

  <!-- Links -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11.5 4.5"/><path d="M14 11a5 5 0 0 0-7.07 0l-2.83 2.83a5 5 0 0 0 7.07 7.07l1.41-1.41"/></svg>
        لینک‌های سرویس
      </p>
      <p class="text-[11px] text-white/40">Copy / Import</p>
    </div>

    <div class="space-y-3">
      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">VLESS</p>
          <p id="vlessLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{vless_url_escaped}</p>
        </div>
        <button id="vlessCopyBtn" type="button" onclick="pxCopy('vlessLinkText','vlessCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>

      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">SUBSCRIPTION</p>
          <p id="subLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{sub_url_escaped}</p>
        </div>
        <button id="subCopyBtn" type="button" onclick="pxCopy('subLinkText','subCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>
    </div>
  </section>

  <!-- Downloads -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
        دانلود برنامه‌ها
      </p>
      <p class="text-[11px] text-white/40">Official Releases</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
      <a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">NG</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayNG</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android</p>
        </div>
      </a>
      <a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">N</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayN</p>
          <p class="mt-0.5 text-[10px] text-white/40">Windows / macOS / Linux</p>
        </div>
      </a>
      <a href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">H</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">Hiddify</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android / Windows / macOS / Linux</p>
        </div>
      </a>
    </div>
  </section>

  <!-- Footer -->
  <div class="rounded-2xl border border-emerald-400/15 bg-emerald-400/[0.05] p-4 text-center text-xs text-white/45">
    پشتیبانی و اطلاعیه‌ها &nbsp;·&nbsp; <b class="text-emerald-300">کانال تلگرام: logic_sec</b>
  </div>

</div>

<!-- QR Code Modal Popup -->
<div id="qrModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md hidden">
  <div class="w-full max-w-sm rounded-[24px] border border-white/15 bg-[#0b0c14] p-6 text-center shadow-2xl relative">
    <button type="button" onclick="closeQrModal()" class="absolute top-4 left-4 w-8 h-8 rounded-full bg-white/5 border border-white/10 grid place-items-center text-white/60 hover:text-white">✕</button>
    <p class="text-sm font-black text-white/90 mb-2">QR Code اسکن کانفیگ</p>
    <p class="text-[11px] text-white/40 mb-4">برای اتصال سریع با گوشی موبایل</p>
    <div id="qrcodeContainer" class="bg-white p-4 rounded-2xl inline-block mx-auto mb-4 border border-white/10"></div>
    <p id="qrModalText" class="text-[10px] text-purple-300 break-all max-h-16 overflow-y-auto px-2" dir="ltr"></p>
  </div>
</div>

<script>
const vlessUrlData = "{vless_url}";

// Theme toggle logic with localStorage support (2 themes total)
function toggleTheme() {{
  const body = document.body;
  body.classList.toggle('theme-lighter');
  const isLighter = body.classList.contains('theme-lighter');
  localStorage.setItem('px_theme', isLighter ? 'lighter' : 'dark');
}}

// Initialize saved theme on load
(function() {{
  if (localStorage.getItem('px_theme') === 'lighter') {{
    document.body.classList.add('theme-lighter');
  }}
}})();

function openQrModal() {{
  var modal = document.getElementById('qrModal');
  var container = document.getElementById('qrcodeContainer');
  var txtEl = document.getElementById('qrModalText');
  container.innerHTML = "";
  txtEl.textContent = vlessUrlData;
  modal.classList.remove('hidden');
  try {{
    var typeNumber = 0;
    var errorCorrectionLevel = 'L';
    var qr = qrcode(typeNumber, errorCorrectionLevel);
    qr.addData(vlessUrlData);
    qr.make();
    container.innerHTML = qr.createImgTag(5, 8);
  }} catch (e) {{
    container.innerHTML = "<p class='text-xs text-black'>خطا در تولید QR Code</p>";
  }}
}}

function closeQrModal() {{
  document.getElementById('qrModal').classList.add('hidden');
}}

document.getElementById('qrModal').addEventListener('click', function(e) {{
  if (e.target === this) closeQrModal();
}});

function pxCopy(textId, btnId) {{
  var el = document.getElementById(textId);
  var btn = document.getElementById(btnId);
  if (!el || !btn) return;
  var text = el.textContent.textContext || el.textContent.trim();
  var done = function() {{
    var original = btn.getAttribute('data-original');
    if (!original) {{
      original = btn.innerHTML;
      btn.setAttribute('data-original', original);
    }}
    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg><span>کپی شد</span>';
    btn.classList.add('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    setTimeout(function() {{
      btn.innerHTML = original;
      btn.classList.remove('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    }}, 1700);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done).catch(function() {{ fallbackCopy(text, done); }});
  }} else {{
    fallbackCopy(text, done);
  }}
}}
function fallbackCopy(text, cb) {{
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {{ document.execCommand('copy'); }} catch (e) {{}}
  document.body.removeChild(ta);
  if (cb) cb();
}}
</script>
</body>
</html>"""
    return HTMLResponse(info_html)
# ============================================================
# SUB GROUP API
# ============================================================

@app.post("/api/subs")
async def create_sub_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    sub_id, sub = await create_sub_group(
        name=body.get(
            "name",
            "گروه جدید",
        ),
        desc=body.get(
            "desc",
            "",
        ),
        password=body.get(
            "password",
            "",
        ),
    )

    host = get_host(request)

    return {
        "sub_id":
            sub_id,

        **sub,

        "password_hash":
            None,

        "public_url":
            (
                f"https://{host}"
                f"/p/{sub['uuid_key']}"
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{sub['uuid_key']}"
            ),
    }


@app.get("/api/subs")
async def list_subs_api(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with SUBS_LOCK:
        snapshot_subs = dict(SUBS)

    async with LINKS_LOCK:
        snapshot_links = dict(LINKS)

    result = []

    for sid, sub in snapshot_subs.items():

        link_ids = sub.get(
            "link_ids",
            [],
        )

        active_count = sum(
            1
            for lid in link_ids
            if is_link_allowed(
                snapshot_links.get(
                    lid
                )
            )
        )

        total_used = sum(
            snapshot_links[
                lid
            ].get(
                "used_bytes",
                0,
            )

            for lid in link_ids

            if lid in snapshot_links
        )

        result.append(
            {
                "sub_id":
                    sid,

                **sub,

                "password_hash":
                    None,

                "has_password":
                    sub.get(
                        "password_hash"
                    ) is not None,

                "links_count":
                    len(link_ids),

                "active_count":
                    active_count,

                "total_used_bytes":
                    total_used,

                "total_used_fmt":
                    fmt_bytes(
                        total_used
                    ),

                "public_url":
                    (
                        f"https://{host}"
                        f"/p/{sub['uuid_key']}"
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub-group/{sub['uuid_key']}"
                    ),
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "subs": result
    }


@app.patch("/api/subs/{sub_id}")
async def update_sub_api(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            raise HTTPException(
                status_code=404,
                detail="sub not found",
            )

        sub = SUBS[sub_id]

        if "name" in body:
            sub["name"] = str(
                body["name"]
            )[:60]

        if "desc" in body:
            sub["desc"] = str(
                body["desc"]
            )[:200]

        if "password" in body:

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

            sub["password_hash"] = (
                hash_password(password)
                if password
                else None
            )

        if "link_ids" in body:

            sub["link_ids"] = list(
                body["link_ids"]
            )

    await save_state()

    return {
        "ok": True
    }


@app.delete("/api/subs/{sub_id}")
async def delete_sub_api(
    sub_id: str,
    _=Depends(require_auth),
):

    name = await remove_sub_group(
        sub_id
    )

    if name is None:
        raise HTTPException(
            status_code=404,
            detail="sub not found",
        )

    return {
        "ok": True,
        "deleted": sub_id,
    }


@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    link_id = str(
        body.get(
            "link_id",
            "",
        )
    )

    action = str(
        body.get(
            "action",
            "add",
        )
    )

    if action == "add":

        success = await set_link_sub(
            link_id,
            sub_id,
        )

    else:

        success = await set_link_sub(
            link_id,
            None,
        )

    if not success:
        raise HTTPException(
            status_code=404,
            detail="link or sub not found",
        )

    return {
        "ok": True
    }


# ============================================================
# GROUP SUB
# ============================================================

@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        sub = next(
            (
                item
                for item
                in SUBS.values()
                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not sub:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    if sub.get(
        "password_hash"
    ):

        password = (
            request.query_params.get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub["password_hash"]
        ):

            raise HTTPException(
                status_code=403,
                detail="wrong password",
            )

    host = get_host(request)

    async with LINKS_LOCK:

        lines = []

        for link_id in sub.get(
            "link_ids",
            [],
        ):

            link = LINKS.get(
                link_id
            )

            if (
                link
                and is_link_allowed(
                    link
                )
            ):

                lines.append(
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    )
                )

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    total_used = 0
    total_limit = 0
    expiries = []
    valid_ids = list(sub.get("link_ids", []))

    async with LINKS_LOCK:
        for link_id in valid_ids:
            link = LINKS.get(link_id)
            if not link or not is_link_allowed(link):
                continue
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            if link.get("expires_at"):
                expiries.append(str(link.get("expires_at")))

    # For a group subscription, expose aggregate usage/expiry in standard headers.
    group_limit = total_limit if total_limit > 0 else 0
    group_expiry = None
    if expiries:
        try:
            group_expiry = min(
                expiries,
                key=lambda x: datetime.fromisoformat(x)
            )
        except Exception:
            group_expiry = expiries[0]

    group_volume_text = (
        f"{fmt_bytes(total_used)}/{fmt_bytes(group_limit)}"
        if group_limit > 0
        else f"{fmt_bytes(total_used)}/∞"
    )
    group_expiry_text = group_expiry or "∞"
    group_title = (
        f"0.0.0.0 | {group_volume_text} | {group_expiry_text} | "
        f"{sub['name']} | کانال تلگرام: logic_sec"
    )
    headers = subscription_metadata_headers(
        total_used,
        group_limit,
        group_expiry,
        host,
        f"https://{host}/public-sub/{uuid_key}",
        group_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )


# ============================================================
# PUBLIC GROUP
# ============================================================

PUBLIC_SUB_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>
<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
PX Panel
</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;

    display:flex;
    justify-content:center;
    align-items:center;

    padding:20px;

    font-family:Arial,sans-serif;

    color:#fff;

    background:
        radial-gradient(
            circle at top right,
            rgba(37,99,235,.17),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:560px;

    padding:28px;
    border-radius:25px;

    background:rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:blur(25px);
}

h1{
    margin-top:0;
}

.text{
    color:rgba(255,255,255,.55);
    line-height:2;
    font-size:13px;
}

.url{
    margin-top:20px;
    padding:14px;

    border-radius:13px;

    background:rgba(0,0,0,.22);

    color:#93c5fd;

    direction:ltr;
    word-break:break-all;

    font-family:Consolas,monospace;
}

.support{
    display:inline-block;
    margin-top:18px;

    color:#60a5fa;
    text-decoration:none;
}

.version{
    color:#60a5fa;
    font-size:11px;
}

</style>
</head>

<body>

<div class="card">

<h1>
PX Panel
</h1>

<div class="version">
13.7.1
</div>

<div class="text">
اشتراک شما آماده است.
</div>

<div
class="url"
id="subUrl"
></div>

<a
class="support"
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
>
پشتیبانی @Pixonal
</a>

</div>

<script>

const url =
    location.origin +
    location.pathname.replace(
        "/p/",
        "/sub-group/"
    );

document.getElementById(
    "subUrl"
).textContent = url;

</script>

</body>
</html>
"""


@app.get(
    "/p/{uuid_key}",
    response_class=HTMLResponse,
)
async def public_sub_page(
    uuid_key: str,
):

    async with SUBS_LOCK:

        exists = any(
            item.get(
                "uuid_key"
            ) == uuid_key
            for item in SUBS.values()
        )

    if not exists:

        return HTMLResponse(
            """
            <h2
            style="
            font-family:sans-serif;
            padding:40px;
            "
            >
            گروه پیدا نشد
            </h2>
            """,
            status_code=404,
        )

    return HTMLResponse(
        PUBLIC_SUB_HTML
    )


@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        entry = next(
            (
                (
                    sid,
                    item,
                )

                for sid, item
                in SUBS.items()

                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    _, sub = entry

    has_password = (
        sub.get(
            "password_hash"
        ) is not None
    )

    if has_password:

        password = (
            request
            .query_params
            .get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub[
                "password_hash"
            ]
        ):

            return JSONResponse(
                {
                    "locked": True,
                    "name":
                        sub["name"],
                }
            )

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    links_out = []

    active_connections = 0

    for link_id in sub.get(
        "link_ids",
        [],
    ):

        link = snapshot.get(
            link_id
        )

        if not link:
            continue

        allowed = is_link_allowed(
            link
        )

        connection_count = sum(
            1
            for item in connections.values()
            if item.get("uuid") == link_id
        )

        active_connections += (
            connection_count
        )

        links_out.append(
            {
                "uuid":
                    link_id,

                "label":
                    link.get(
                        "label"
                    ),

                "active":
                    allowed,

                "protocol":
                    link.get(
                        "protocol",
                        DEFAULT_PROTOCOL,
                    ),

                "used_bytes":
                    link.get(
                        "used_bytes",
                        0,
                    ),

                "used_fmt":
                    fmt_bytes(
                        link.get(
                            "used_bytes",
                            0,
                        )
                    ),

                "limit_bytes":
                    link.get(
                        "limit_bytes",
                        0,
                    ),

                "limit_fmt":
                    (
                        "∞"
                        if not link.get(
                            "limit_bytes",
                            0,
                        )
                        else fmt_bytes(
                            link[
                                "limit_bytes"
                            ]
                        )
                    ),

                "expires_at":
                    link.get(
                        "expires_at"
                    ),

                "vless_link":
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub/{link_id}"
                    ),

                "info_url":
                    (
                        f"https://{host}"
                        f"/info/{link_id}"
                    ),

                "connections":
                    connection_count,

                "ip_limit":
                    link.get(
                        "ip_limit",
                        0,
                    ),

                "speed_limit_bytes":
                    link.get(
                        "speed_limit_bytes",
                        0,
                    ),

                "connection_limit":
                    link.get(
                        "connection_limit",
                        0,
                    ),
            }
        )

    total_used = sum(
        item["used_bytes"]
        for item in links_out
    )

    return {
        "locked": False,

        "name":
            sub["name"],

        "desc":
            sub.get(
                "desc",
                "",
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{uuid_key}"
            ),

        "active_connections":
            active_connections,

        "total_used_fmt":
            fmt_bytes(
                total_used
            ),

        "support":
            SUPPORT_USERNAME,

        "links":
            links_out,
    }




@app.post("/api/mix-sub")
async def mix_subscription(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    ids = body.get("link_ids") or []
    if not isinstance(ids, list) or len(ids) < 2:
        raise HTTPException(status_code=400, detail="حداقل ۲ کانفیگ انتخاب کنید")
    if len(ids) > 40:
        raise HTTPException(status_code=400, detail="حداکثر ۴۰ کانفیگ")
    host = get_host(request)
    lines = []
    used_names = set()
    total_used = 0
    total_limit = 0
    labels = []
    async with LINKS_LOCK:
        for lid in ids:
            link = LINKS.get(lid)
            if not link or not is_link_allowed(link):
                continue
            labels.append(str(link.get("label") or lid[:8]))
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(
                lid, host, remark=name,
                protocol=link.get("protocol", DEFAULT_PROTOCOL),
                fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT),
                alpn=link.get("alpn"),
                port=link.get("port", DEFAULT_PORT),
            ))
    if not lines:
        raise HTTPException(status_code=400, detail="هیچ کانفیگ معتبری انتخاب نشده")
    # stats first line
    vol = f"{fmt_bytes(total_used)}/{fmt_bytes(total_limit)}" if total_limit > 0 else f"{fmt_bytes(total_used)}/∞"
    mix_label = "Mix-" + random_config_name()[:6]
    stats = f"{mix_label} | {vol} | {len(lines)} configs"
    first = generate_vless_link(ids[0], "127.0.0.1", remark=stats, protocol="vless-ws")
    content = base64.b64encode(("\n".join([first] + lines)).encode()).decode()
    # store as a sub group for reuse
    sub_id, sub = await create_sub_group(name=mix_label, desc="مخلوط‌سازی کانفیگ‌ها")
    async with SUBS_LOCK:
        if sub_id in SUBS:
            SUBS[sub_id]["link_ids"] = list(ids)
    await save_state()
    return {
        "ok": True,
        "sub_url": f"https://{host}/sub-group/{sub['uuid_key']}",
        "name": mix_label,
        "count": len(lines),
        "content_preview": stats,
    }


@app.get("/api/categories")
async def list_categories(_=Depends(require_auth)):
    items = [{**cat, "id": cid} for cid, cat in CATEGORIES.items()]
    items.sort(key=lambda x: int(x.get("number", 0)))
    return {"categories": items}

@app.post("/api/categories")
async def create_category(request: Request, _=Depends(require_auth)):
    if len(CATEGORIES) >= 10:
        raise HTTPException(status_code=400, detail="حداکثر ۱۰ دسته‌بندی")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    name = str(body.get("name") or "دسته جدید").strip()[:40]
    used = {int(x.get("number", 0)) for x in CATEGORIES.values()}
    num = 0
    while num in used:
        num += 1
    cid = str(num)
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    speed_value = safe_float(body.get("speed_limit_value", 0))
    speed_bytes = 0 if speed_value <= 0 else parse_speed_to_bytes(speed_value, "MBIT")
    raw_clean = body.get("clean_ips") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    record = {
        "id": cid, "name": name, "number": num,
        "limit_bytes": limit_bytes,
        "expires_days": safe_int(body.get("expires_days", 0), minimum=0),
        "connection_limit": safe_int(body.get("connection_limit", 0), minimum=0),
        "speed_limit_bytes": speed_bytes,
        "ip_limit": safe_int(body.get("ip_limit", 0), minimum=0),
        "clean_ips": clean_ips,
        "random_name": bool(body.get("random_name", False)),
        "single_user": bool(body.get("single_user", False)),
        "created_at": datetime.now().isoformat(),
    }
    CATEGORIES[cid] = record
    await save_state()
    return {"ok": True, **record}


@app.patch("/api/categories/{cid}")
async def update_category(cid: str, request: Request, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    cat = CATEGORIES[cid]
    if "name" in body:
        cat["name"] = str(body.get("name") or cat["name"]).strip()[:40]
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        unit = str(body.get("limit_unit") or "GB").upper()
        cat["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, unit)
    if "expires_days" in body:
        cat["expires_days"] = safe_int(body.get("expires_days", 0), minimum=0)
    if "connection_limit" in body:
        cat["connection_limit"] = safe_int(body.get("connection_limit", 0), minimum=0)
    if "speed_limit_value" in body:
        sv = safe_float(body.get("speed_limit_value", 0))
        cat["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, "MBIT")
    if "ip_limit" in body:
        cat["ip_limit"] = safe_int(body.get("ip_limit", 0), minimum=0)
    if "clean_ips" in body:
        raw = body.get("clean_ips") or ""
        if isinstance(raw, list):
            cat["clean_ips"] = [str(x).strip() for x in raw if str(x).strip()]
        else:
            cat["clean_ips"] = [x.strip() for x in str(raw).replace(",", "\n").splitlines() if x.strip()]
    if "random_name" in body:
        cat["random_name"] = bool(body.get("random_name"))
    if "single_user" in body:
        cat["single_user"] = bool(body.get("single_user"))
    await save_state()
    return {"ok": True, **cat}

@app.delete("/api/categories/{cid}")
async def delete_category(cid: str, _=Depends(require_auth)):
    if cid in ("0", "1"):
        raise HTTPException(status_code=400, detail="پیش‌فرض قابل حذف نیست")
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    del CATEGORIES[cid]
    for link in LINKS.values():
        if str(link.get("category_id")) == cid:
            link["category_id"] = "0"
    await save_state()
    return {"ok": True}

# ============================================================
# STATS
# ============================================================

@app.get("/stats")
async def get_stats(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    return {
        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "active_connections":
            len(connections),

        "total_traffic_mb":
            round(
                stats[
                    "total_bytes"
                ]
                / (
                    1024 ** 2
                ),
                2,
            ),

        "total_traffic_bytes":
            stats[
                "total_bytes"
            ],

        "total_requests":
            stats[
                "total_requests"
            ],

        "total_errors":
            stats[
                "total_errors"
            ],

        "uptime":
            uptime(),

        "timestamp":
            datetime.now().isoformat(),

        "hourly":
            dict(
                hourly_traffic
            ),

        "recent_errors":
            list(
                error_logs
            )[-10:],

        "links_count":
            len(snapshot),

        "active_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_allowed(
                    link
                )
            ),

        "expired_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_expired(
                    link
                )
            ),

        "subs_count":
            len(SUBS),
    }


@app.get("/api/activity")
async def get_activity(
    _=Depends(require_auth),
):

    return {
        "logs":
            list(
                activity_logs
            )[-150:]
    }


# ============================================================
# CONNECTIONS
# ============================================================

@app.get("/api/connections")
async def get_connections(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    grouped = {}

    for connection in connections.values():

        ip = connection.get(
            "ip",
            "نامشخص",
        )

        link = snapshot.get(
            connection.get(
                "uuid"
            )
        )

        label = (
            link.get(
                "label"
            )
            if link
            else "نامشخص"
        )

        group = grouped.get(ip)

        if group is None:

            group = {
                "ip":
                    ip,

                "sessions":
                    0,

                "bytes":
                    0,

                "labels":
                    set(),

                "transports":
                    set(),

                "first_connected_at":
                    connection.get(
                        "connected_at"
                    ),

                "last_connected_at":
                    connection.get(
                        "connected_at"
                    ),
            }

            grouped[ip] = group

        group["sessions"] += 1

        group["bytes"] += int(
            connection.get(
                "bytes",
                0,
            )
            or 0
        )

        group["labels"].add(
            label
        )

        group["transports"].add(
            connection.get(
                "transport",
                DEFAULT_PROTOCOL,
            )
        )

    result = []

    for group in grouped.values():

        result.append(
            {
                "ip":
                    group["ip"],

                "sessions":
                    group["sessions"],

                "labels":
                    sorted(
                        group["labels"]
                    ),

                "label":
                    (
                        " · ".join(
                            sorted(
                                group["labels"]
                            )
                        )
                        if group["labels"]
                        else "نامشخص"
                    ),

                "transports":
                    sorted(
                        group["transports"]
                    ),

                "bytes":
                    group["bytes"],

                "bytes_fmt":
                    fmt_bytes(
                        group["bytes"]
                    ),

                "connected_at":
                    group[
                        "first_connected_at"
                    ],

                "last_connected_at":
                    group[
                        "last_connected_at"
                    ],
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "last_connected_at"
            )
            or "",
        reverse=True,
    )

    return {
        "connections":
            result,

        "count":
            len(result),

        "raw_count":
            len(connections),
    }


# ============================================================
# OPTIONAL EXISTING PROJECT MODULES
# ============================================================

# ============================================================
# IMPORTANT:
# DO NOT REPLACE THIS VLESS CORE.
# ============================================================

try:

    from relay_vless import (
        RELAY_BUF,
        parse_vless_header,
        check_and_use,
        relay_ws_to_tcp,
        relay_tcp_to_ws,
        websocket_tunnel,
    )

    app.add_api_websocket_route(
        "/ws/{uuid}",
        websocket_tunnel,
    )

    logger.info(
        "VLESS relay loaded."
    )

except Exception as exc:

    logger.warning(
        "VLESS relay module unavailable: %s",
        exc,
    )


# ============================================================
# XHTTP
# ============================================================

try:

    from xhttp_siz10 import (
        router as xhttp_router
    )

    app.include_router(
        xhttp_router
    )

    logger.info(
        "XHTTP module loaded."
    )

except Exception as exc:

    logger.warning(
        "XHTTP module unavailable: %s",
        exc,
    )


# ============================================================
# TELEGRAM
# ============================================================

try:

    from telegram_bot import (
        start_bot as _tg_start_bot,
        stop_bot as _tg_stop_bot,
    )

except Exception:

    async def _tg_start_bot():
        return None

    async def _tg_stop_bot():
        return None


@app.on_event("startup")
async def start_optional_telegram():

    try:

        await _tg_start_bot()

        logger.info(
            "Telegram module initialized."
        )

    except Exception as exc:

        logger.warning(
            "Telegram bot disabled/error: %s",
            exc,
        )


# ============================================================
# HTTP PROXY
# ============================================================

_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


@app.api_route(
    "/proxy/{target_url:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    ],
)
async def http_proxy(
    target_url: str,
    request: Request,
):

    if not target_url.startswith("http"):
        target_url = (
            "https://"
            + target_url
        )

    if http_client is None:
        raise HTTPException(
            status_code=503,
            detail="HTTP client not ready",
        )

    try:

        body = await request.body()

        headers = {
            key: value
            for key, value
            in request.headers.items()
            if (
                key.lower()
                not in _HOP
            )
            and (
                key.lower()
                != "host"
            )
        }

        response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        stats["total_bytes"] += len(
            response.content
        )

        stats["total_requests"] += 1

        hourly_traffic[
            now_ir().strftime(
                "%H:00"
            )
        ] += len(
            response.content
        )

        output_headers = {
            key: value
            for key, value
            in response.headers.items()
            if key.lower() not in _HOP
        }

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=output_headers,
        )

    except Exception as exc:

        stats["total_errors"] += 1

        error_logs.append(
            {
                "error":
                    str(exc),

                "url":
                    target_url,

                "time":
                    datetime.now().isoformat(),
            }
        )

        logger.exception(
            "Proxy error: %s",
            target_url,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Proxy error: "
                f"{exc}"
            ),
        )


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl" id="htmlRoot">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no">
<title>PXPanel 13.7.1</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#06060b;--bg2:#0b0b12;--bg3:#12121c;--card:rgba(18,18,28,.92);--card-b:rgba(255,255,255,.08);
  --accent:#3b82f6;--accent2:#60a5fa;--purple:#8b5cf6;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;
  --t1:#f8fafc;--t2:rgba(248,250,252,.72);--t3:rgba(248,250,252,.42);
  --sb:252px;--sb-c:74px;--radius:18px;--shadow:0 12px 40px rgba(0,0,0,.45);
  --input-bg:rgba(0,0,0,.4);--hover:rgba(59,130,246,.12);
  --glow:0 0 40px rgba(59,130,246,.12);--glass:blur(16px);
}
html.light{
  --bg:#eef1f8;--bg2:#ffffff;--bg3:#f1f4fa;--card:#ffffff;--card-b:rgba(15,23,42,.09);
  --accent:#2563eb;--accent2:#3b82f6;--purple:#7c3aed;--green:#16a34a;--red:#dc2626;--amber:#d97706;
  --t1:#0f172a;--t2:#475569;--t3:#94a3b8;
  --shadow:0 10px 32px rgba(15,23,42,.08);
  --input-bg:#f8fafc;--hover:rgba(37,99,235,.08);
  --glow:0 0 32px rgba(37,99,235,.08);--glass:blur(12px);
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--t1);display:flex;min-height:100vh;overflow-x:hidden;transition:background .3s,color .3s}
body::before{content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%, rgba(59,130,246,.14), transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%, rgba(139,92,246,.10), transparent 45%);
}
html.light body::before{
  background:
    radial-gradient(ellipse 80% 50% at 100% 0%, rgba(37,99,235,.08), transparent 50%),
    radial-gradient(ellipse 60% 40% at 0% 100%, rgba(124,58,237,.06), transparent 45%);
}
.sidebar,.main,.mob-bar,.modal-bg,.toast{position:relative;z-index:1}
.sidebar{z-index:300}.mob-bar{z-index:250}.modal-bg{z-index:500}.toast{z-index:999}
body.en{font-family:'Inter',system-ui,sans-serif}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-thumb{background:var(--t3);border-radius:99px}

.sidebar{position:fixed;right:0;top:0;bottom:0;width:var(--sb);background:var(--bg2);border-left:1px solid var(--card-b);display:flex;flex-direction:column;z-index:300;transition:width .28s cubic-bezier(.4,0,.2,1),transform .28s,background .3s;box-shadow:var(--shadow);backdrop-filter:var(--glass)}
.sidebar.collapsed{width:var(--sb-c)}
.sb-toggle{position:absolute;left:-15px;top:50%;transform:translateY(-50%);width:30px;height:30px;border-radius:8px;background:var(--accent);border:2px solid var(--bg);color:#fff;display:flex;align-items:center;justify-content:center;cursor:pointer;z-index:310;box-shadow:0 4px 14px rgba(37,99,235,.4);transition:.2s}
.sb-toggle:hover{filter:brightness(1.1);transform:translateY(-50%) scale(1.05)}
.sb-toggle svg{width:14px;height:14px;transition:transform .28s}
.sidebar.collapsed .sb-toggle svg{transform:rotate(180deg)}
.sb-logo{display:flex;align-items:center;gap:12px;padding:20px 16px;border-bottom:1px solid var(--card-b)}
.sb-logo-icon{width:40px;height:40px;border-radius:12px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;color:#fff;flex-shrink:0;box-shadow:0 4px 14px rgba(59,130,246,.35)}
.sb-logo-text{overflow:hidden;white-space:nowrap}
.sb-logo-name{font-size:15px;font-weight:800;letter-spacing:-.02em}
.sb-logo-ver{font-size:10px;color:var(--t3);margin-top:2px}
.sidebar.collapsed .sb-logo-text,.sidebar.collapsed .nav-label,.sidebar.collapsed .nav-sec,.sidebar.collapsed .sb-foot span{opacity:0;width:0;overflow:hidden;pointer-events:none}
.nav{flex:1;overflow-y:auto;padding:10px 0}
.nav-sec{padding:14px 18px 6px;font-size:9px;letter-spacing:.14em;text-transform:uppercase;color:var(--t3);font-weight:700}
.nav-item{display:flex;align-items:center;gap:11px;padding:11px 16px;margin:2px 10px;border-radius:12px;color:var(--t3);cursor:pointer;transition:.15s;border:none;background:transparent;width:calc(100% - 20px);font-family:inherit;font-size:13px;font-weight:500}
.nav-item svg{width:18px;height:18px;flex-shrink:0}
.nav-item:hover{background:var(--hover);color:var(--t2)}
.nav-item.on{background:var(--hover);color:var(--accent2);font-weight:700;box-shadow:inset -3px 0 0 var(--accent)}
.sidebar.collapsed .nav-item{justify-content:center;padding:12px 0;margin:3px 12px}
.sidebar.collapsed .nav-item.on{box-shadow:none}
.sb-foot{padding:12px;border-top:1px solid var(--card-b);display:flex;flex-direction:column;gap:7px}
.sb-foot button,.sb-foot a.btn{display:flex;align-items:center;justify-content:center;gap:8px;padding:10px;border-radius:11px;border:1px solid var(--card-b);background:var(--bg3);color:var(--t2);cursor:pointer;font-family:inherit;font-size:12px;width:100%;text-decoration:none;font-weight:600;transition:.15s}
.sb-foot button:hover,.sb-foot a.btn:hover{background:var(--hover);color:var(--t1)}
.sb-foot a.danger{background:rgba(239,68,68,.08);border-color:rgba(239,68,68,.2);color:var(--red)}

.main{margin-right:var(--sb);flex:1;min-width:0;padding:28px 24px 60px;transition:margin .28s}
.main.expanded{margin-right:var(--sb-c)}
.page{display:none;animation:fadeIn .25s ease}
.page.on{display:block}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.page-head{display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:14px;margin-bottom:22px}
.page-title{font-size:20px;font-weight:800;display:flex;align-items:center;gap:10px;letter-spacing:-.02em}
.page-title svg{width:22px;height:22px;color:var(--accent2)}
.page-sub{font-size:12px;color:var(--t3);margin-top:5px}

.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:20px}
.metric{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);transition:.25s;backdrop-filter:var(--glass)}
.metric:hover{border-color:rgba(59,130,246,.25)}
.metric-label{font-size:11px;color:var(--t3);margin-bottom:8px;display:flex;align-items:center;gap:6px;font-weight:600}
.metric-val{font-size:24px;font-weight:800;letter-spacing:-.03em}
.card{background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);padding:20px;margin-bottom:14px;box-shadow:var(--shadow);backdrop-filter:var(--glass);transition:border-color .2s,box-shadow .2s}
.card-title{font-size:13px;font-weight:700;margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card-title svg{width:16px;height:16px;color:var(--accent2)}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:14px}
.action-card{cursor:pointer;transition:.2s;border:1px solid var(--card-b)}
.action-card:hover{border-color:rgba(59,130,246,.4);transform:translateY(-2px);box-shadow:0 12px 28px rgba(59,130,246,.12)}
.action-card.purple:hover{border-color:rgba(139,92,246,.45)}

.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 16px;border-radius:11px;border:1px solid var(--card-b);background:var(--bg3);color:var(--t2);cursor:pointer;font-family:inherit;font-size:12px;font-weight:600;transition:.15s}
.btn:hover{color:var(--t1);border-color:var(--accent)}
.btn-p{background:linear-gradient(135deg,#3b82f6,#6366f1);border:none;color:#fff;box-shadow:0 6px 20px rgba(59,130,246,.35)}
.btn-p:hover{filter:brightness(1.08);color:#fff}
.btn-d{background:rgba(239,68,68,.1);border-color:rgba(239,68,68,.25);color:var(--red)}
.btn-sm{padding:7px 11px;font-size:11px;border-radius:9px}
.btn svg{width:15px;height:15px}

.table-wrap{overflow-x:auto;border-radius:14px;border:1px solid var(--card-b)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
th{text-align:right;padding:12px 14px;background:var(--bg3);color:var(--t3);font-weight:700;white-space:nowrap}
td{padding:12px 14px;border-top:1px solid var(--card-b);vertical-align:middle}
tr:hover td{background:var(--hover)}
.ops{display:flex;gap:5px;flex-wrap:wrap;align-items:center}

.range-tabs{display:flex;gap:4px;background:var(--bg3);padding:4px;border-radius:12px;border:1px solid var(--card-b)}
.range-tab{padding:7px 13px;border-radius:9px;font-size:11px;font-weight:700;color:var(--t3);cursor:pointer;border:none;background:transparent;font-family:inherit;transition:.15s}
.range-tab.on{background:var(--accent);color:#fff;box-shadow:0 2px 8px rgba(37,99,235,.35)}

.field{margin-bottom:14px}
.field label{display:block;font-size:11px;color:var(--t3);margin-bottom:6px;font-weight:700}
.field input,.field select,.field textarea{width:100%;padding:11px 13px;border-radius:11px;border:1px solid var(--card-b);background:var(--input-bg);color:var(--t1);font-family:inherit;font-size:13px;outline:none;transition:.15s}
.field input:focus,.field select:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(59,130,246,.15)}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}

.support-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px}
.support-tile{display:flex;align-items:center;gap:14px;padding:20px;background:var(--card);border:1px solid var(--card-b);border-radius:var(--radius);text-decoration:none;color:inherit;transition:.2s;box-shadow:var(--shadow)}
.support-tile:hover{border-color:rgba(59,130,246,.35);transform:translateY(-3px)}
.support-icon{width:48px;height:48px;border-radius:14px;background:var(--hover);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.support-icon svg{width:22px;height:22px;color:var(--accent2)}
.support-label{font-size:11px;color:var(--t3);font-weight:600}
.support-val{font-size:13px;font-weight:700;margin-top:3px}

.log-item{padding:12px 0;border-bottom:1px solid var(--card-b);font-size:12px;display:flex;gap:12px;align-items:flex-start}
.log-time{color:var(--t3);font-size:10px;white-space:nowrap;min-width:72px;font-weight:600}
.log-msg{color:var(--t2);flex:1;line-height:1.5}

.modal-bg{position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(6px);z-index:500;display:none;align-items:center;justify-content:center;padding:16px}
.modal-bg.open{display:flex}
.modal{background:var(--bg2);border:1px solid var(--card-b);border-radius:20px;width:min(520px,100%);max-height:90vh;overflow-y:auto;padding:24px;box-shadow:0 24px 64px rgba(0,0,0,.4)}
.modal-title{font-size:17px;font-weight:800;margin-bottom:16px}
.modal-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:18px;flex-wrap:wrap}
.link-box{background:var(--input-bg);border:1px solid var(--card-b);border-radius:12px;padding:12px;font-size:11px;word-break:break-all;color:var(--t2);margin:8px 0 12px;font-family:ui-monospace,monospace;line-height:1.6;max-height:90px;overflow:auto}

.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(90px);background:var(--bg2);border:1px solid var(--card-b);color:var(--t1);padding:13px 22px;border-radius:14px;font-size:13px;font-weight:600;z-index:999;opacity:0;transition:.3s;pointer-events:none;box-shadow:var(--shadow)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}

.switch{position:relative;display:inline-block;width:44px;height:26px;vertical-align:middle}
.switch input{opacity:0;width:0;height:0}
.slider{position:absolute;cursor:pointer;inset:0;background:rgba(148,163,184,.35);border-radius:26px;transition:.2s}
.slider:before{position:absolute;content:"";height:20px;width:20px;left:3px;bottom:3px;background:#fff;border-radius:50%;transition:.2s;box-shadow:0 2px 6px rgba(0,0,0,.2)}
.switch input:checked+.slider{background:var(--green)}
.switch input:checked+.slider:before{transform:translateX(18px)}

.mob-bar{display:none;position:fixed;top:0;left:0;right:0;height:56px;background:var(--bg2);border-bottom:1px solid var(--card-b);z-index:250;align-items:center;justify-content:space-between;padding:0 16px;box-shadow:var(--shadow)}
.overlay{position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:290;display:none}
.overlay.show{display:block}

@media(max-width:900px){
  .sidebar{transform:translateX(100%)}
  .sidebar.open{transform:translateX(0)}
  .sb-toggle{display:none!important}
  .main,.main.expanded{margin-right:0;padding-top:72px}
  .mob-bar{display:flex}
  .metrics{grid-template-columns:1fr 1fr}
  .g2,.form-row{grid-template-columns:1fr}
}
@media(max-width:480px){.metrics{grid-template-columns:1fr}}
</style>
</head>
<body>

<div class="mob-bar">
  <div style="font-weight:800;font-size:15px">PXPanel</div>
  <button class="btn btn-sm" id="mobMenuBtn" aria-label="menu">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="20" height="20"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
  </button>
</div>
<div class="overlay" id="overlay"></div>

<aside class="sidebar" id="sidebar">
  <button class="sb-toggle" id="sbToggle" title="Toggle">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M15 18l-6-6 6-6"/></svg>
  </button>
  <div class="sb-logo">
    <div class="sb-logo-icon">PX</div>
    <div class="sb-logo-text">
      <div class="sb-logo-name">PXPanel</div>
      <div class="sb-logo-ver">v13.7.1</div>
    </div>
  </div>
  <nav class="nav">
    <div class="nav-sec" data-i18n="sec_panel">پنل</div>
    <button class="nav-item on" data-page="dash">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
      <span class="nav-label" data-i18n="nav_dash">داشبورد</span>
    </button>
    <button class="nav-item" data-page="configs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
      <span class="nav-label" data-i18n="nav_configs">کانفیگ‌ها</span>
    </button>
    <button class="nav-item" data-page="create">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg>
      <span class="nav-label" data-i18n="nav_create">ساخت کانفیگ</span>
    </button>
    <button class="nav-item" data-page="stats">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg>
      <span class="nav-label" data-i18n="nav_stats">آمار</span>
    </button>
    <button class="nav-item" data-page="logs">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>
      <span class="nav-label" data-i18n="nav_logs">لاگ فعالیت</span>
    </button>
    <div class="nav-sec" data-i18n="sec_sys">سیستم</div>
    <button class="nav-item" data-page="settings">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>
      <span class="nav-label" data-i18n="nav_settings">تنظیمات</span>
    </button>
    <button class="nav-item" data-page="support">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/><path d="M21 19a2 2 0 0 1-2 2h-1a2 2 0 0 1-2-2v-3a2 2 0 0 1 2-2h3zM3 19a2 2 0 0 0 2 2h1a2 2 0 0 0 2-2v-3a2 2 0 0 0-2-2H3z"/></svg>
      <span class="nav-label" data-i18n="nav_support">پشتیبانی</span>
    </button>
  </nav>
  <div class="sb-foot">
    <button type="button" id="themeBtn" onclick="toggleTheme()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>
      <span id="themeLabel" data-i18n="theme">تم روشن</span>
    </button>
    <button type="button" onclick="refreshAll()">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10M1 14l5.4 4.4A9 9 0 0 0 20.5 15"/></svg>
      <span data-i18n="refresh">بروزرسانی</span>
    </button>
    <a href="/logout" class="btn danger">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" width="16" height="16"><path d="M10 5H5v14h5"/><path d="m14 8 4 4-4 4"/><path d="M18 12H9"/></svg>
      <span data-i18n="logout">خروج</span>
    </a>
  </div>
</aside>

<main class="main" id="main">

<section class="page on" id="page-dash">
  <div class="page-head">
    <div>
      <div class="page-title">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>
        <span data-i18n="nav_dash">داشبورد</span>
      </div>
      <div class="page-sub" id="lastUpd" data-i18n="loading">در حال بارگذاری...</div>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="metric-label" data-i18n="m_conns">اتصالات فعال</div><div class="metric-val" id="mConns">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_traffic">ترافیک کل</div><div class="metric-val" id="mTraffic">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_links">کانفیگ‌ها</div><div class="metric-val" id="mLinks">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_uptime">آپتایم سرور</div><div class="metric-val" id="mUptime" style="font-size:17px">—</div></div>
  </div>
  <div class="g2">
    <div class="card action-card" onclick="goPage('create')">
      <div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg><span data-i18n="quick_create">ساخت کانفیگ</span></div>
      <p style="color:var(--t2);font-size:12px;line-height:1.6" data-i18n="quick_create_desc">ساخت دستی با محدودیت ترافیک، سرعت، تعداد و انقضا</p>
    </div>
    <div class="card action-card purple" onclick="doAutoCreate()">
      <div class="card-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2"/></svg><span data-i18n="auto_create">ساخت خودکار (پیشنهادی)</span></div>
      <p style="color:var(--t2);font-size:12px;line-height:1.6" data-i18n="auto_create_desc">ساخت سریع با تنظیمات بهینه · لینک VLESS و ساب</p>
    </div>
  </div>
</section>

<section class="page" id="page-configs">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg><span data-i18n="nav_configs">کانفیگ‌ها</span></div>
      <div class="page-sub" data-i18n="configs_sub">مدیریت لینک‌ها · VLESS و ساب</div>
    </div>
    <div style="display:flex;gap:8px">
      <button class="btn btn-p btn-sm" onclick="goPage('create')"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M12 5v14M5 12h14"/></svg></button>
      <button class="btn btn-sm" onclick="refreshAll()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg></button>
    </div>
  </div>
  <div class="card" style="padding:0">
    <div class="table-wrap">
      <table>
        <thead><tr>
          <th data-i18n="th_name">نام</th><th data-i18n="th_proto">پروتکل</th><th data-i18n="th_status">وضعیت</th>
          <th data-i18n="th_usage">مصرف</th><th data-i18n="th_ops">عملیات</th>
        </tr></thead>
        <tbody id="linksTable"><tr><td colspan="5" style="text-align:center;color:var(--t3);padding:32px">...</td></tr></tbody>
      </table>
    </div>
  </div>
</section>

<section class="page" id="page-create">
  <div class="page-head">
    <div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 5v14M5 12h14"/></svg><span data-i18n="nav_create">ساخت کانفیگ</span></div></div>
  </div>
  <div class="g2">
    <div class="card">
      <div class="card-title" data-i18n="manual_create">ساخت دستی</div>
      <div class="field"><label data-i18n="label_name">نام</label><input id="cName" placeholder="auto"></div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_count">تعداد کانفیگ در ساب (۱–۴۰)</label><input id="cCount" type="number" value="1" min="1" max="40"></div>
        <div class="field"><label data-i18n="label_days">انقضا (روز)</label><input id="cDays" type="number" value="0" min="0"></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_limit">محدودیت حجم</label><input id="cLimit" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_unit">واحد</label><select id="cUnit"><option>GB</option><option>MB</option><option>KB</option></select></div>
      </div>
      <div class="form-row">
        <div class="field"><label data-i18n="label_ip">محدودیت IP</label><input id="cIp" type="number" value="0" min="0"></div>
        <div class="field"><label data-i18n="label_speed">سرعت (Mbps)</label><input id="cSpeed" type="number" value="0" min="0"></div>
      </div>
      <button class="btn btn-p" style="width:100%" onclick="doManualCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><path d="M12 5v14M5 12h14"/></svg>
        <span data-i18n="btn_create">ساخت</span>
      </button>
    </div>
    <div class="card" style="border-color:rgba(139,92,246,.35)">
      <div class="card-title" data-i18n="auto_create">ساخت خودکار (پیشنهادی)</div>
      <p style="color:var(--t2);font-size:13px;line-height:1.75;margin-bottom:14px" data-i18n="auto_desc">با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.</p>
      <div class="field"><label data-i18n="label_count">تعداد کانفیگ در ساب (۱–۴۰)</label><input id="aCount" type="number" value="1" min="1" max="40"></div>
      <button class="btn btn-p" style="width:100%;background:linear-gradient(135deg,#8b5cf6,#6366f1)" onclick="doAutoCreate()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="16" height="16"><circle cx="12" cy="12" r="3"/><path d="M12 2v2M12 20v2"/></svg>
        <span data-i18n="btn_auto">ساخت خودکار</span>
      </button>
    </div>
  </div>
</section>

<section class="page" id="page-stats">
  <div class="page-head">
    <div>
      <div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 3v18h18"/><path d="M7 16l4-8 4 4 5-6"/></svg><span data-i18n="nav_stats">آمار</span></div>
      <div class="page-sub" data-i18n="stats_sub">ترافیک و اتصالات · فیلتر زمانی</div>
    </div>
    <div class="range-tabs" id="rangeTabs">
      <button class="range-tab" data-r="day" onclick="setRange('day',this)" data-i18n="r_day">روز</button>
      <button class="range-tab" data-r="week" onclick="setRange('week',this)" data-i18n="r_week">هفته</button>
      <button class="range-tab on" data-r="month" onclick="setRange('month',this)" data-i18n="r_month">ماه</button>
      <button class="range-tab" data-r="all" onclick="setRange('all',this)" data-i18n="r_all">کل</button>
    </div>
  </div>
  <div class="metrics">
    <div class="metric"><div class="metric-label" data-i18n="m_traffic">ترافیک</div><div class="metric-val" id="sTraffic">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_conns">اتصالات</div><div class="metric-val" id="sConns">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_links">کانفیگ فعال</div><div class="metric-val" id="sActive">—</div></div>
    <div class="metric"><div class="metric-label" data-i18n="m_uptime">آپتایم</div><div class="metric-val" id="sUptime" style="font-size:16px">—</div></div>
  </div>
  <div class="card"><div class="card-title" data-i18n="panel_info">اطلاعات کل پنل</div><div id="panelInfo" style="font-size:13px;color:var(--t2);line-height:2"></div></div>
</section>

<section class="page" id="page-logs">
  <div class="page-head">
    <div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/></svg><span data-i18n="nav_logs">لاگ فعالیت</span></div></div>
    <button class="btn btn-sm" onclick="loadLogs()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" width="14" height="14"><path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.1-3.4L23 10"/></svg></button>
  </div>
  <div class="card" id="logsBox"><div style="text-align:center;color:var(--t3);padding:28px">...</div></div>
</section>

<section class="page" id="page-settings">
  <div class="page-head"><div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3"/></svg><span data-i18n="nav_settings">تنظیمات</span></div></div></div>
  <div class="card">
    <div class="card-title" data-i18n="theme">تم</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-p" onclick="setTheme('dark')" data-i18n="theme_dark">تم تیره</button>
      <button class="btn" onclick="setTheme('light')" data-i18n="theme_light">تم روشن</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="lang_label">زبان / Language</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-p" onclick="setLang('fa')">فارسی کامل</button>
      <button class="btn" onclick="setLang('en')">Full English</button>
    </div>
  </div>
  <div class="card">
    <div class="card-title" data-i18n="change_pw">تغییر رمز عبور</div>
    <div class="field"><label data-i18n="pw_cur">رمز فعلی</label><input type="password" id="pwCur"></div>
    <div class="field"><label data-i18n="pw_new">رمز جدید</label><input type="password" id="pwNew"></div>
    <div class="field"><label data-i18n="pw_cf">تکرار رمز</label><input type="password" id="pwCf"></div>
    <button class="btn btn-p" onclick="doChangePw()"><span data-i18n="btn_save">ذخیره</span></button>
  </div>
</section>

<section class="page" id="page-support">
  <div class="page-head"><div><div class="page-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M3 18v-6a9 9 0 0 1 18 0v6"/></svg><span data-i18n="nav_support">پشتیبانی</span></div></div></div>
  <div class="support-grid">
    <a class="support-tile" href="https://github.com/iran-px-panel/pxpanel" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.3 3.44 9.8 8.2 11.4.6.1.82-.26.82-.58v-2.03c-3.34.73-4.03-1.61-4.03-1.61-.55-1.39-1.34-1.76-1.34-1.76-1.1-.75.08-.74.08-.74 1.21.09 1.85 1.24 1.85 1.24 1.07 1.84 2.81 1.31 3.5 1 .11-.78.42-1.31.76-1.61-2.66-.3-5.46-1.33-5.46-5.93 0-1.31.47-2.38 1.24-3.22-.12-.3-.54-1.52.12-3.18 0 0 1.01-.32 3.3 1.23a11.5 11.5 0 0 1 6 0c2.29-1.55 3.3-1.23 3.3-1.23.66 1.66.24 2.88.12 3.18.77.84 1.24 1.91 1.24 3.22 0 4.61-2.8 5.62-5.48 5.92.43.37.81 1.1.81 2.22v3.29c0 .32.22.69.83.57C20.56 21.8 24 17.3 24 12 24 5.37 18.63 0 12 0z"/></svg></div>
      <div><div class="support-label" data-i18n="github">گیت‌هاب</div><div class="support-val">iran-px-panel/pxpanel</div></div>
    </a>
    <a class="support-tile" href="https://t.me/logic_sec" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12s5.37 12 12 12 12-5.37 12-12S18.63 0 12 0zm5.56 8.2-1.86 8.77c-.14.62-.5.77-1.01.48l-2.8-2.06-1.35 1.3c-.15.15-.27.27-.55.27l.2-2.84 5.18-4.68c.22-.2-.05-.31-.35-.12l-6.4 4.03-2.76-.86c-.6-.19-.61-.6.12-.89l10.78-4.16c.5-.18.94.12.78.86z"/></svg></div>
      <div><div class="support-label" data-i18n="telegram">تلگرام</div><div class="support-val">@logic_sec</div></div>
    </a>
    <a class="support-tile" href="https://t.me/logictop12" target="_blank" rel="noopener">
      <div class="support-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/></svg></div>
      <div><div class="support-label" data-i18n="channel">کانال پشتیبان</div><div class="support-val">t.me/logictop12</div></div>
    </a>
  </div>
</section>
</main>

<!-- Result modal after create -->
<div class="modal-bg" id="resultModal">
  <div class="modal">
    <div class="modal-title" data-i18n="created_title">کانفیگ ساخته شد</div>
    <div class="field"><label>VLESS</label><div class="link-box" id="resVless">—</div>
      <button class="btn btn-p btn-sm" style="width:100%" onclick="copyText(document.getElementById('resVless').textContent)">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        <span data-i18n="copy_vless">کپی VLESS</span>
      </button>
    </div>
    <div class="field" style="margin-top:14px"><label data-i18n="sub_label">سابسکریپشن</label><div class="link-box" id="resSub">—</div>
      <button class="btn btn-sm" style="width:100%" onclick="copyText(document.getElementById('resSub').textContent)">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg>
        <span data-i18n="copy_sub">کپی ساب</span>
      </button>
    </div>
    <div class="modal-actions">
      <button class="btn" onclick="closeResult()">OK</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const I18N={
fa:{sec_panel:'پنل',sec_sys:'سیستم',nav_dash:'داشبورد',nav_configs:'کانفیگ‌ها',nav_create:'ساخت کانفیگ',nav_stats:'آمار',nav_logs:'لاگ فعالیت',nav_settings:'تنظیمات',nav_support:'پشتیبانی',refresh:'بروزرسانی',logout:'خروج',loading:'در حال بارگذاری...',m_conns:'اتصالات فعال',m_traffic:'ترافیک کل',m_links:'کانفیگ‌ها',m_uptime:'آپتایم سرور',quick_create:'ساخت کانفیگ',quick_create_desc:'ساخت دستی با محدودیت ترافیک، سرعت، تعداد و انقضا',auto_create:'ساخت خودکار (پیشنهادی)',auto_create_desc:'ساخت سریع با تنظیمات بهینه · لینک VLESS و ساب',configs_sub:'مدیریت لینک‌ها · VLESS و ساب',th_name:'نام',th_proto:'پروتکل',th_status:'وضعیت',th_usage:'مصرف',th_ops:'عملیات',manual_create:'ساخت دستی',label_name:'نام',label_count:'تعداد کانفیگ در ساب (۱–۴۰)',label_limit:'محدودیت حجم',label_unit:'واحد',label_days:'انقضا (روز)',label_ip:'محدودیت IP',label_speed:'سرعت (Mbps)',btn_create:'ساخت',btn_auto:'ساخت خودکار',auto_desc:'با یک کلیک کانفیگ بهینه ساخته می‌شود. بعد از ساخت لینک VLESS و ساب در اختیار شماست.',stats_sub:'ترافیک و اتصالات · فیلتر زمانی',r_day:'روز',r_week:'هفته',r_month:'ماه',r_all:'کل',panel_info:'اطلاعات کل پنل',lang_label:'زبان',change_pw:'تغییر رمز عبور',pw_cur:'رمز فعلی',pw_new:'رمز جدید',pw_cf:'تکرار رمز',btn_save:'ذخیره',github:'گیت‌هاب',telegram:'تلگرام',channel:'کانال پشتیبان',theme:'تم',theme_dark:'تم تیره',theme_light:'تم روشن',created_title:'کانفیگ ساخته شد',copy_vless:'کپی VLESS',copy_sub:'کپی ساب',sub_label:'سابسکریپشن'},
en:{sec_panel:'PANEL',sec_sys:'SYSTEM',nav_dash:'Dashboard',nav_configs:'Configs',nav_create:'Create Config',nav_stats:'Statistics',nav_logs:'Activity Log',nav_settings:'Settings',nav_support:'Support',refresh:'Refresh',logout:'Logout',loading:'Loading...',m_conns:'Active connections',m_traffic:'Total traffic',m_links:'Configs',m_uptime:'Server uptime',quick_create:'Create Config',quick_create_desc:'Manual create with traffic, speed, count and expiry',auto_create:'Auto Create (Suggested)',auto_create_desc:'Quick optimal create · VLESS and Sub links',configs_sub:'Manage links · VLESS and Sub',th_name:'Name',th_proto:'Protocol',th_status:'Status',th_usage:'Usage',th_ops:'Actions',manual_create:'Manual create',label_name:'Name',label_count:'Configs in sub (1–40)',label_limit:'Traffic limit',label_unit:'Unit',label_days:'Expiry (days)',label_ip:'IP limit',label_speed:'Speed (Mbps)',btn_create:'Create',btn_auto:'Auto create',auto_desc:'One click creates an optimal config. VLESS and Sub links will be shown.',stats_sub:'Traffic and connections · time filter',r_day:'Day',r_week:'Week',r_month:'Month',r_all:'All',panel_info:'Panel overview',lang_label:'Language',change_pw:'Change password',pw_cur:'Current password',pw_new:'New password',pw_cf:'Confirm password',btn_save:'Save',github:'GitHub',telegram:'Telegram',channel:'Support channel',theme:'Theme',theme_dark:'Dark theme',theme_light:'Light theme',created_title:'Config created',copy_vless:'Copy VLESS',copy_sub:'Copy Sub',sub_label:'Subscription'}
};
let lang=localStorage.getItem('px_lang')||'fa';
let statRange='month';
function t(k){return (I18N[lang]||I18N.fa)[k]||k}
function applyLang(){
  document.getElementById('htmlRoot').lang=lang;
  document.getElementById('htmlRoot').dir=lang==='fa'?'rtl':'ltr';
  document.body.classList.toggle('en',lang==='en');
  document.querySelectorAll('[data-i18n]').forEach(el=>{const k=el.getAttribute('data-i18n');if(I18N[lang][k])el.textContent=I18N[lang][k]});
  const tl=document.getElementById('themeLabel');
  if(tl) tl.textContent=document.documentElement.classList.contains('light')?t('theme_dark'):t('theme_light');
}
function setLang(l){lang=l;localStorage.setItem('px_lang',l);applyLang();toast(l==='fa'?'زبان فارسی':'English')}

function setTheme(mode){
  if(mode==='light') document.documentElement.classList.add('light');
  else document.documentElement.classList.remove('light');
  localStorage.setItem('px_theme',mode);
  applyLang();
}
function toggleTheme(){
  const isLight=document.documentElement.classList.contains('light');
  setTheme(isLight?'dark':'light');
}
(function(){const th=localStorage.getItem('px_theme')||'dark';setTheme(th)})();

const sb=document.getElementById('sidebar'),main=document.getElementById('main');
document.getElementById('sbToggle').onclick=()=>{
  sb.classList.toggle('collapsed');
  main.classList.toggle('expanded',sb.classList.contains('collapsed'));
  localStorage.setItem('sb_c',sb.classList.contains('collapsed')?'1':'0');
};
if(localStorage.getItem('sb_c')==='1'){sb.classList.add('collapsed');main.classList.add('expanded')}
document.getElementById('mobMenuBtn').onclick=()=>{sb.classList.add('open');document.getElementById('overlay').classList.add('show')};
document.getElementById('overlay').onclick=()=>{sb.classList.remove('open');document.getElementById('overlay').classList.remove('show')};

function goPage(name){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('on',n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('on',p.id==='page-'+name));
  sb.classList.remove('open');document.getElementById('overlay').classList.remove('show');
  window.scrollTo({top:0,behavior:'smooth'});
  if(name==='logs')loadLogs();
  if(name==='configs'||name==='dash'||name==='stats')refreshAll();
}
document.querySelectorAll('.nav-item').forEach(el=>el.addEventListener('click',()=>goPage(el.dataset.page)));

function toast(msg){
  const el=document.getElementById('toast');
  el.textContent=msg;el.classList.add('show');
  clearTimeout(window.__tt);window.__tt=setTimeout(()=>el.classList.remove('show'),2200);
}
async function api(url,opts={}){
  try{
    const r=await fetch(url,{cache:'no-store',credentials:'same-origin',...opts});
    if(r.status===401){location.href='/login';return null}
    let data=null;try{data=await r.json()}catch{data={ok:false}}
    if(!r.ok){toast(data.detail||data.error||'Error');return null}
    return data;
  }catch(e){toast(lang==='fa'?'ارتباط برقرار نشد':'Connection failed');return null}
}
function fmtB(b){b=Number(b)||0;if(b<1024)return b+' B';if(b<1024**2)return (b/1024).toFixed(1)+' KB';if(b<1024**3)return (b/1024**2).toFixed(2)+' MB';return (b/1024**3).toFixed(2)+' GB'}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}

async function refreshAll(){
  const links=await api('/api/links');
  if(!links)return;
  const arr=Array.isArray(links.links)?links.links:(Array.isArray(links)?links:[]);
  document.getElementById('mLinks').textContent=arr.length;
  let active=0,used=0;
  arr.forEach(l=>{if(l.active!==false)active++;used+=Number(l.used_bytes||0)});
  document.getElementById('mTraffic').textContent=fmtB(used);
  document.getElementById('sTraffic').textContent=fmtB(used);
  document.getElementById('sActive').textContent=active;
  document.getElementById('lastUpd').textContent=(lang==='fa'?'بروزرسانی: ':'Updated: ')+new Date().toLocaleTimeString(lang==='fa'?'fa-IR':'en-US');
  try{
    const c=await api('/api/connections');
    const cnt=(c&&c.connections)?c.connections.length:((c&&typeof c.count==='number')?c.count:0);
    document.getElementById('mConns').textContent=cnt;
    document.getElementById('sConns').textContent=cnt;
  }catch(e){}
  try{
    const h=await fetch('/health',{cache:'no-store'}).then(r=>r.json());
    if(h&&h.uptime){
      document.getElementById('mUptime').textContent=h.uptime;
      const su=document.getElementById('sUptime');if(su)su.textContent=h.uptime;
    }
  }catch(e){}
  renderLinks(arr);
  document.getElementById('panelInfo').innerHTML=lang==='fa'
    ?`کل کانفیگ: <b>${arr.length}</b> · فعال: <b>${active}</b> · مصرف: <b>${fmtB(used)}</b> · بازه: <b>${statRange}</b>`
    :`Total: <b>${arr.length}</b> · Active: <b>${active}</b> · Usage: <b>${fmtB(used)}</b> · Range: <b>${statRange}</b>`;
}

function renderLinks(arr){
  const tb=document.getElementById('linksTable');
  if(!arr.length){tb.innerHTML=`<tr><td colspan="5" style="text-align:center;color:var(--t3);padding:28px">${lang==='fa'?'کانفیگی نیست':'No configs'}</td></tr>`;return}
  window.__linksMap={};
  tb.innerHTML=arr.map(l=>{
    const uid=l.uuid||l.id||'';
    window.__linksMap[uid]=l;
    const name=l.label||l.name||String(uid).slice(0,8);
    const proto=l.protocol||'vless-ws';
    const on=l.active!==false&&!l.expired;
    return `<tr>
      <td><b>${esc(name)}</b></td>
      <td style="color:var(--t3);font-size:11px">${esc(proto)}</td>
      <td><label class="switch"><input type="checkbox" ${on?'checked':''} onchange="toggleLink('${esc(uid)}',this.checked)"><span class="slider"></span></label></td>
      <td>${fmtB(l.used_bytes)}${l.limit_bytes?(' / '+fmtB(l.limit_bytes)):''}</td>
      <td class="ops">
        <button class="btn btn-sm" onclick="copyLinkById('${esc(uid)}')" title="VLESS"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
        <button class="btn btn-sm" onclick="copySubById('${esc(uid)}')" title="Sub"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 11a9 9 0 0 1 9 9M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1"/></svg></button>
        <button class="btn btn-sm" onclick="showResult(window.__linksMap['${esc(uid)}'])" title="Info"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4M12 8h.01"/></svg></button>
        <button class="btn btn-sm btn-d" onclick="deleteLink('${esc(uid)}')"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6"/></svg></button>
      </td>
    </tr>`;
  }).join('');
}
function getLinkUrl(l){if(!l)return '';return l.vless_full||l.vless||l.vless_link||l.link||''}
function getSubUrl(l){if(!l)return '';return l.sub||l.sub_url||l.info||''}
async function copyText(text){
  text=String(text||'').trim();
  if(!text||text==='—'){toast(lang==='fa'?'لینکی نیست':'Nothing to copy');return}
  try{
    if(navigator.clipboard&&window.isSecureContext) await navigator.clipboard.writeText(text);
    else{const ta=document.createElement('textarea');ta.value=text;ta.style.cssText='position:fixed;left:-9999px';document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta)}
    toast(lang==='fa'?'کپی شد':'Copied');
  }catch(e){toast(lang==='fa'?'کپی نشد':'Copy failed')}
}
async function copyLinkById(uid){await copyText(getLinkUrl((window.__linksMap||{})[uid]))}
async function copySubById(uid){await copyText(getSubUrl((window.__linksMap||{})[uid]))}
async function toggleLink(uid,state){
  const r=await api('/api/links/'+uid,{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({active:!!state})});
  if(r!==null) toast(state?(lang==='fa'?'فعال شد':'Enabled'):(lang==='fa'?'غیرفعال شد':'Disabled'));
  refreshAll();
}
async function deleteLink(uid){
  if(!confirm(lang==='fa'?'حذف شود؟':'Delete?'))return;
  const r=await api('/api/links/'+uid,{method:'DELETE'});
  if(r!==null){toast(lang==='fa'?'حذف شد':'Deleted');refreshAll()}
}
function showResult(data){
  if(!data)return;
  document.getElementById('resVless').textContent=getLinkUrl(data)||'—';
  document.getElementById('resSub').textContent=getSubUrl(data)||'—';
  document.getElementById('resultModal').classList.add('open');
}
function closeResult(){document.getElementById('resultModal').classList.remove('open')}
document.getElementById('resultModal').addEventListener('click',e=>{if(e.target.id==='resultModal')closeResult()});

async function doAutoCreate(){
  toast(lang==='fa'?'در حال ساخت...':'Creating...');
  const count=Math.max(1,Math.min(40,Number(document.getElementById('aCount')?.value)||1));
  let r=await api('/api/links/auto',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({config_count:count})});
  if(!r){
    r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({label:'auto-'+Date.now().toString(36).slice(-5),limit_value:0,limit_unit:'GB',config_count:count})});
  }
  if(r){showResult(r);refreshAll()}
}
async function doManualCreate(){
  const body={
    label:document.getElementById('cName').value||undefined,
    config_count:Math.max(1,Math.min(40,Number(document.getElementById('cCount').value)||1)),
    limit_value:Number(document.getElementById('cLimit').value)||0,
    limit_unit:document.getElementById('cUnit').value||'GB',
    expires_days:Number(document.getElementById('cDays').value)||0,
    ip_limit:Number(document.getElementById('cIp').value)||0,
    speed_limit_value:Number(document.getElementById('cSpeed').value)||0,
    speed_limit_unit:'MBIT'
  };
  const r=await api('/api/links',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(r){showResult(r);refreshAll()}
}
async function doChangePw(){
  const cur=document.getElementById('pwCur').value,nw=document.getElementById('pwNew').value,cf=document.getElementById('pwCf').value;
  if(nw!==cf){toast(lang==='fa'?'رمزها یکی نیستند':'Passwords mismatch');return}
  const r=await api('/api/change-password',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:cur,new_password:nw,repeat_password:cf})});
  if(r){toast(lang==='fa'?'رمز تغییر کرد':'Password changed');document.getElementById('pwCur').value='';document.getElementById('pwNew').value='';document.getElementById('pwCf').value=''}
}
async function loadLogs(){
  const box=document.getElementById('logsBox');
  const data=await api('/api/activity');
  const logs=Array.isArray(data)?data:(data&&data.logs)||[];
  if(!logs.length){box.innerHTML=`<div style="text-align:center;color:var(--t3);padding:24px">${lang==='fa'?'لاگی نیست':'No logs'}</div>`;return}
  box.innerHTML=logs.slice().reverse().map(l=>{
    const tm=(l.time||l.ts||'').toString().slice(11,19)||'—';
    return `<div class="log-item"><div class="log-time">${esc(tm)}</div><div class="log-msg">${esc(l.message||l.msg||JSON.stringify(l))}</div></div>`;
  }).join('');
}
function setRange(r,el){
  statRange=r;
  document.querySelectorAll('#rangeTabs .range-tab').forEach(t=>t.classList.toggle('on',t.dataset.r===r));
  refreshAll();toast(t('r_'+r));
}
applyLang();refreshAll();setInterval(refreshAll,15000);
</script>
</body>
</html>
"""




@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
async def dashboard(
    request: Request,
):

    if not await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/login"
        )

    await ensure_default_categories()
    await ensure_default_link()

    return HTMLResponse(
        DASHBOARD_HTML
    )


# ============================================================
# TEST
# ============================================================

@app.get(
    "/test-ws",
    response_class=HTMLResponse,
)
async def test_ws():

    return HTMLResponse(
        """
        <script>
        location.href='/dashboard'
        </script>
        """
    )


# ============================================================
# GLOBAL ERROR HANDLER
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    stats[
        "total_errors"
    ] += 1

    error_logs.append(
        {
            "error":
                str(exc),

            "path":
                str(request.url),

            "method":
                request.method,

            "time":
                datetime.now().isoformat(),
        }
    )

    logger.exception(
        "Unhandled exception: %s %s",
        request.method,
        request.url,
    )

    # API requests
    if (
        request.url.path.startswith(
            "/api/"
        )
        or request.url.path == "/stats"
    ):

        return JSONResponse(
            {
                "ok": False,
                "error":
                    str(exc)
                or "internal server error",
            },
            status_code=500,
        )

    return HTMLResponse(
        """
        <html lang="fa" dir="rtl">
        <body style="
            background:#07070a;
            color:#fff;
            font-family:sans-serif;
            padding:40px;
        ">
            <h2>
            خطای داخلی PX Panel
            </h2>

            <p>
            لطفاً لاگ Railway را بررسی کنید.
            </p>
        </body>
        </html>
        """,
        status_code=500,
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        workers=1,
    )

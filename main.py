# ============================================================
# PixonPanel 12.0.1 Beta
# Railway Ready
# ============================================================

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
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
    WebSocket,
    WebSocketDisconnect,
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

APP_NAME = "PixonPanel"
APP_VERSION = "12.0.1 Beta"

SUPPORT_USERNAME = "@Pixonal"
SUPPORT_URL = "https://t.me/Pixonal"

NEWS_URL = (
    "https://raw.githubusercontent.com/"
    "pxir029/fuckyoo/refs/heads/main/news.json"
)

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
NEWS_LOCK = asyncio.Lock()


# ============================================================
# SECRET
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get(
        "SECRET_KEY"
    )

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

        generated = secrets.token_urlsafe(
            48
        )

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

        return secrets.token_urlsafe(
            48
        )


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
# NEWS CACHE
# ============================================================

NEWS_CACHE = {
    "data": None,
    "expires_at": 0,
}


# ============================================================
# PROTOCOL
# ============================================================

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
)

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

    if (
        maximum is not None
        and number > maximum
    ):
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


def auto_config_name():
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
    )

    suffix = "".join(
        secrets.choice(alphabet)
        for _ in range(8)
    )

    return f"pxpanel_{suffix}"


def now_ir():
    if IRAN_TZ:
        return datetime.now(
            IRAN_TZ
        )

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
            value * 1024 ** 4
        )

    if unit == "GB":
        return int(
            value * 1024 ** 3
        )

    if unit == "MB":
        return int(
            value * 1024 ** 2
        )

    if unit == "KB":
        return int(
            value * 1024
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


def is_link_expired(link: dict):
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

    if is_link_expired(
        link
    ):
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
        connection.get(
            "ip"
        )
        for connection
        in connections.values()
        if (
            connection.get("uuid")
            == uuid
        )
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

    ips = unique_ips_for_uuid(
        uuid
    )

    if ip in ips:
        return True

    return len(ips) < limit


def get_host(
    request: Request | None = None,
):
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

            host = (
                host
                .split(":")[0]
                .strip()
            )

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
):
    payload = (
        password
        + SECRET_KEY
    ).encode(
        "utf-8"
    )

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
# SESSION
# ============================================================

SESSION_COOKIE = (
    "pixonpanel_session"
)

SESSION_TTL = (
    60
    * 60
    * 24
    * 365
)


async def create_session():
    token = secrets.token_urlsafe(
        48
    )

    async with SESSIONS_LOCK:
        SESSIONS[
            token
        ] = (
            time.time()
            + SESSION_TTL
        )

    return token


async def is_valid_session(
    token: str | None,
):
    if not token:
        return False

    async with SESSIONS_LOCK:

        expiry = SESSIONS.get(
            token
        )

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

    secure = (
        forwarded_proto == "https"
        or request.url.scheme == "https"
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


# ============================================================
# VLESS GENERATOR
# SAME WORKING CORE
# ============================================================

def generate_vless_link(
    uuid: str,
    host: str,
    remark: str = "PixonPanel",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
):

    fp = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT

    alpn_value = (
        (
            alpn
            or ""
        ).strip()
        or DEFAULT_ALPN_BY_PROTOCOL.get(
            protocol,
            "http/1.1",
        )
    )

    port_value = (
        port
        or DEFAULT_PORT
    )

    if not (
        MIN_PORT
        <= port_value
        <= MAX_PORT
    ):
        port_value = DEFAULT_PORT


    # ========================================================
    # DO NOT CHANGE
    # ========================================================

    if protocol == "vless-ws":

        path = (
            f"/ws/{uuid}"
        )

        params = {
            "encryption":
                "none",

            "security":
                "tls",

            "type":
                "ws",

            "host":
                host,

            "path":
                path,

            "sni":
                host,

            "fp":
                fp,

            "alpn":
                alpn_value,
        }

    else:

        mode = protocol.replace(
            "xhttp-",
            "",
        )

        path = (
            f"/xhttp-siz10/"
            f"{mode}/"
            f"{uuid}"
        )

        params = {
            "encryption":
                "none",

            "security":
                "tls",

            "type":
                "xhttp",

            "mode":
                mode,

            "host":
                host,

            "path":
                path,

            "sni":
                host,

            "fp":
                fp,

            "alpn":
                alpn_value,
        }


    query = "&".join(
        f"{key}="
        f"{quote(str(value))}"

        for key, value
        in params.items()
    )


    return (
        f"vless://"
        f"{uuid}@"
        f"{host}:"
        f"{port_value}?"
        f"{query}#"
        f"{quote(remark)}"
    )


def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
):
    return generate_vless_link(
        uid,
        host,
        remark=(
            f"PixonPanel-"
            f"{link.get('label', '')}"
        ),
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


# ============================================================
# LINK INFO
# ============================================================

def build_link_info(
    link: dict,
    uid: str,
    host: str,
):

    return {
        "uuid":
            uid,

        "name":
            link.get(
                "label",
                "",
            ),

        "label":
            link.get(
                "label",
                "",
            ),

        "protocol":
            link.get(
                "protocol",
                DEFAULT_PROTOCOL,
            ),

        "active":
            is_link_allowed(
                link
            ),

        "used_bytes":
            int(
                link.get(
                    "used_bytes",
                    0,
                )
                or 0
            ),

        "limit_bytes":
            int(
                link.get(
                    "limit_bytes",
                    0,
                )
                or 0
            ),

        "expires_at":
            link.get(
                "expires_at"
            ),

        "ip_limit":
            int(
                link.get(
                    "ip_limit",
                    0,
                )
                or 0
            ),

        "speed_limit_bytes":
            int(
                link.get(
                    "speed_limit_bytes",
                    0,
                )
                or 0
            ),

        "connection_limit":
            int(
                link.get(
                    "connection_limit",
                    0,
                )
                or 0
            ),

        "fragment":
            link.get(
                "fragment",
                "off",
            ),

        "fingerprint":
            link.get(
                "fingerprint",
                DEFAULT_FINGERPRINT,
            ),

        "alpn":
            link.get(
                "alpn",
                "http/1.1",
            ),

        "port":
            link.get(
                "port",
                DEFAULT_PORT,
            ),

        "note":
            link.get(
                "note",
                "",
            ),

        "notice":
            link.get(
                "notice",
                "",
            ),

        "vless":
            vless_link_for_link(
                link,
                uid,
                host,
            ),

        "sub":
            f"https://{host}/sub/{uid}",

        "info":
            f"https://{host}/info/{uid}",

        "support":
            SUPPORT_USERNAME,
    }


# ============================================================
# PERSISTENCE
# ============================================================

async def load_state():

    global AUTH

    try:

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            raw = await file.read()

        data = json.loads(
            raw
        )

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

        stored_password = data.get(
            "password_hash"
        )

        if stored_password:
            AUTH[
                "password_hash"
            ] = stored_password


        for link in LINKS.values():

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
                "http/1.1",
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
                "notice",
                "",
            )

            link.setdefault(
                "used_bytes",
                0,
            )


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

            payload = {
                "links":
                    dict(LINKS),

                "subs":
                    dict(SUBS),

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


async def ensure_default_link():

    global _default_link_created

    if _default_link_created:
        return

    async with LINKS_LOCK:

        if not any(
            item.get(
                "is_default"
            )
            for item
            in LINKS.values()
        ):

            digest = hashlib.sha256(
                (
                    "default"
                    + SECRET_KEY
                ).encode(
                    "utf-8"
                )
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

                "notice":
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
                    0,

                "connection_limit":
                    0,

                "fragment":
                    "off",
            }

    _default_link_created = True

    await save_state()


# ============================================================
# LINK MANAGEMENT
# ============================================================

async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    notice: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "http/1.1",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    connection_limit: int = 0,
    fragment: str = "off",
):

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

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

    if fragment not in {
        "off",
        "safe",
        "balanced",
        "aggressive",
    }:
        fragment = "off"

    uid = generate_uuid()

    record = {

        "label":
            (
                label
                or "لینک جدید"
            ).strip()[:60],

        "limit_bytes":
            max(
                0,
                int(
                    limit_bytes
                ),
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

        "notice":
            (
                notice
                or ""
            ).strip()[:2000],

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
                or "http/1.1"
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
                int(
                    speed_limit_bytes
                ),
            ),

        "connection_limit":
            max(
                0,
                int(
                    connection_limit
                ),
            ),

        "fragment":
            fragment,
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
# SUB GROUP
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

    uuid_key = secrets.token_urlsafe(
        16
    )

    record = {

        "name":
            name,

        "desc":
            desc,

        "password_hash":
            (
                hash_password(
                    password
                )
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
        SUBS[
            sub_id
        ] = record

    await save_state()

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

        del SUBS[
            sub_id
        ]

    async with LINKS_LOCK:

        for link in LINKS.values():

            if (
                link.get(
                    "sub_id"
                )
                == sub_id
            ):

                link[
                    "sub_id"
                ] = None

    await save_state()

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
        20.0,
        connect=8.0,
    )

    http_client = httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )

    await load_state()

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


@app.on_event("shutdown")
async def shutdown():

    await save_state()

    if http_client:

        await http_client.aclose()


# ============================================================
# NEWS
# ============================================================

def normalize_news(raw):

    if raw is None:
        return {
            "enabled": False,
            "title": "اطلاعیه مهم",
            "message": "",
            "updated_at": None,
        }

    if isinstance(
        raw,
        list,
    ):

        raw = {
            "items": raw
        }

    if not isinstance(
        raw,
        dict,
    ):

        return {
            "enabled": False,
            "title": "اطلاعیه مهم",
            "message": "",
            "updated_at": None,
        }


    enabled = raw.get(
        "enabled",
        raw.get(
            "active",
            raw.get(
                "show",
                raw.get(
                    "visible",
                    True,
                ),
            ),
        ),
    )

    title = (
        raw.get(
            "title"
        )
        or raw.get(
            "name"
        )
        or "اطلاعیه مهم"
    )

    message = (
        raw.get(
            "message"
        )
        or raw.get(
            "text"
        )
        or raw.get(
            "description"
        )
        or raw.get(
            "content"
        )
        or ""
    )


    nested = raw.get(
        "news"
    )

    if isinstance(
        nested,
        dict,
    ):

        enabled = nested.get(
            "enabled",
            enabled,
        )

        title = (
            nested.get(
                "title"
            )
            or title
        )

        if not message:

            message = (
                nested.get(
                    "message"
                )
                or nested.get(
                    "text"
                )
                or nested.get(
                    "description"
                )
                or nested.get(
                    "content"
                )
                or ""
            )


    nested = raw.get(
        "notice"
    )

    if isinstance(
        nested,
        dict,
    ):

        enabled = nested.get(
            "enabled",
            enabled,
        )

        title = (
            nested.get(
                "title"
            )
            or title
        )

        if not message:

            message = (
                nested.get(
                    "message"
                )
                or nested.get(
                    "text"
                )
                or nested.get(
                    "description"
                )
                or nested.get(
                    "content"
                )
                or ""
            )


    items = raw.get(
        "items"
    )

    if (
        not message
        and isinstance(
            items,
            list,
        )
        and items
    ):

        first = items[0]

        if isinstance(
            first,
            dict,
        ):

            enabled = first.get(
                "enabled",
                enabled,
            )

            title = (
                first.get(
                    "title"
                )
                or title
            )

            message = (
                first.get(
                    "message"
                )
                or first.get(
                    "text"
                )
                or first.get(
                    "description"
                )
                or first.get(
                    "content"
                )
                or ""
            )

        elif isinstance(
            first,
            str,
        ):

            message = first


    return {
        "enabled":
            bool(enabled),

        "title":
            str(title),

        "message":
            str(message),

        "updated_at":
            raw.get(
                "updated_at"
            )
            or raw.get(
                "updatedAt"
            ),
    }


async def fetch_news():

    now = time.time()

    async with NEWS_LOCK:

        if (
            NEWS_CACHE["data"]
            is not None
            and NEWS_CACHE["expires_at"]
            > now
        ):

            return NEWS_CACHE["data"]


        if http_client is None:

            return {
                "enabled": False,
                "title": "اطلاعیه مهم",
                "message": "",
                "updated_at": None,
            }


        try:

            response = await http_client.get(
                NEWS_URL,
                headers={
                    "User-Agent":
                        "PixonPanel/12.0.1",
                    "Cache-Control":
                        "no-cache",
                },
            )

            response.raise_for_status()

            data = normalize_news(
                response.json()
            )

            NEWS_CACHE[
                "data"
            ] = data

            NEWS_CACHE[
                "expires_at"
            ] = now + 60

            return data


        except Exception as exc:

            logger.warning(
                "Could not fetch news: %s",
                exc,
            )

            cached = (
                NEWS_CACHE.get(
                    "data"
                )
            )

            if cached:
                return cached

            return {
                "enabled": False,
                "title": "اطلاعیه مهم",
                "message": "",
                "updated_at": None,
            }


@app.get("/api/news")
async def api_news():

    return await fetch_news()


# ============================================================
# LANDING
# ============================================================

LANDING_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
PixonPanel
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

    padding:18px;

    color:#fff;

    font-family:
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.17),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:580px;

    padding:30px;

    border-radius:6px;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:
        blur(25px);
}

.logo{
    width:48px;
    height:48px;

    display:flex;
    align-items:center;
    justify-content:center;

    border-radius:6px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.title{
    margin-top:15px;

    font-size:23px;

    font-weight:900;
}

.version{
    margin-top:4px;

    color:#a78bfa;

    font-size:10px;
}

.status{
    display:inline-block;

    margin-top:16px;

    padding:6px 9px;

    border-radius:6px;

    color:#86efac;

    background:
        rgba(34,197,94,.08);

    font-size:10px;
}

.desc{
    margin-top:15px;

    color:
        rgba(255,255,255,.52);

    line-height:2;

    font-size:11px;
}

.btn{
    display:block;

    margin-top:18px;

    padding:12px;

    border-radius:6px;

    text-align:center;

    color:#fff;

    text-decoration:none;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-size:10px;

    font-weight:800;
}

.support{
    display:block;

    margin-top:14px;

    color:#a78bfa;

    text-decoration:none;

    text-align:center;

    font-size:9px;
}

</style>

</head>

<body>

<div class="card">

<div class="logo">
P
</div>

<div class="title">
PixonPanel
</div>

<div class="version">
12.0.1 Beta
</div>

<div class="status">
● سیستم آنلاین و فعال است
</div>

<div class="desc">
این صفحه درگاه عمومی PixonPanel است.
برای مدیریت کانفیگ‌ها وارد پنل شوید.
</div>

<a
href="/login"
class="btn"
>
ورود به پنل
</a>

<a
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
class="support"
>
پشتیبانی @Pixonal
</a>

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

<title>
ورود | PixonPanel
</title>

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

    padding:18px;

    color:#fff;

    font-family:
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.18),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:410px;

    padding:26px;

    border-radius:6px;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:
        blur(25px);
}

.logo{
    width:47px;
    height:47px;

    display:flex;
    align-items:center;
    justify-content:center;

    border-radius:6px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

h1{
    margin:15px 0 0;

    font-size:22px;
}

.version{
    margin-top:4px;

    color:#a78bfa;

    font-size:10px;
}

.description{
    margin-top:8px;

    color:
        rgba(255,255,255,.45);

    line-height:1.8;

    font-size:10px;
}

form{
    margin-top:19px;
}

label{
    display:block;

    margin-bottom:7px;

    color:
        rgba(255,255,255,.42);

    font-size:9px;
}

input{
    width:100%;

    padding:13px;

    border-radius:6px;

    border:
        1px solid
        rgba(255,255,255,.08);

    outline:none;

    color:#fff;

    background:
        rgba(0,0,0,.18);

    direction:ltr;

    text-align:left;
}

button{
    width:100%;

    margin-top:10px;

    padding:13px;

    border:0;

    border-radius:6px;

    color:#fff;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight:800;

    cursor:pointer;
}

.error{
    margin-top:10px;

    padding:10px;

    border-radius:6px;

    color:#fca5a5;

    background:
        rgba(239,68,68,.08);

    font-size:9px;
}

.support{
    display:block;

    margin-top:15px;

    text-align:center;

    color:#a78bfa;

    text-decoration:none;

    font-size:9px;
}

</style>

</head>

<body>

<div class="card">

<div class="logo">
P
</div>

<h1>
ورود به PixonPanel
</h1>

<div class="version">
12.0.1 Beta
</div>

<div class="description">
رمز عبور پنل مدیریت را وارد کنید.
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
ورود
</button>

</form>

<a
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
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

    return LOGIN_HTML.replace(
        "</form>",
        (
            f"""
            <div class="error">
                {escape_html(message)}
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

        if (
            "application/json"
            in content_type
        ):

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

    except Exception:

        return HTMLResponse(
            login_error_html(
                "خطا در پردازش اطلاعات ورود."
            ),
            status_code=400,
        )


    if not password:

        return HTMLResponse(
            login_error_html(
                "رمز عبور را وارد کنید."
            ),
            status_code=400,
        )


    if (
        hash_password(
            password
        )
        != AUTH[
            "password_hash"
        ]
    ):

        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق "
                f"از {client_ip(request)}"
            ),
            "err",
        )

        return HTMLResponse(
            login_error_html(
                "رمز عبور اشتباه است."
            ),
            status_code=401,
        )


    token = await create_session()

    response = RedirectResponse(
        "/dashboard",
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


# ============================================================
# API LOGIN
# ============================================================

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

    if (
        hash_password(password)
        != AUTH[
            "password_hash"
        ]
    ):

        raise HTTPException(
            status_code=401,
            detail="رمز عبور اشتباه است",
        )

    token = await create_session()

    response = JSONResponse(
        {
            "ok":
                True,

            "authenticated":
                True,
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
async def logout(
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
            "ok":
                True
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
async def change_password(
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
        hash_password(
            current_password
        )
        != AUTH[
            "password_hash"
        ]
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

    if len(
        new_password
    ) < 6:

        raise HTTPException(
            status_code=400,
            detail=(
                "رمز جدید باید حداقل "
                "۶ کاراکتر باشد"
            ),
        )

    if new_password != repeat_password:

        raise HTTPException(
            status_code=400,
            detail=(
                "تکرار رمز عبور یکسان نیست"
            ),
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )

    async with SESSIONS_LOCK:

        SESSIONS.clear()

        SESSIONS[
            token
        ] = (
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
        "ok":
            True
    }


# ============================================================
# CREATE LINK API
# ============================================================

@app.post("/api/links")
async def create_link_api(
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


    connection_limit = safe_int(
        body.get(
            "connection_limit",
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

    if fragment not in {
        "off",
        "safe",
        "balanced",
        "aggressive",
    }:

        fragment = "off"


    uid, link = await make_link(

        label=body.get(
            "label",
            auto_config_name(),
        ),

        limit_bytes=
            limit_bytes,

        expires_at=
            expires_at,

        note=body.get(
            "note",
            "",
        ),

        notice=body.get(
            "notice",
            "",
        ),

        sub_id=body.get(
            "sub_id"
        ),

        protocol=
            protocol,

        fingerprint=
            fingerprint,

        alpn=body.get(
            "alpn",
            DEFAULT_ALPN_BY_PROTOCOL.get(
                protocol,
                "http/1.1",
            ),
        ),

        port=
            port,

        ip_limit=
            ip_limit,

        speed_limit_bytes=
            speed_bytes,

        connection_limit=
            connection_limit,

        fragment=
            fragment,
    )


    host = get_host(
        request
    )


    return {
        "ok":
            True,

        **build_link_info(
            link,
            uid,
            host,
        ),
    }


# ============================================================
# AUTO CREATE
# ============================================================

@app.post("/api/links/auto")
async def create_auto_link(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(
        request
    )

    uid, link = await make_link(

        label=
            auto_config_name(),

        limit_bytes=
            0,

        expires_at=
            None,

        note=
            "Auto generated by PixonPanel",

        notice=
            "",

        sub_id=
            None,

        # Keep the working VLESS WS
        protocol=
            "vless-ws",

        fingerprint=
            "chrome",

        alpn=
            "http/1.1",

        port=
            443,

        ip_limit=
            0,

        speed_limit_bytes=
            0,

        connection_limit=
            0,

        fragment=
            "off",
    )


    return {
        "ok":
            True,

        **build_link_info(
            link,
            uid,
            host,
        ),
    }


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/links")
async def list_links(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(
        request
    )

    async with LINKS_LOCK:

        snapshot = dict(
            LINKS
        )

    result = []


    for uid, link in snapshot.items():

        item = build_link_info(
            link,
            uid,
            host,
        )

        item[
            "created_at"
        ] = link.get(
            "created_at"
        )

        item[
            "expired"
        ] = is_link_expired(
            link
        )

        item[
            "connected_ips"
        ] = len(
            unique_ips_for_uuid(
                uid
            )
        )

        result.append(
            item
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
        "links":
            result
    }


# ============================================================
# LINK INFO API
# ============================================================

@app.get(
    "/api/links/{uid}/info"
)
async def link_info_api(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(
            uid
        )

        if not link:

            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        snapshot = dict(
            link
        )


    host = get_host(
        request
    )

    return {
        "ok":
            True,

        **build_link_info(
            snapshot,
            uid,
            host,
        ),
    }


# ============================================================
# UPDATE LINK
# ============================================================

@app.patch(
    "/api/links/{uid}"
)
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
            detail="JSON نامعتبر است",
        )


    async with LINKS_LOCK:

        if uid not in LINKS:

            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link = LINKS[
            uid
        ]

        old_sub = link.get(
            "sub_id"
        )

        old_label = link.get(
            "label",
            uid,
        )


        if "label" in body:

            label = str(
                body.get(
                    "label",
                    "",
                )
            ).strip()

            if label:
                link[
                    "label"
                ] = label[:60]


        if "active" in body:

            link[
                "active"
            ] = bool(
                body.get(
                    "active"
                )
            )


        if "note" in body:

            link[
                "note"
            ] = str(
                body.get(
                    "note",
                    "",
                )
            )[:500]


        if "notice" in body:

            link[
                "notice"
            ] = str(
                body.get(
                    "notice",
                    "",
                )
            )[:2000]


        if body.get(
            "reset_usage",
            False,
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


        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                )
            ).strip()

            if protocol not in PROTOCOLS:
                protocol = DEFAULT_PROTOCOL

            link[
                "protocol"
            ] = protocol


        if "fingerprint" in body:

            fingerprint = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).strip().lower()

            if fingerprint not in FINGERPRINTS:
                fingerprint = DEFAULT_FINGERPRINT

            link[
                "fingerprint"
            ] = fingerprint


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

            link[
                "fragment"
            ] = fragment


        if "alpn" in body:

            link[
                "alpn"
            ] = str(
                body.get(
                    "alpn",
                    "http/1.1",
                )
            )[:100]


        if "port" in body:

            link[
                "port"
            ] = safe_int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                ),
                default=DEFAULT_PORT,
                minimum=MIN_PORT,
                maximum=MAX_PORT,
            )


        if "ip_limit" in body:

            link[
                "ip_limit"
            ] = safe_int(
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

            unit = str(
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
                    unit,
                )
            )


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
            f"«{old_label}» "
            f"ویرایش شد"
        ),
        "info",
    )


    return {
        "ok":
            True
    }


# ============================================================
# RESET USAGE
# ============================================================

@app.post(
    "/api/links/{uid}/reset-usage"
)
async def reset_usage(
    uid: str,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        if uid not in LINKS:

            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        LINKS[
            uid
        ][
            "used_bytes"
        ] = 0

        label = LINKS[
            uid
        ].get(
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
        "ok":
            True,

        "used_bytes":
            0,
    }


# ============================================================
# DELETE
# ============================================================

@app.delete(
    "/api/links/{uid}"
)
async def delete_link(
    uid: str,
    _=Depends(require_auth),
):

    deleted = await remove_link(
        uid
    )

    if deleted is None:

        raise HTTPException(
            status_code=404,
            detail="link not found",
        )

    return {
        "ok":
            True,

        "deleted":
            uid,
    }


# ============================================================
# SINGLE SUB
# ============================================================

@app.get(
    "/sub/{uuid}"
)
async def subscription_single(
    uuid: str,
    request: Request,
):

    async with LINKS_LOCK:

        link = LINKS.get(
            uuid
        )

    if not is_link_allowed(
        link
    ):

        raise HTTPException(
            status_code=404,
            detail="not found or inactive",
        )


    host = get_host(
        request
    )


    vless = vless_link_for_link(
        link,
        uuid,
        host,
    )


    content = (
        base64
        .b64encode(
            vless.encode()
        )
        .decode()
    )


    return Response(
        content=content,
        media_type="text/plain",
        headers={

            "profile-title":
                quote(
                    link.get(
                        "label",
                        APP_NAME,
                    )
                ),

            "support-url":
                SUPPORT_URL,

            "profile-update-interval":
                "12",
        },
    )


# ============================================================
# SUB ALL
# ============================================================

@app.get(
    "/sub-all"
)
async def subscription_all(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(
        request
    )

    async with LINKS_LOCK:

        lines = [

            vless_link_for_link(
                link,
                uid,
                host,
            )

            for uid, link
            in LINKS.items()

            if is_link_allowed(
                link
            )
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

        link = LINKS.get(
            uid
        )

        if not link:

            return HTMLResponse(
                """
                <html lang="fa" dir="rtl">
                <body style="
                    margin:0;
                    padding:40px;
                    background:#07070a;
                    color:#fff;
                    font-family:sans-serif;
                ">
                    <h2>
                    کانفیگ پیدا نشد
                    </h2>
                </body>
                </html>
                """,
                status_code=404,
            )

        snapshot = dict(
            link
        )


    host = get_host(
        request
    )


    vless = vless_link_for_link(
        snapshot,
        uid,
        host,
    )


    sub_url = (
        f"https://{host}"
        f"/sub/{uid}"
    )


    news = await fetch_news()


    custom_notice = (
        snapshot.get(
            "notice",
            "",
        )
        .strip()
    )


    custom_notice_html = ""

    if custom_notice:

        custom_notice_html = (
            """
            <div class="notice custom">
                <div class="notice-head">
                    <span class="icon">
                        #
                    </span>
                    <span>
                        اطلاعیه کانفیگ
                    </span>
                </div>

                <div class="notice-text">
            """
            +
            escape_html(
                custom_notice
            ).replace(
                "\n",
                "<br>"
            )
            +
            """
                </div>
            </div>
            """
        )


    system_notice_html = ""

    if (
        news.get(
            "enabled",
            False,
        )
        and
        news.get(
            "message",
            "",
        ).strip()
    ):

        system_notice_html = (
            """
            <div class="notice system">

                <div class="notice-head">

                    <span class="icon">
                        !
                    </span>

                    <span>
            """
            +
            escape_html(
                news.get(
                    "title",
                    "اطلاعیه مهم",
                )
            )
            +
            """
                    </span>

                </div>

                <div class="notice-text">
            """
            +
            escape_html(
                news.get(
                    "message",
                    "",
                )
            ).replace(
                "\n",
                "<br>"
            )
            +
            """
                </div>

            </div>
            """
        )


    info_html = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
PixonPanel | INFO
</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;

    padding:16px;

    display:flex;
    justify-content:center;
    align-items:center;

    color:#fff;

    font-family:
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.18),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:720px;

    padding:20px;

    border-radius:6px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.045);

    backdrop-filter:blur(24px);
}

.brand{
    display:flex;

    align-items:center;

    gap:9px;
}

.logo{
    width:40px;
    height:40px;

    display:flex;
    justify-content:center;
    align-items:center;

    border-radius:6px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.title{
    font-size:17px;
    font-weight:900;
}

.version{
    margin-top:2px;

    color:#a78bfa;

    font-size:9px;
}

.notice{
    margin-top:10px;

    padding:12px;

    border-radius:6px;

    border:
        1px solid
        rgba(255,255,255,.06);

    background:
        rgba(255,255,255,.03);
}

.notice.custom{
    background:
        rgba(139,92,246,.07);

    border-color:
        rgba(139,92,246,.15);
}

.notice.system{
    background:
        rgba(99,102,241,.07);

    border-color:
        rgba(99,102,241,.16);
}

.notice-head{
    display:flex;

    align-items:center;

    gap:6px;

    font-size:10px;

    font-weight:800;
}

.icon{
    width:19px;
    height:19px;

    display:inline-flex;

    align-items:center;
    justify-content:center;

    border-radius:5px;

    background:
        rgba(255,255,255,.07);

    color:#c4b5fd;
}

.notice-text{
    margin-top:7px;

    color:
        rgba(255,255,255,.58);

    line-height:1.9;

    font-size:9px;
}

.row{
    margin-top:9px;

    padding:11px;

    border-radius:6px;

    background:
        rgba(255,255,255,.025);

    border:
        1px solid
        rgba(255,255,255,.055);
}

.label{
    margin-bottom:6px;

    color:
        rgba(255,255,255,.32);

    font-size:8px;
}

.value{
    direction:ltr;

    text-align:left;

    word-break:break-all;

    color:#c4b5fd;

    font-family:
        Consolas,
        monospace;

    font-size:8px;
}

.support{
    margin-top:14px;

    color:#a78bfa;

    font-size:9px;
}

</style>

</head>

<body>

<div class="card">

<div class="brand">

<div class="logo">
P
</div>

<div>

<div class="title">
__NAME__
</div>

<div class="version">
PixonPanel · __APP_VERSION__
</div>

</div>

</div>

__CUSTOM_NOTICE__

__SYSTEM_NOTICE__


<div class="row">

<div class="label">
وضعیت
</div>

<div class="value">
__STATUS__
</div>

</div>


<div class="row">

<div class="label">
UUID
</div>

<div class="value">
__UUID__
</div>

</div>


<div class="row">

<div class="label">
VLESS
</div>

<div class="value">
__VLESS__
</div>

</div>


<div class="row">

<div class="label">
SUB
</div>

<div class="value">
__SUB__
</div>

</div>


<div class="row">

<div class="label">
Volume
</div>

<div class="value">
__VOLUME__
</div>

</div>


<div class="row">

<div class="label">
Time
</div>

<div class="value">
__TIME__
</div>

</div>


<div class="row">

<div class="label">
IP Limit
</div>

<div class="value">
__IP_LIMIT__
</div>

</div>


<div class="row">

<div class="label">
Connection Limit
</div>

<div class="value">
__CONNECTION_LIMIT__
</div>

</div>


<div class="row">

<div class="label">
Speed
</div>

<div class="value">
__SPEED__
</div>

</div>


<div class="row">

<div class="label">
Fingerprint
</div>

<div class="value">
__FINGERPRINT__
</div>

</div>


<div class="row">

<div class="label">
Fragment
</div>

<div class="value">
__FRAGMENT__
</div>

</div>


<div class="support">

پشتیبانی:

<strong>
__SUPPORT__
</strong>

</div>

</div>

</body>

</html>
"""


    info_html = (
        info_html
        .replace(
            "__NAME__",
            escape_html(
                snapshot.get(
                    "label",
                    APP_NAME,
                )
            ),
        )
        .replace(
            "__APP_VERSION__",
            escape_html(
                APP_VERSION
            ),
        )
        .replace(
            "__CUSTOM_NOTICE__",
            custom_notice_html,
        )
        .replace(
            "__SYSTEM_NOTICE__",
            system_notice_html,
        )
        .replace(
            "__STATUS__",
            (
                "ACTIVE"
                if is_link_allowed(
                    snapshot
                )
                else
                "DISABLED"
            ),
        )
        .replace(
            "__UUID__",
            escape_html(
                uid
            ),
        )
        .replace(
            "__VLESS__",
            escape_html(
                vless
            ),
        )
        .replace(
            "__SUB__",
            escape_html(
                sub_url
            ),
        )
        .replace(
            "__VOLUME__",
            (
                "Unlimited"
                if not snapshot.get(
                    "limit_bytes",
                    0,
                )
                else escape_html(
                    fmt_bytes(
                        snapshot.get(
                            "limit_bytes",
                            0,
                        )
                    )
                )
            ),
        )
        .replace(
            "__TIME__",
            (
                "Unlimited"
                if not snapshot.get(
                    "expires_at"
                )
                else escape_html(
                    snapshot.get(
                        "expires_at"
                    )
                )
            ),
        )
        .replace(
            "__IP_LIMIT__",
            (
                "Unlimited"
                if not snapshot.get(
                    "ip_limit",
                    0,
                )
                else str(
                    snapshot.get(
                        "ip_limit"
                    )
                )
            ),
        )
        .replace(
            "__CONNECTION_LIMIT__",
            (
                "Unlimited"
                if not snapshot.get(
                    "connection_limit",
                    0,
                )
                else str(
                    snapshot.get(
                        "connection_limit"
                    )
                )
            ),
        )
        .replace(
            "__SPEED__",
            (
                "Unlimited"
                if not snapshot.get(
                    "speed_limit_bytes",
                    0,
                )
                else escape_html(
                    fmt_bytes(
                        snapshot.get(
                            "speed_limit_bytes",
                            0,
                        )
                    )
                    + "/s"
                )
            ),
        )
        .replace(
            "__FINGERPRINT__",
            escape_html(
                snapshot.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ),
        )
        .replace(
            "__FRAGMENT__",
            escape_html(
                snapshot.get(
                    "fragment",
                    "off",
                )
            ),
        )
        .replace(
            "__SUPPORT__",
            escape_html(
                SUPPORT_USERNAME
            ),
        )
    )


    return HTMLResponse(
        info_html
    )


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

    host = get_host(
        request
    )

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

    host = get_host(
        request
    )

    async with SUBS_LOCK:
        snapshot_subs = dict(
            SUBS
        )

    async with LINKS_LOCK:
        snapshot_links = dict(
            LINKS
        )

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
        "subs":
            result
    }


@app.patch(
    "/api/subs/{sub_id}"
)
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

        sub = SUBS[
            sub_id
        ]

        if "name" in body:

            sub[
                "name"
            ] = str(
                body[
                    "name"
                ]
            )[:60]

        if "desc" in body:

            sub[
                "desc"
            ] = str(
                body[
                    "desc"
                ]
            )[:200]

        if "password" in body:

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

            sub[
                "password_hash"
            ] = (
                hash_password(
                    password
                )
                if password
                else None
            )

        if "link_ids" in body:

            sub[
                "link_ids"
            ] = list(
                body[
                    "link_ids"
                ]
            )

    await save_state()

    return {
        "ok":
            True
    }


@app.delete(
    "/api/subs/{sub_id}"
)
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
        "ok":
            True,

        "deleted":
            sub_id,
    }


@app.post(
    "/api/subs/{sub_id}/links"
)
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
        "ok":
            True
    }


# ============================================================
# GROUP SUB
# ============================================================

@app.get(
    "/sub-group/{uuid_key}"
)
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
                )
                == uuid_key
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
            hash_password(
                password
            )
            != sub[
                "password_hash"
            ]
        ):

            raise HTTPException(
                status_code=403,
                detail="wrong password",
            )


    host = get_host(
        request
    )


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


    return Response(
        content=content,
        media_type="text/plain",
        headers={

            "profile-title":
                quote(
                    sub[
                        "name"
                    ]
                ),

            "support-url":
                SUPPORT_URL,

            "profile-update-interval":
                "12",
        },
    )


# ============================================================
# PUBLIC GROUP PAGE
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
PixonPanel
</title>

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

    padding:16px;

    color:#fff;

    font-family:
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.17),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:600px;

    padding:22px;

    border-radius:6px;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:blur(24px);
}

.title{
    font-size:18px;
    font-weight:900;
}

.version{
    margin-top:3px;
    color:#a78bfa;
    font-size:9px;
}

.text{
    margin-top:10px;
    color:rgba(255,255,255,.5);
    line-height:1.9;
    font-size:10px;
}

.url{
    margin-top:13px;
    padding:11px;

    direction:ltr;
    text-align:left;

    word-break:break-all;

    border-radius:6px;

    background:
        rgba(0,0,0,.2);

    color:#c4b5fd;

    font-family:Consolas,monospace;

    font-size:8px;
}

.notice{
    margin-top:10px;
    padding:11px;
    border-radius:6px;

    background:
        rgba(99,102,241,.06);

    border:
        1px solid
        rgba(99,102,241,.12);

    color:rgba(255,255,255,.58);

    font-size:9px;
    line-height:1.9;
}

.support{
    display:inline-block;
    margin-top:13px;

    color:#a78bfa;

    text-decoration:none;

    font-size:9px;
}

</style>

</head>

<body>

<div class="card">

<div class="title">
PixonPanel
</div>

<div class="version">
12.0.1 Beta
</div>

<div
class="notice"
id="systemNotice"
>
</div>

<div class="text">
اشتراک شما آماده است.
</div>

<div
class="url"
id="subUrl"
>
</div>

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

const subUrl =
    location.origin +
    location.pathname.replace(
        "/p/",
        "/sub-group/"
    );

document.getElementById(
    "subUrl"
).textContent = subUrl;


fetch("/api/news")
    .then(
        response =>
            response.json()
    )
    .then(
        data => {

            if(
                data.enabled &&
                data.message
            ){

                const box =
                    document.getElementById(
                        "systemNotice"
                    );

                box.innerHTML =
                    "<strong>" +
                    String(
                        data.title ||
                        "اطلاعیه مهم"
                    ) +
                    "</strong><br>" +
                    String(
                        data.message
                    )
                    .replaceAll(
                        "\n",
                        "<br>"
                    );

            }

        }
    )
    .catch(
        () => {}
    );

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
            )
            == uuid_key

            for item
            in SUBS.values()
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


# ============================================================
# PUBLIC SUB DATA
# ============================================================

@app.get(
    "/api/public/sub/{uuid_key}"
)
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
                )
                == uuid_key
            ),
            None,
        )

    if not entry:

        raise HTTPException(
            status_code=404,
            detail="not found",
        )


    _, sub = entry


    if sub.get(
        "password_hash"
    ):

        password = (
            request
            .query_params
            .get(
                "pw",
                "",
            )
        )

        if (
            hash_password(
                password
            )
            != sub[
                "password_hash"
            ]
        ):

            return {
                "locked":
                    True,

                "name":
                    sub[
                        "name"
                    ],
            }


    host = get_host(
        request
    )


    async with LINKS_LOCK:
        snapshot = dict(
            LINKS
        )


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

            for item
            in connections.values()

            if item.get(
                "uuid"
            )
            == link_id
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

                "notice":
                    link.get(
                        "notice",
                        "",
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
        item[
            "used_bytes"
        ]

        for item
        in links_out
    )


    return {

        "locked":
            False,

        "name":
            sub[
                "name"
            ],

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


# ============================================================
# STATS
# ============================================================

@app.get("/stats")
async def get_stats(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(
            LINKS
        )

    return {

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "active_connections":
            len(
                connections
            ),

        "total_bytes":
            stats[
                "total_bytes"
            ],

        "total_traffic_bytes":
            stats[
                "total_bytes"
            ],

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

        "recent_errors":
            list(
                error_logs
            )[-10:],
    }


# ============================================================
# ACTIVITY
# ============================================================

@app.get(
    "/api/activity"
)
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

@app.get(
    "/api/connections"
)
async def get_connections(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(
            LINKS
        )

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
            else
            "نامشخص"
        )


        group = grouped.get(
            ip
        )


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

            grouped[
                ip
            ] = group


        group[
            "sessions"
        ] += 1


        group[
            "bytes"
        ] += int(
            connection.get(
                "bytes",
                0,
            )
            or 0
        )


        group[
            "labels"
        ].add(
            label
        )


        group[
            "transports"
        ].add(
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
                    group[
                        "ip"
                    ],

                "sessions":
                    group[
                        "sessions"
                    ],

                "bytes":
                    group[
                        "bytes"
                    ],

                "bytes_fmt":
                    fmt_bytes(
                        group[
                            "bytes"
                        ]
                    ),

                "label":
                    (
                        " · ".join(
                            sorted(
                                group[
                                    "labels"
                                ]
                            )
                        )

                        if group[
                            "labels"
                        ]

                        else
                        "نامشخص"
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


    return {

        "connections":
            result,

        "count":
            len(result),

        "raw_count":
            len(connections),
    }


# ============================================================
# REAL VLESS CORE
# DO NOT CHANGE
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

    logger.exception(
        "VLESS relay module unavailable: %s",
        exc,
    )


# ============================================================
# OPTIONAL XHTTP
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
# OPTIONAL TELEGRAM
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


@app.on_event("shutdown")
async def stop_optional_telegram():

    try:

        await _tg_stop_bot()

    except Exception:
        pass


# ============================================================
# DASHBOARD
# IMPORTANT:
# Raw string + placeholders.
# NO F-STRING.
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
PixonPanel
</title>

<style>

*{
    box-sizing:border-box;
}

html,
body{
    margin:0;
    min-height:100%;
}

body{
    min-height:100vh;

    color:#fff;

    font-family:
        Arial,
        sans-serif;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.13),
            transparent 25%
        ),
        radial-gradient(
            circle at bottom left,
            rgba(139,92,246,.09),
            transparent 25%
        ),
        #07070a;
}

.wrapper{
    width:min(
        1280px,
        calc(100% - 18px)
    );

    margin:auto;

    padding:
        13px
        0
        40px;
}

.topbar{
    display:flex;

    justify-content:
        space-between;

    align-items:center;

    gap:8px;

    flex-wrap:wrap;

    margin-bottom:8px;
}

.brand{
    display:flex;

    align-items:center;

    gap:8px;
}

.logo{
    width:40px;
    height:40px;

    display:flex;

    align-items:center;
    justify-content:center;

    border-radius:6px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.brand-name{
    font-size:14px;

    font-weight:900;
}

.version{
    margin-top:2px;

    color:#a78bfa;

    font-size:8px;
}

.controls{
    display:flex;

    gap:5px;

    flex-wrap:wrap;
}

button,
a{
    font-family:inherit;
}

.top-btn{
    border:1px solid
        rgba(255,255,255,.06);

    border-radius:6px;

    padding:
        8px 10px;

    color:#fff;

    background:
        rgba(255,255,255,.035);

    font-size:8px;

    cursor:pointer;

    text-decoration:none;
}

.top-btn.primary{
    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    border-color:
        transparent;
}

.top-btn.danger{
    color:#fca5a5;
}

.stats{
    display:grid;

    grid-template-columns:
        repeat(6,1fr);

    gap:6px;
}

.stat{
    padding:10px;

    border-radius:6px;

    background:
        rgba(255,255,255,.03);

    border:
        1px solid
        rgba(255,255,255,.06);
}

.stat-label{
    color:
        rgba(255,255,255,.3);

    font-size:7px;
}

.stat-value{
    margin-top:5px;

    font-size:16px;

    font-weight:900;
}

.panel{
    margin-top:8px;

    overflow:hidden;

    border-radius:6px;

    border:
        1px solid
        rgba(255,255,255,.06);

    background:
        rgba(255,255,255,.03);
}

.panel-head{
    display:flex;

    justify-content:
        space-between;

    align-items:center;

    padding:
        10px 11px;

    gap:8px;

    border-bottom:
        1px solid
        rgba(255,255,255,.05);
}

.panel-title{
    font-size:10px;

    font-weight:800;
}

.panel-sub{
    margin-top:2px;

    color:
        rgba(255,255,255,.27);

    font-size:7px;
}

.table-wrap{
    overflow:auto;
}

table{
    width:100%;

    min-width:1180px;

    border-collapse:
        collapse;
}

th,
td{
    text-align:right;

    padding:
        9px;

    border-bottom:
        1px solid
        rgba(255,255,255,.04);

    font-size:7px;

    vertical-align:middle;
}

th{
    color:
        rgba(255,255,255,.28);

    font-weight:500;
}

.badge{
    display:inline-flex;

    padding:
        4px 6px;

    border-radius:6px;

    font-size:7px;
}

.badge.active{
    color:#86efac;

    background:
        rgba(34,197,94,.08);
}

.badge.off{
    color:#fca5a5;

    background:
        rgba(239,68,68,.08);
}

.url{
    max-width:220px;

    direction:ltr;

    text-align:left;

    white-space:nowrap;

    overflow:hidden;

    text-overflow:ellipsis;

    color:#c4b5fd;

    font-family:
        Consolas,
        monospace;

    font-size:7px;
}

.actions{
    display:flex;

    flex-wrap:wrap;

    gap:3px;
}

.action{
    border:0;

    border-radius:6px;

    padding:
        6px 7px;

    color:#fff;

    background:
        rgba(255,255,255,.05);

    font-size:7px;

    cursor:pointer;
}

.action.primary{
    background:
        rgba(99,102,241,.18);
}

.action.green{
    color:#86efac;
}

.action.red{
    color:#fca5a5;
}

.logs{
    margin:0;

    padding:11px;

    min-height:90px;

    max-height:230px;

    overflow:auto;

    color:
        rgba(255,255,255,.4);

    font-family:
        Consolas,
        monospace;

    white-space:pre-wrap;

    font-size:7px;
}

.downloads{
    display:grid;

    grid-template-columns:
        repeat(3,1fr);

    gap:5px;

    padding:9px;
}

.download{
    display:block;

    padding:9px;

    border-radius:6px;

    text-decoration:none;

    color:#fff;

    border:
        1px solid
        rgba(255,255,255,.05);

    background:
        rgba(255,255,255,.025);

    font-size:7px;
}

.download small{
    display:block;

    margin-top:3px;

    color:
        rgba(255,255,255,.28);

    font-size:6px;
}

.system-notice{
    margin:
        0 9px
        9px;

    padding:10px;

    border-radius:6px;

    background:
        rgba(99,102,241,.06);

    border:
        1px solid
        rgba(99,102,241,.12);

    color:
        rgba(255,255,255,.57);

    line-height:1.8;

    font-size:7px;
}

.system-notice strong{
    color:#c4b5fd;
}

.modal-bg{
    position:fixed;

    inset:0;

    z-index:1000;

    display:none;

    justify-content:center;
    align-items:center;

    padding:10px;

    background:
        rgba(0,0,0,.68);

    backdrop-filter:
        blur(10px);
}

.modal-bg.open{
    display:flex;
}

.modal{
    width:100%;

    max-width:720px;

    max-height:
        calc(100vh - 20px);

    overflow:auto;

    padding:15px;

    border-radius:6px;

    background:
        #0f0f15;

    border:
        1px solid
        rgba(255,255,255,.07);
}

.modal-head{
    display:flex;

    justify-content:
        space-between;

    align-items:center;

    margin-bottom:11px;
}

.modal-title{
    font-size:11px;

    font-weight:900;
}

.close{
    width:28px;
    height:28px;

    border:0;

    border-radius:6px;

    background:
        rgba(255,255,255,.05);

    color:#fff;

    cursor:pointer;
}

.fields{
    display:grid;

    grid-template-columns:
        repeat(2,1fr);

    gap:6px;
}

.field{
    display:flex;

    flex-direction:column;

    gap:4px;
}

.field.full{
    grid-column:
        1 / -1;
}

.field label{
    color:
        rgba(255,255,255,.34);

    font-size:7px;
}

.field input,
.field select,
.field textarea{
    width:100%;

    padding:9px;

    border-radius:6px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(255,255,255,.03);

    color:#fff;

    outline:none;

    font-family:inherit;

    font-size:8px;
}

.field textarea{
    min-height:75px;

    resize:vertical;
}

.modal-actions{
    display:flex;

    gap:5px;

    margin-top:9px;
}

.modal-btn{
    flex:1;

    border:0;

    border-radius:6px;

    padding:10px;

    cursor:pointer;

    color:#fff;

    background:
        rgba(255,255,255,.05);

    font-size:8px;
}

.modal-btn.primary{
    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.news-box{
    padding:13px;

    border-radius:6px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(255,255,255,.025);
}

.news-title{
    font-size:14px;

    font-weight:900;
}

.news-version{
    margin-top:3px;

    color:#a78bfa;

    font-size:7px;
}

.news-message{
    margin-top:9px;

    color:
        rgba(255,255,255,.62);

    font-size:9px;

    line-height:2;
}

.empty{
    text-align:center;

    padding:24px;

    color:
        rgba(255,255,255,.27);
}

.toast{
    position:fixed;

    left:10px;
    bottom:10px;

    z-index:3000;

    padding:
        9px 11px;

    border-radius:6px;

    color:#fff;

    background:
        #15151c;

    border:
        1px solid
        rgba(255,255,255,.08);

    font-size:7px;

    opacity:0;

    transform:
        translateY(8px);

    transition:
        .2s ease;

    pointer-events:none;
}

.toast.show{
    opacity:1;

    transform:
        translateY(0);
}

@media(max-width:1050px){

    .stats{
        grid-template-columns:
            repeat(3,1fr);
    }

    .downloads{
        grid-template-columns:
            repeat(2,1fr);
    }
}

@media(max-width:700px){

    .stats{
        grid-template-columns:
            repeat(2,1fr);
    }

    .fields{
        grid-template-columns:1fr;
    }

    .field.full{
        grid-column:auto;
    }

}

@media(max-width:430px){

    .downloads{
        grid-template-columns:1fr;
    }

}

</style>

</head>

<body>

<div class="wrapper">


<div class="topbar">

<div class="brand">

<div class="logo">
P
</div>

<div>

<div class="brand-name">
PixonPanel
</div>

<div class="version">
__APP_VERSION__
</div>

</div>

</div>


<div class="controls">

<button
class="top-btn primary"
id="autoBtn"
>
+ ساخت خودکار
</button>

<button
class="top-btn"
id="manualBtn"
>
+ ساخت دستی
</button>

<button
class="top-btn"
id="passwordBtn"
>
تغییر رمز
</button>

<button
class="top-btn"
id="newsBtn"
>
اطلاعیه
</button>

<a
class="top-btn danger"
href="/logout"
>
خروج
</a>

</div>

</div>


<div class="stats">

<div class="stat">
<div class="stat-label">
کانفیگ
</div>
<div
id="statLinks"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
فعال
</div>
<div
id="statActive"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
اتصال
</div>
<div
id="statConnections"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
Traffic
</div>
<div
id="statTraffic"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
Requests
</div>
<div
id="statRequests"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
Uptime
</div>
<div
id="statUptime"
class="stat-value"
>
-
</div>
</div>

</div>


<div class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
مدیریت کانفیگ‌ها
</div>

<div class="panel-sub">
VLESS · SUB · INFO · EDIT · RESET
</div>

</div>

<button
class="top-btn"
id="refreshBtn"
>
↻
</button>

</div>


<div class="table-wrap">

<table>

<thead>

<tr>

<th>
نام
</th>

<th>
پروتکل
</th>

<th>
وضعیت
</th>

<th>
مصرف
</th>

<th>
زمان
</th>

<th>
IP
</th>

<th>
VLESS
</th>

<th>
عملیات
</th>

</tr>

</thead>


<tbody
id="linksTable"
>
</tbody>

</table>

</div>

</div>


<div class="panel">

<div class="panel-head">

<div class="panel-title">
فعالیت
</div>

</div>

<pre
class="logs"
id="logs"
>
در حال بارگذاری...
</pre>

</div>


<div class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
برنامه‌های اتصال
</div>

<div class="panel-sub">
Android · iPhone · iPad · Windows
</div>

</div>

</div>


<div class="downloads">


<a
class="download"
href="https://play.google.com/store/apps/details?id=com.happproxy"
target="_blank"
rel="noopener"
>
Happ Android
<small>
Google Play
</small>
</a>


<a
class="download"
href="https://dl.v2rayng.org/releases/latest/v2rayNG_2.2.6_arm64-v8a.apk"
target="_blank"
rel="noopener"
>
v2rayNG
<small>
Android APK
</small>
</a>


<a
class="download"
href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box"
target="_blank"
rel="noopener"
>
V2Box Android
<small>
Google Play
</small>
</a>


<a
class="download"
href="https://apps.apple.com/app/happ-proxy-utility/id6504287215"
target="_blank"
rel="noopener"
>
Happ
<small>
iPhone / iPad
</small>
</a>


<a
class="download"
href="https://apps.apple.com/app/v2box-v2ray-client/id6446814690"
target="_blank"
rel="noopener"
>
V2Box
<small>
iPhone / iPad
</small>
</a>


<a
class="download"
href="https://apps.apple.com/app/streisand/id6450534064"
target="_blank"
rel="noopener"
>
Streisand
<small>
iPhone / iPad
</small>
</a>


<a
class="download"
href="https://apps.apple.com/app/foxray/id6448898396"
target="_blank"
rel="noopener"
>
FoXray
<small>
iPhone / iPad
</small>
</a>


<a
class="download"
href="https://github.com/2dust/v2rayN/releases/latest"
target="_blank"
rel="noopener"
>
v2rayN
<small>
Windows
</small>
</a>


<a
class="download"
href="https://happ-proxy.com/"
target="_blank"
rel="noopener"
>
Happ
<small>
Windows
</small>
</a>


</div>


<div class="system-notice">

<strong>
آپدیت برنامه اتصال
</strong>

<br>

برای بهترین سازگاری، پایداری و عملکرد،
برنامه اتصال خود را همیشه به آخرین نسخه
بروزرسانی کنید.

</div>


</div>

</div>


<!-- ======================================================
MANUAL MODAL
====================================================== -->

<div
id="manualModal"
class="modal-bg"
>

<div class="modal">

<div class="modal-head">

<div
id="manualTitle"
class="modal-title"
>
ساخت کانفیگ
</div>

<button
class="close"
id="manualClose"
>
×
</button>

</div>


<div class="fields">


<div class="field">

<label>
نام
</label>

<input
id="fName"
placeholder="نام کانفیگ"
/>

</div>


<div class="field">

<label>
پروتکل
</label>

<select id="fProtocol">

<option value="vless-ws">
VLESS WebSocket
</option>

<option value="xhttp-packet-up">
XHTTP Packet Up
</option>

<option value="xhttp-stream-up">
XHTTP Stream Up
</option>

<option value="xhttp-stream-one">
XHTTP Stream One
</option>

</select>

</div>


<div class="field">

<label>
حجم
</label>

<input
id="fVolume"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
واحد حجم
</label>

<select id="fVolumeUnit">

<option value="GB">
GB
</option>

<option value="MB">
MB
</option>

<option value="TB">
TB
</option>

</select>

</div>


<div class="field">

<label>
زمان
</label>

<input
id="fDays"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
IP Limit
</label>

<input
id="fIpLimit"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
Connection Limit
</label>

<input
id="fConnectionLimit"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
Speed MBIT
</label>

<input
id="fSpeed"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
Fingerprint
</label>

<select id="fFingerprint">

<option value="chrome">
Chrome
</option>

<option value="firefox">
Firefox
</option>

<option value="safari">
Safari
</option>

<option value="ios">
iOS
</option>

<option value="android">
Android
</option>

<option value="edge">
Edge
</option>

<option value="360">
360
</option>

<option value="qq">
QQ
</option>

<option value="random">
Random
</option>

<option value="randomized">
Randomized
</option>

</select>

</div>


<div class="field">

<label>
Fragment
</label>

<select id="fFragment">

<option value="off">
خاموش
</option>

<option value="safe">
Safe
</option>

<option value="balanced">
Balanced
</option>

<option value="aggressive">
Aggressive
</option>

</select>

</div>


<div class="field">

<label>
Port
</label>

<input
id="fPort"
type="number"
min="1"
max="65535"
value="443"
/>

</div>


<div class="field">

<label>
ALPN
</label>

<input
id="fAlpn"
value="http/1.1"
/>

</div>


<div class="field full">

<label>
یادداشت
</label>

<textarea
id="fNote"
placeholder="یادداشت"
></textarea>

</div>


<div class="field full">

<label>
اطلاعیه اختصاصی این کانفیگ
</label>

<textarea
id="fNotice"
placeholder="این متن در صفحه INFO بالای اطلاعیه سیستم نمایش داده می‌شود."
></textarea>

</div>


</div>


<div class="modal-actions">

<button
class="modal-btn"
id="manualCancel"
>
انصراف
</button>

<button
class="modal-btn primary"
id="manualSave"
>
ذخیره
</button>

</div>

</div>

</div>


<!-- ======================================================
AUTO MODAL
====================================================== -->

<div
id="autoModal"
class="modal-bg"
>

<div class="modal">

<div class="modal-head">

<div class="modal-title">
ساخت خودکار
</div>

<button
class="close"
id="autoClose"
>
×
</button>

</div>


<div
style="
color:rgba(255,255,255,.56);
font-size:8px;
line-height:2;
"
>

نام:
<b>
pxpanel_********
</b>

<br>

Volume:
<b>
Unlimited
</b>

<br>

Time:
<b>
Unlimited
</b>

<br>

IP:
<b>
Unlimited
</b>

<br>

Speed:
<b>
Unlimited
</b>

<br>

Connection:
<b>
Unlimited
</b>

<br>

Protocol:
<b>
VLESS WebSocket
</b>

<br>

Port:
<b>
443
</b>

<br>

Path:
<b>
/ws/UUID
</b>

</div>


<div class="modal-actions">

<button
class="modal-btn"
id="autoCancel"
>
انصراف
</button>

<button
class="modal-btn primary"
id="autoConfirm"
>
ساخت
</button>

</div>

</div>

</div>


<!-- ======================================================
PASSWORD
====================================================== -->

<div
id="passwordModal"
class="modal-bg"
>

<div class="modal">

<div class="modal-head">

<div class="modal-title">
تغییر رمز
</div>

<button
class="close"
id="passwordClose"
>
×
</button>

</div>


<div class="fields">


<div class="field full">

<label>
رمز فعلی
</label>

<input
id="currentPassword"
type="password"
/>

</div>


<div class="field">

<label>
رمز جدید
</label>

<input
id="newPassword"
type="password"
/>

</div>


<div class="field">

<label>
تکرار رمز جدید
</label>

<input
id="repeatPassword"
type="password"
/>

</div>


</div>


<div class="modal-actions">

<button
class="modal-btn"
id="passwordCancel"
>
انصراف
</button>

<button
class="modal-btn primary"
id="passwordSave"
>
ذخیره
</button>

</div>

</div>

</div>


<!-- ======================================================
NEWS
====================================================== -->

<div
id="newsModal"
class="modal-bg"
>

<div class="modal">

<div class="modal-head">

<div class="modal-title">
اطلاعیه مهم
</div>

<button
class="close"
id="newsClose"
>
×
</button>

</div>


<div class="news-box">

<div
id="newsTitle"
class="news-title"
>
در حال دریافت...
</div>

<div class="news-version">
PixonPanel · __APP_VERSION__
</div>

<div
id="newsText"
class="news-message"
>
لطفاً صبر کنید...
</div>

</div>


<div class="modal-actions">

<button
class="modal-btn primary"
id="newsOk"
>
متوجه شدم
</button>

</div>

</div>

</div>


<div
id="toast"
class="toast"
>
</div>


<script>

/* =========================================================
HELPERS
========================================================= */

const $ = (
    id
) =>
    document.getElementById(
        id
    );


let editingUuid =
    null;


let latestLinks = [];


function escapeHtml(
    value
){

    return String(
        value ?? ""
    )

    .replaceAll(
        "&",
        "&amp;"
    )

    .replaceAll(
        "<",
        "&lt;"
    )

    .replaceAll(
        ">",
        "&gt;"
    )

    .replaceAll(
        '"',
        "&quot;"
    )

    .replaceAll(
        "'",
        "&#039;"
    );

}


function formatBytes(
    value
){

    value =
        Number(
            value || 0
        );


    if(
        value < 1024
    ){

        return (
            value +
            " B"
        );

    }


    if(
        value <
        1024 ** 2
    ){

        return (
            (
                value /
                1024
            ).toFixed(1)
            +
            " KB"
        );

    }


    if(
        value <
        1024 ** 3
    ){

        return (
            (
                value /
                1024 ** 2
            ).toFixed(2)
            +
            " MB"
        );

    }


    return (
        (
            value /
            1024 ** 3
        ).toFixed(2)
        +
        " GB"
    );

}


function showToast(
    message
){

    const element =
        $("toast");


    element.textContent =
        message;


    element.classList.add(
        "show"
    );


    clearTimeout(
        window.__toastTimer
    );


    window.__toastTimer =
        setTimeout(
            () => {

                element.classList.remove(
                    "show"
                );

            },

            2200
        );

}


/* =========================================================
API
========================================================= */

async function api(
    url,
    options = {}
){

    try{

        const response =
            await fetch(
                url,
                {
                    cache:
                        "no-store",

                    credentials:
                        "same-origin",

                    ...options
                }
            );


        if(
            response.status ===
            401
        ){

            location.href =
                "/login";

            return null;

        }


        let data;

        try{

            data =
                await response.json();

        }catch{

            data = {
                ok:false,
                error:
                    "پاسخ نامعتبر از سرور"
            };

        }


        if(
            !response.ok
        ){

            showToast(
                data.detail ||
                data.error ||
                "خطای سرور"
            );

            console.error(
                "API ERROR:",
                url,
                data
            );

            return null;

        }


        return data;

    }catch(error){

        console.error(
            "FETCH ERROR:",
            url,
            error
        );

        showToast(
            "ارتباط با سرور برقرار نشد"
        );

        return null;

    }

}


/* =========================================================
MODAL
========================================================= */

function openModal(
    id
){

    $(id)
        .classList
        .add(
            "open"
        );

}


function closeModal(
    id
){

    $(id)
        .classList
        .remove(
            "open"
        );

}


/* =========================================================
FORM
========================================================= */

function clearForm(){

    $("fName").value =
        "";

    $("fProtocol").value =
        "vless-ws";

    $("fVolume").value =
        "";

    $("fVolumeUnit").value =
        "GB";

    $("fDays").value =
        "";

    $("fIpLimit").value =
        "";

    $("fConnectionLimit").value =
        "";

    $("fSpeed").value =
        "";

    $("fFingerprint").value =
        "chrome";

    $("fFragment").value =
        "off";

    $("fPort").value =
        "443";

    $("fAlpn").value =
        "http/1.1";

    $("fNote").value =
        "";

    $("fNotice").value =
        "";

}


function fillForm(
    data
){

    $("fName").value =
        data.label || "";


    $("fProtocol").value =
        data.protocol ||
        "vless-ws";


    $("fVolume").value =
        data.limit_bytes
        ? (
            data.limit_bytes /
            1024 /
            1024 /
            1024
        ).toFixed(2)
        : "";


    $("fVolumeUnit").value =
        "GB";


    $("fDays").value =
        "";


    $("fIpLimit").value =
        data.ip_limit || "";


    $("fConnectionLimit").value =
        data.connection_limit || "";


    $("fSpeed").value =
        data.speed_limit_bytes
        ? (
            data.speed_limit_bytes *
            8 /
            1024 /
            1024
        ).toFixed(2)
        : "";


    $("fFingerprint").value =
        data.fingerprint ||
        "chrome";


    $("fFragment").value =
        data.fragment ||
        "off";


    $("fPort").value =
        data.port ||
        443;


    $("fAlpn").value =
        data.alpn ||
        "http/1.1";


    $("fNote").value =
        data.note ||
        "";


    $("fNotice").value =
        data.notice ||
        "";

}


/* =========================================================
AUTO
========================================================= */

$("autoBtn")
    .addEventListener(
        "click",
        () => {

            openModal(
                "autoModal"
            );

        }
    );


$("autoClose")
    .addEventListener(
        "click",
        () =>
            closeModal(
                "autoModal"
            )
    );


$("autoCancel")
    .addEventListener(
        "click",
        () =>
            closeModal(
                "autoModal"
            )
    );


$("autoConfirm")
    .addEventListener(
        "click",
        async () => {

            closeModal(
                "autoModal"
            );


            showToast(
                "در حال ساخت..."
            );


            const result =
                await api(
                    "/api/links/auto",
                    {
                        method:
                            "POST"
                    }
                );


            if(
                !result
            ){
                return;
            }


            if(
                result.vless
            ){

                await copyText(
                    result.vless
                );

            }


            showToast(
                "کانفیگ ساخته شد"
            );


            refresh();

        }
    );


/* =========================================================
MANUAL CREATE
========================================================= */

$("manualBtn")
    .addEventListener(
        "click",
        () => {

            editingUuid =
                null;

            clearForm();

            $("manualTitle")
                .textContent =
                "ساخت کانفیگ";

            openModal(
                "manualModal"
            );

        }
    );


$("manualClose")
    .addEventListener(
        "click",
        () =>
            closeModal(
                "manualModal"
            )
    );


$("manualCancel")
    .addEventListener(
        "click",
        () =>
            closeModal(
                "manualModal"
            )
    );


$("manualSave")
    .addEventListener(
        "click",
        async () => {

            const body = {

                label:
                    $("fName")
                        .value
                        .trim()
                    ||
                    "کانفیگ جدید",

                protocol:
                    $("fProtocol")
                        .value,

                limit_value:
                    Number(
                        $("fVolume")
                            .value
                        || 0
                    ),

                limit_unit:
                    $("fVolumeUnit")
                        .value,

                expires_days:
                    Number(
                        $("fDays")
                            .value
                        || 0
                    ),

                ip_limit:
                    Number(
                        $("fIpLimit")
                            .value
                        || 0
                    ),

                connection_limit:
                    Number(
                        $("fConnectionLimit")
                            .value
                        || 0
                    ),

                speed_limit_value:
                    Number(
                        $("fSpeed")
                            .value
                        || 0
                    ),

                speed_limit_unit:
                    "MBIT",

                fingerprint:
                    $("fFingerprint")
                        .value,

                fragment:
                    $("fFragment")
                        .value,

                port:
                    Number(
                        $("fPort")
                            .value
                        || 443
                    ),

                alpn:
                    $("fAlpn")
                        .value,

                note:
                    $("fNote")
                        .value,

                notice:
                    $("fNotice")
                        .value
            };


            let result;


            if(
                editingUuid
            ){

                result =
                    await api(
                        "/api/links/" +
                        encodeURIComponent(
                            editingUuid
                        ),
                        {
                            method:
                                "PATCH",

                            headers:{
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify(
                                    body
                                )
                        }
                    );

            }else{

                result =
                    await api(
                        "/api/links",
                        {
                            method:
                                "POST",

                            headers:{
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify(
                                    body
                                )
                        }
                    );

            }


            if(
                !result
            ){
                return;
            }


            const wasEditing =
                Boolean(
                    editingUuid
                );


            closeModal(
                "manualModal"
            );


            if(
                result.vless
            ){

                await copyText(
                    result.vless
                );

            }


            editingUuid =
                null;


            showToast(
                wasEditing
                ? "کانفیگ ویرایش شد"
                : "کانفیگ ساخته شد"
            );


            refresh();

        }
    );


/* =========================================================
EDIT
========================================================= */

async function editLink(
    uuid
){

    const result =
        await api(
            "/api/links/" +
            encodeURIComponent(
                uuid
            ) +
            "/info"
        );


    if(
        !result
    ){
        return;
    }


    editingUuid =
        uuid;


    fillForm(
        result
    );


    $("manualTitle")
        .textContent =
        "ویرایش کانفیگ";


    openModal(
        "manualModal"
    );

}


/* =========================================================
COPY
========================================================= */

async function copyText(
    text
){

    if(
        !text
    ){
        return;
    }


    try{

        await navigator
            .clipboard
            .writeText(
                text
            );

        showToast(
            "کپی شد"
        );

    }catch{

        const area =
            document.createElement(
                "textarea"
            );

        area.value =
            text;

        document.body.appendChild(
            area
        );

        area.select();

        document.execCommand(
            "copy"
        );

        area.remove();

        showToast(
            "کپی شد"
        );

    }

}


/* =========================================================
TOGGLE
========================================================= */

async function toggleLink(
    uuid,
    currentlyActive
){

    const result =
        await api(
            "/api/links/" +
            encodeURIComponent(
                uuid
            ),
            {
                method:
                    "PATCH",

                headers:{
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        active:
                            !currentlyActive
                    })
            }
        );


    if(
        result
    ){

        showToast(
            currentlyActive
            ? "کانفیگ غیرفعال شد"
            : "کانفیگ فعال شد"
        );

        refresh();

    }

}


/* =========================================================
RESET
========================================================= */

async function resetLink(
    uuid
){

    const result =
        await api(
            "/api/links/" +
            encodeURIComponent(
                uuid
            ) +
            "/reset-usage",
            {
                method:
                    "POST"
            }
        );


    if(
        result
    ){

        showToast(
            "مصرف ریست شد"
        );

        refresh();

    }

}


/* =========================================================
DELETE
========================================================= */

async function deleteLink(
    uuid
){

    if(
        !confirm(
            "این کانفیگ حذف شود؟"
        )
    ){
        return;
    }


    const result =
        await api(
            "/api/links/" +
            encodeURIComponent(
                uuid
            ),
            {
                method:
                    "DELETE"
            }
        );


    if(
        result
    ){

        showToast(
            "کانفیگ حذف شد"
        );

        refresh();

    }

}


/* =========================================================
INFO
========================================================= */

function openInfo(
    url
){

    if(
        !url
    ){
        return;
    }


    window.open(
        url,
        "_blank",
        "noopener,noreferrer"
    );

}


/* =========================================================
ROW RENDER
========================================================= */

function renderLinks(
    links
){

    latestLinks =
        links || [];


    const table =
        $("linksTable");


    table.innerHTML =
        "";


    if(
        !latestLinks.length
    ){

        table.innerHTML = `
            <tr>
                <td
                colspan="8"
                class="empty"
                >
                کانفیگی وجود ندارد
                </td>
            </tr>
        `;

        return;
    }


    for(
        const link
        of latestLinks
    ){

        const row =
            document.createElement(
                "tr"
            );


        const limit =
            Number(
                link.limit_bytes ||
                0
            );


        const used =
            Number(
                link.used_bytes ||
                0
            );


        const usage =
            limit > 0

            ? (
                formatBytes(
                    used
                )
                +
                " / "
                +
                formatBytes(
                    limit
                )
            )

            : (
                formatBytes(
                    used
                )
                +
                " / ∞"
            );


        row.innerHTML = `

<td>

<div style="font-weight:700">
${escapeHtml(
    link.label
)}
</div>

<div
style="
margin-top:3px;
color:rgba(255,255,255,.2);
font-size:6px;
"
>
${escapeHtml(
    link.uuid
)}
</div>

</td>


<td>
${escapeHtml(
    link.protocol
)}
</td>


<td>

<span class="
    badge
    ${
        link.active
        ? "active"
        : "off"
    }
">

${
    link.active
    ? "فعال"
    : "غیرفعال"
}

</span>

</td>


<td>
${escapeHtml(
    usage
)}
</td>


<td>
${
    link.expires_at
    ? escapeHtml(
        link.expires_at
    )
    : "∞"
}
</td>


<td>
${Number(
    link.connected_ips ||
    0
)}
</td>


<td>

<div
class="url"
title="${escapeHtml(
    link.vless
)}"
>
${escapeHtml(
    link.vless
)}
</div>

</td>


<td>

<div class="actions">

<button
class="action primary btn-copy-vless"
>
VLESS
</button>

<button
class="action btn-copy-sub"
>
SUB
</button>

<button
class="action btn-info"
>
INFO
</button>

<button
class="action btn-edit"
>
ویرایش
</button>

<button
class="action btn-reset"
>
ریست
</button>

<button
class="action ${
    link.active
    ? "red"
    : "green"
} btn-toggle"
>
${
    link.active
    ? "خاموش"
    : "فعال"
}
</button>

<button
class="action red btn-delete"
>
حذف
</button>

</div>

</td>

`;


        /*
         * IMPORTANT:
         * No inline onclick.
         * Every button receives
         * its own event listener.
         */


        row.querySelector(
            ".btn-copy-vless"
        ).addEventListener(
            "click",
            () =>
                copyText(
                    link.vless
                )
        );


        row.querySelector(
            ".btn-copy-sub"
        ).addEventListener(
            "click",
            () =>
                copyText(
                    link.sub
                )
        );


        row.querySelector(
            ".btn-info"
        ).addEventListener(
            "click",
            () =>
                openInfo(
                    link.info
                )
        );


        row.querySelector(
            ".btn-edit"
        ).addEventListener(
            "click",
            () =>
                editLink(
                    link.uuid
                )
        );


        row.querySelector(
            ".btn-reset"
        ).addEventListener(
            "click",
            () =>
                resetLink(
                    link.uuid
                )
        );


        row.querySelector(
            ".btn-toggle"
        ).addEventListener(
            "click",
            () =>
                toggleLink(
                    link.uuid,
                    link.active
                )
        );


        row.querySelector(
            ".btn-delete"
        ).addEventListener(
            "click",
            () =>
                deleteLink(
                    link.uuid
                )
        );


        table.appendChild(
            row
        );

    }

}


/* =========================================================
REFRESH
========================================================= */

async function refresh(){

    const results =
        await Promise.all([
            api(
                "/stats"
            ),

            api(
                "/api/links"
            ),

            api(
                "/api/activity"
            ),
        ]);


    const statsData =
        results[0];

    const linksData =
        results[1];

    const activity =
        results[2];


    if(
        statsData
    ){

        $("statLinks")
            .textContent =
            statsData.links_count;


        $("statActive")
            .textContent =
            statsData.active_links;


        $("statConnections")
            .textContent =
            statsData.active_connections;


        $("statTraffic")
            .textContent =
            formatBytes(
                statsData.total_traffic_bytes
            );


        $("statRequests")
            .textContent =
            statsData.total_requests;


        $("statUptime")
            .textContent =
            statsData.uptime;

    }


    if(
        linksData
    ){

        renderLinks(
            linksData.links
        );

    }


    if(
        activity
        &&
        activity.logs
    ){

        $("logs")
            .textContent =
            activity.logs
                .slice()
                .reverse()
                .map(
                    item =>
                        `[${item.level}] ${item.message}`
                )
                .join(
                    "\n"
                )
                ||
                "فعالیتی ثبت نشده است";

    }

}


/* =========================================================
PASSWORD
========================================================= */

$("passwordBtn")
    .addEventListener(
        "click",
        () =>
            openModal(
                "passwordModal"
            )
    );


$("passwordClose")
    .addEventListener(
        "click",
        () =>
            closeModal(
                "passwordModal"
            )
    );


$("passwordCancel")
    .addEventListener(
        "click",
        () =>
            closeModal(
                "passwordModal"
            )
    );


$("passwordSave")
    .addEventListener(
        "click",
        async () => {

            const result =
                await api(
                    "/api/change-password",
                    {
                        method:
                            "POST",

                        headers:{
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify({

                                current_password:
                                    $("currentPassword")
                                        .value,

                                new_password:
                                    $("newPassword")
                                        .value,

                                repeat_password:
                                    $("repeatPassword")
                                        .value

                            })
                    }
                );


            if(
                result
            ){

                closeModal(
                    "passwordModal"
                );


                $("currentPassword")
                    .value = "";

                $("newPassword")
                    .value = "";

                $("repeatPassword")
                    .value = "";


                showToast(
                    "رمز تغییر کرد"
                );

            }

        }
    );


/* =========================================================
NEWS
========================================================= */

async function loadNews(
    open = false
){

    const data =
        await api(
            "/api/news"
        );


    if(
        !data
    ){
        return;
    }


    if(
        data.enabled
        &&
        data.message
    ){

        $("newsTitle")
            .textContent =
            data.title ||
            "اطلاعیه مهم";


        $("newsText")
            .innerHTML =
            escapeHtml(
                data.message
            )
            .replaceAll(
                "\n",
                "<br>"
            );


        if(
            open
        ){

            openModal(
                "newsModal"
            );

        }

    }else{

        $("newsTitle")
            .textContent =
            "اطلاعیه‌ای وجود ندارد";


        $("newsText")
            .textContent =
            "";

    }

}


$("newsBtn")
    .addEventListener(
        "click",
        () =>
            loadNews(
                true
            )
    );


$("newsClose")
    .addEventListener(
        "click",
        () =>
            closeModal(
                "newsModal"
            )
    );


$("newsOk")
    .addEventListener(
        "click",
        () =>
            closeModal(
                "newsModal"
            )
    );


/* =========================================================
REFRESH BUTTON
========================================================= */

$("refreshBtn")
    .addEventListener(
        "click",
        refresh
    );


/* =========================================================
START
========================================================= */

refresh();


/*
 * Every 1 second
 */
setInterval(
    refresh,
    1000
);


/*
 * Open important news after login.
 */
loadNews(
    true
);

</script>

</body>

</html>
"""


# Inject only static placeholder.
# Dashboard stays raw string, so JavaScript {}
# can never be interpreted by Python.
DASHBOARD_HTML = (
    DASHBOARD_HTML
    .replace(
        "__APP_VERSION__",
        APP_VERSION,
    )
)


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

    await ensure_default_link()

    return HTMLResponse(
        DASHBOARD_HTML
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status":
            "ok",

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "connections":
            len(
                connections
            ),

        "uptime":
            uptime(),
    }


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


    if (
        request.url.path.startswith(
            "/api/"
        )
        or request.url.path
        in {
            "/stats",
        }
    ):

        return JSONResponse(
            {
                "ok":
                    False,

                "error":
                    str(exc)
                    or
                    "internal server error",
            },

            status_code=500,
        )


    return HTMLResponse(
        """
        <html lang="fa" dir="rtl">

        <body style="
            margin:0;
            background:#07070a;
            color:#fff;
            font-family:sans-serif;
            padding:40px;
        ">

        <h2>
        خطای داخلی PixonPanel
        </h2>

        <p>
        درخواست قابل پردازش نیست.
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

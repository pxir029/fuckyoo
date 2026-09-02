import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, parse_qs

import aiofiles
import uvicorn

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response


# ============================================================
# PixonPanel
# ============================================================

APP_NAME = "PixonPanel"
APP_VERSION = "12.0"

SUPPORT_USERNAME = "@Pixonal"
SUPPORT_URL = "https://t.me/Pixonal"

PORT = int(os.environ.get("PORT", "8000"))

DATA_DIR = Path(
    os.environ.get(
        "RAILWAY_VOLUME_MOUNT_PATH",
        os.environ.get("DATA_DIR", "./data")
    )
)

DATA_DIR.mkdir(parents=True, exist_ok=True)

DATA_FILE = DATA_DIR / "pixonpanel_state.json"
SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"

SESSION_COOKIE = "pixonpanel_session"
SESSION_TTL = 60 * 60 * 24 * 365

DEFAULT_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "pxpanel2026"
)

DEFAULT_PROTOCOL = "vless-ws"
DEFAULT_FINGERPRINT = "chrome"
DEFAULT_PORT = 443


# ============================================================
# Logging
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger(APP_NAME)


# ============================================================
# App
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
# Locks
# ============================================================

STATE_LOCK = asyncio.Lock()
SESSION_LOCK = asyncio.Lock()
ACTIVITY_LOCK = asyncio.Lock()


# ============================================================
# Runtime
# ============================================================

START_TIME = time.time()

TOTAL_REQUESTS = 0
TOTAL_BYTES = 0
TOTAL_ERRORS = 0

LINKS = {}
SESSIONS = {}

ACTIVITY_LOG = deque(maxlen=300)
ERROR_LOG = deque(maxlen=100)

# اگر Relay واقعی بعداً وصل شود
ACTIVE_CONNECTIONS = {}

# ============================================================
# Protocols / options
# ============================================================

PROTOCOLS = [
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
]

FINGERPRINTS = [
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
]

FRAGMENTS = {
    "off": None,

    "safe":
        "packets=1-3;length=1-1;interval=10-20",

    "balanced":
        "packets=1-3,10-20;length=1-1;interval=10-20",

    "aggressive":
        "packets=1-3,10-20;length=1-2;interval=5-15",
}


# ============================================================
# Secret
# ============================================================

def load_or_create_secret():

    env_secret = os.environ.get(
        "SECRET_KEY"
    )

    if env_secret:
        return env_secret

    try:

        if SECRET_FILE.exists():

            value = SECRET_FILE.read_text(
                encoding="utf-8"
            ).strip()

            if value:
                return value

        value = secrets.token_urlsafe(
            48
        )

        SECRET_FILE.write_text(
            value,
            encoding="utf-8"
        )

        return value

    except Exception as exc:

        logger.warning(
            "Could not persist secret: %s",
            exc
        )

        return secrets.token_urlsafe(
            48
        )


SECRET_KEY = load_or_create_secret()


# ============================================================
# Password
# ============================================================

def hash_password(password: str):

    raw = (
        str(password)
        + SECRET_KEY
    ).encode("utf-8")

    return hashlib.sha256(
        raw
    ).hexdigest()


AUTH = {
    "password_hash":
        hash_password(
            DEFAULT_PASSWORD
        )
}


# ============================================================
# Helpers
# ============================================================

def now_iso():
    return datetime.now().isoformat()


def safe_int(value, default=0):

    try:
        return int(value)
    except Exception:
        return default


def safe_float(value, default=0.0):

    try:
        return float(value)
    except Exception:
        return default


def generate_uuid():

    raw = secrets.token_hex(16)

    return (
        f"{raw[:8]}-"
        f"{raw[8:12]}-"
        f"{raw[12:16]}-"
        f"{raw[16:20]}-"
        f"{raw[20:32]}"
    )


def generate_auto_name():

    chars = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "23456789"
    )

    suffix = "".join(
        secrets.choice(chars)
        for _ in range(6)
    )

    return f"pxpanel_{suffix}"


def format_bytes(value):

    value = max(
        0,
        safe_int(value)
    )

    if value < 1024:
        return f"{value} B"

    if value < 1024 ** 2:
        return f"{value / 1024:.2f} KB"

    if value < 1024 ** 3:
        return f"{value / 1024 ** 2:.2f} MB"

    if value < 1024 ** 4:
        return f"{value / 1024 ** 3:.2f} GB"

    return f"{value / 1024 ** 4:.2f} TB"


def format_uptime(seconds):

    seconds = max(
        0,
        safe_int(seconds)
    )

    days = seconds // 86400

    hours = (
        seconds % 86400
    ) // 3600

    minutes = (
        seconds % 3600
    ) // 60

    secs = seconds % 60

    base = (
        f"{hours:02d}:"
        f"{minutes:02d}:"
        f"{secs:02d}"
    )

    if days:
        return f"{days}d {base}"

    return base


def parse_size(
    value,
    unit
):

    number = safe_float(value)

    if number <= 0:
        return 0

    unit = str(
        unit or "GB"
    ).upper()

    if unit == "MB":
        return int(
            number
            * 1024
            * 1024
        )

    if unit == "GB":
        return int(
            number
            * 1024
            * 1024
            * 1024
        )

    if unit == "TB":
        return int(
            number
            * 1024
            * 1024
            * 1024
            * 1024
        )

    return int(number)


def parse_speed(
    value,
    unit
):

    number = safe_float(value)

    if number <= 0:
        return 0

    unit = str(
        unit or "MBIT"
    ).upper()

    if unit == "MBIT":

        return int(
            number
            * 1024
            * 1024
            / 8
        )

    if unit == "GBIT":

        return int(
            number
            * 1024
            * 1024
            * 1024
            / 8
        )

    if unit == "MB":

        return int(
            number
            * 1024
            * 1024
        )

    if unit == "KB":

        return int(
            number
            * 1024
        )

    return int(number)


def get_public_host(
    request: Request
):

    forwarded = request.headers.get(
        "x-forwarded-host"
    )

    if forwarded:
        return (
            forwarded
            .split(",")[0]
            .strip()
            .split(":")[0]
        )

    host = request.headers.get(
        "host"
    )

    if host:
        return host.split(":")[0]

    railway = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway:
        return railway

    return "localhost"


def client_ip(
    request: Request
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
        return real

    if request.client:
        return request.client.host

    return "unknown"


def escape_html(
    value
):

    return (
        str(value or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


# ============================================================
# Activity
# ============================================================

async def add_activity(
    message,
    level="info",
    kind="system"
):

    async with ACTIVITY_LOCK:

        ACTIVITY_LOG.append({
            "time": now_iso(),
            "message": message,
            "level": level,
            "kind": kind,
        })


# ============================================================
# Persistence
# ============================================================

async def save_state():

    async with STATE_LOCK:

        payload = {
            "links": LINKS,
            "password_hash":
                AUTH["password_hash"],
            "saved_at":
                now_iso(),
        }

        temp_file = (
            DATA_FILE.with_suffix(".tmp")
        )

        try:

            async with aiofiles.open(
                temp_file,
                "w",
                encoding="utf-8"
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
                "save_state failed"
            )

            ERROR_LOG.append({
                "time": now_iso(),
                "error": str(exc),
            })


async def load_state():

    if not DATA_FILE.exists():
        return

    try:

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            raw = await file.read()

        payload = json.loads(
            raw
        )

        LINKS.clear()

        LINKS.update(
            payload.get(
                "links",
                {}
            )
        )

        stored_password = payload.get(
            "password_hash"
        )

        if stored_password:

            AUTH[
                "password_hash"
            ] = stored_password

    except Exception as exc:

        logger.exception(
            "load_state failed"
        )


# ============================================================
# Sessions
# ============================================================

async def create_session():

    token = secrets.token_urlsafe(
        48
    )

    async with SESSION_LOCK:

        SESSIONS[
            token
        ] = (
            time.time()
            + SESSION_TTL
        )

    return token


async def valid_session(
    token
):

    if not token:
        return False

    async with SESSION_LOCK:

        expires = SESSIONS.get(
            token
        )

        if expires is None:
            return False

        if expires < time.time():

            SESSIONS.pop(
                token,
                None
            )

            return False

        return True


async def destroy_session(
    token
):

    if not token:
        return

    async with SESSION_LOCK:

        SESSIONS.pop(
            token,
            None
        )


async def require_auth(
    request: Request
):

    token = request.cookies.get(
        SESSION_COOKIE
    )

    if not await valid_session(
        token
    ):

        raise HTTPException(
            status_code=401,
            detail="unauthorized"
        )

    return token


# ============================================================
# Link state
# ============================================================

def is_expired(
    link
):

    expires = link.get(
        "expires_at"
    )

    if not expires:
        return False

    try:

        return (
            datetime.now()
            >= datetime.fromisoformat(
                expires
            )
        )

    except Exception:

        return False


def is_active(
    link
):

    if not link.get(
        "active",
        True
    ):
        return False

    if is_expired(
        link
    ):
        return False

    limit = safe_int(
        link.get(
            "limit_bytes",
            0
        )
    )

    used = safe_int(
        link.get(
            "used_bytes",
            0
        )
    )

    if (
        limit > 0
        and used >= limit
    ):
        return False

    return True


def connection_count(
    uuid
):

    return sum(
        1
        for item
        in ACTIVE_CONNECTIONS.values()
        if item.get(
            "uuid"
        ) == uuid
    )


def current_ips(
    uuid
):

    return {
        item.get("ip")
        for item
        in ACTIVE_CONNECTIONS.values()
        if (
            item.get("uuid")
            == uuid
            and item.get("ip")
        )
    }


def can_accept_connection(
    uuid,
    ip
):

    link = LINKS.get(
        uuid
    )

    if not link:
        return False

    if not is_active(
        link
    ):
        return False

    limit = safe_int(
        link.get(
            "concurrent_limit",
            0
        )
    )

    if (
        limit > 0
        and
        connection_count(
            uuid
        ) >= limit
    ):

        return False

    ip_limit = safe_int(
        link.get(
            "ip_limit",
            0
        )
    )

    if ip_limit > 0:

        ips = current_ips(
            uuid
        )

        if (
            ip not in ips
            and len(ips)
            >= ip_limit
        ):

            return False

    return True


# ============================================================
# VLESS
# ============================================================

def build_vless(
    uid,
    link,
    host
):

    protocol = link.get(
        "protocol",
        DEFAULT_PROTOCOL
    )

    if protocol not in PROTOCOLS:

        protocol = DEFAULT_PROTOCOL

    fingerprint = link.get(
        "fingerprint",
        DEFAULT_FINGERPRINT
    )

    if (
        fingerprint
        not in FINGERPRINTS
    ):

        fingerprint = DEFAULT_FINGERPRINT

    port = safe_int(
        link.get(
            "port",
            DEFAULT_PORT
        ),
        DEFAULT_PORT
    )

    if not (
        1
        <= port
        <= 65535
    ):

        port = DEFAULT_PORT

    alpn = (
        link.get(
            "alpn",
            ""
        )
        or (
            "http/1.1"
            if protocol == "vless-ws"
            else "h2,http/1.1"
        )
    )

    params = {
        "encryption":
            "none",
        "security":
            "tls",
        "sni":
            host,
        "fp":
            fingerprint,
        "alpn":
            alpn,
    }

    if protocol == "vless-ws":

        params.update({

            "type":
                "ws",

            "host":
                host,

            "path":
                f"/ws/{uid}",
        })

    else:

        mode = protocol.replace(
            "xhttp-",
            ""
        )

        params.update({

            "type":
                "xhttp",

            "mode":
                mode,

            "host":
                host,

            "path":
                (
                    f"/xhttp-siz10/"
                    f"{mode}/"
                    f"{uid}"
                ),
        })

    fragment = link.get(
        "fragment"
    )

    if fragment:

        params[
            "fragment"
        ] = fragment

    query = "&".join(
        (
            f"{key}="
            f"{quote(str(value), safe='')}"
        )

        for key, value
        in params.items()

        if value is not None
        and str(value) != ""
    )

    remark = (
        link.get(
            "label",
            APP_NAME
        )
        or APP_NAME
    )

    return (
        f"vless://"
        f"{uid}@"
        f"{host}:"
        f"{port}?"
        f"{query}#"
        f"{quote(remark)}"
    )


def serialize_link(
    uid,
    link,
    host
):

    used = safe_int(
        link.get(
            "used_bytes",
            0
        )
    )

    limit = safe_int(
        link.get(
            "limit_bytes",
            0
        )
    )

    percentage = (
        0
        if limit <= 0
        else min(
            100,
            round(
                (
                    used
                    / limit
                )
                * 100,
                1
            )
        )
    )

    return {

        "uuid":
            uid,

        **link,

        "expired":
            is_expired(
                link
            ),

        "online":
            is_active(
                link
            ),

        "connections":
            connection_count(
                uid
            ),

        "usage_percent":
            percentage,

        "used_fmt":
            format_bytes(
                used
            ),

        "limit_fmt":
            (
                "نامحدود"
                if limit <= 0
                else format_bytes(
                    limit
                )
            ),

        "vless_link":
            build_vless(
                uid,
                link,
                host
            ),

        "sub_url":
            (
                f"https://"
                f"{host}/sub/"
                f"{uid}"
            ),

        "info_url":
            (
                f"https://"
                f"{host}/info/"
                f"{uid}"
            ),
    }


# ============================================================
# Automatic config
# ============================================================

@app.post(
    "/api/links/auto"
)
async def create_auto(
    request: Request,
    _=Depends(require_auth)
):

    global TOTAL_REQUESTS

    TOTAL_REQUESTS += 1

    uid = generate_uuid()

    link = {

        "label":
            generate_auto_name(),

        "limit_bytes":
            0,

        "used_bytes":
            0,

        "duration_days":
            0,

        "expires_at":
            None,

        "active":
            True,

        "protocol":
            "vless-ws",

        "fingerprint":
            "chrome",

        "fragment":
            None,

        "fragment_profile":
            "off",

        "alpn":
            "http/1.1",

        "port":
            443,

        "concurrent_limit":
            0,

        "ip_limit":
            0,

        "speed_limit_bytes":
            0,

        "note":
            "Auto generated by PixonPanel",

        "created_at":
            now_iso(),

        "updated_at":
            now_iso(),

        "is_default":
            False,
    }

    LINKS[
        uid
    ] = link

    await save_state()

    await add_activity(
        (
            f"کانفیگ خودکار "
            f"«{link['label']}» "
            "ساخته شد"
        ),
        "ok",
        "link"
    )

    host = get_public_host(
        request
    )

    return {
        "ok":
            True,

        **serialize_link(
            uid,
            link,
            host
        )
    }


# ============================================================
# Manual create
# ============================================================

@app.post(
    "/api/links/manual"
)
async def create_manual(
    request: Request,
    _=Depends(require_auth)
):

    global TOTAL_REQUESTS

    TOTAL_REQUESTS += 1

    data = await request.json()

    label = str(
        data.get(
            "label",
            ""
        )
    ).strip()

    if not label:

        raise HTTPException(
            status_code=400,
            detail=
                "نام کانفیگ الزامی است."
        )

    volume_value = safe_float(
        data.get(
            "volume_value",
            0
        )
    )

    volume_unit = str(
        data.get(
            "volume_unit",
            "GB"
        )
    )

    days = max(
        0,
        safe_int(
            data.get(
                "duration_days",
                0
            )
        )
    )

    concurrent = max(
        0,
        safe_int(
            data.get(
                "concurrent_limit",
                0
            )
        )
    )

    ip_limit = max(
        0,
        safe_int(
            data.get(
                "ip_limit",
                0
            )
        )
    )

    speed = parse_speed(
        data.get(
            "speed_limit_value",
            0
        ),
        data.get(
            "speed_limit_unit",
            "MBIT"
        )
    )

    protocol = str(
        data.get(
            "protocol",
            DEFAULT_PROTOCOL
        )
    )

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        data.get(
            "fingerprint",
            DEFAULT_FINGERPRINT
        )
    ).lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    fragment_key = str(
        data.get(
            "fragment",
            "off"
        )
    )

    if fragment_key not in FRAGMENTS:
        fragment_key = "off"

    try:
        port = int(
            data.get(
                "port",
                DEFAULT_PORT
            )
        )
    except Exception:
        port = DEFAULT_PORT

    if not (
        1
        <= port
        <= 65535
    ):
        port = DEFAULT_PORT

    if days > 0:

        expires_at = (
            datetime.now()
            + timedelta(
                days=days
            )
        ).isoformat()

    else:

        expires_at = None

    uid = generate_uuid()

    link = {

        "label":
            label[:80],

        "limit_bytes":
            parse_size(
                volume_value,
                volume_unit
            ),

        "used_bytes":
            0,

        "duration_days":
            days,

        "expires_at":
            expires_at,

        "active":
            True,

        "protocol":
            protocol,

        "fingerprint":
            fingerprint,

        "fragment":
            FRAGMENTS[
                fragment_key
            ],

        "fragment_profile":
            fragment_key,

        "alpn":
            str(
                data.get(
                    "alpn",
                    ""
                )
            )[:100],

        "port":
            port,

        "concurrent_limit":
            concurrent,

        "ip_limit":
            ip_limit,

        "speed_limit_bytes":
            speed,

        "note":
            str(
                data.get(
                    "note",
                    ""
                )
            )[:300],

        "created_at":
            now_iso(),

        "updated_at":
            now_iso(),

        "is_default":
            False,
    }

    LINKS[
        uid
    ] = link

    await save_state()

    await add_activity(
        (
            f"کانفیگ دستی "
            f"«{label}» "
            "ساخته شد"
        ),
        "ok",
        "link"
    )

    host = get_public_host(
        request
    )

    return {
        "ok":
            True,

        **serialize_link(
            uid,
            link,
            host
        )
    }


# ============================================================
# List
# ============================================================

@app.get(
    "/api/links"
)
async def list_links(
    request: Request,
    _=Depends(require_auth)
):

    host = get_public_host(
        request
    )

    result = [

        serialize_link(
            uid,
            link,
            host
        )

        for uid, link
        in LINKS.items()
    ]

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                ""
            ),
        reverse=True
    )

    return {
        "links":
            result
    }


# ============================================================
# Update
# ============================================================

@app.patch(
    "/api/links/{uid}"
)
async def update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth)
):

    if uid not in LINKS:

        raise HTTPException(
            status_code=404,
            detail=
                "کانفیگ پیدا نشد."
        )

    data = await request.json()

    link = LINKS[
        uid
    ]

    if "label" in data:

        label = str(
            data.get(
                "label",
                ""
            )
        ).strip()

        if label:
            link[
                "label"
            ] = label[:80]

    if "active" in data:

        link[
            "active"
        ] = bool(
            data[
                "active"
            ]
        )

    if "protocol" in data:

        protocol = str(
            data.get(
                "protocol"
            )
        )

        if protocol in PROTOCOLS:

            link[
                "protocol"
            ] = protocol

    if "fingerprint" in data:

        fingerprint = str(
            data.get(
                "fingerprint"
            )
        ).lower()

        if fingerprint in FINGERPRINTS:

            link[
                "fingerprint"
            ] = fingerprint

    if "fragment" in data:

        key = str(
            data.get(
                "fragment"
            )
        )

        if key in FRAGMENTS:

            link[
                "fragment_profile"
            ] = key

            link[
                "fragment"
            ] = FRAGMENTS[
                key
            ]

    if "volume_value" in data:

        link[
            "limit_bytes"
        ] = parse_size(
            data.get(
                "volume_value",
                0
            ),
            data.get(
                "volume_unit",
                "GB"
            )
        )

    if "duration_days" in data:

        days = max(
            0,
            safe_int(
                data.get(
                    "duration_days",
                    0
                )
            )
        )

        link[
            "duration_days"
        ] = days

        if days:

            link[
                "expires_at"
            ] = (
                datetime.now()
                + timedelta(
                    days=days
                )
            ).isoformat()

        else:

            link[
                "expires_at"
            ] = None

    if "concurrent_limit" in data:

        link[
            "concurrent_limit"
        ] = max(
            0,
            safe_int(
                data.get(
                    "concurrent_limit",
                    0
                )
            )
        )

    if "ip_limit" in data:

        link[
            "ip_limit"
        ] = max(
            0,
            safe_int(
                data.get(
                    "ip_limit",
                    0
                )
            )
        )

    if "speed_limit_value" in data:

        link[
            "speed_limit_bytes"
        ] = parse_speed(
            data.get(
                "speed_limit_value",
                0
            ),
            data.get(
                "speed_limit_unit",
                "MBIT"
            )
        )

    if "port" in data:

        port = safe_int(
            data.get(
                "port",
                443
            ),
            443
        )

        if (
            1
            <= port
            <= 65535
        ):

            link[
                "port"
            ] = port

    if "alpn" in data:

        link[
            "alpn"
        ] = str(
            data.get(
                "alpn",
                ""
            )
        )[:100]

    if "note" in data:

        link[
            "note"
        ] = str(
            data.get(
                "note",
                ""
            )
        )[:300]

    link[
        "updated_at"
    ] = now_iso()

    await save_state()

    await add_activity(
        (
            f"کانفیگ "
            f"«{link['label']}» "
            "ویرایش شد"
        ),
        "info",
        "link"
    )

    return {
        "ok":
            True,

        **serialize_link(
            uid,
            link,
            get_public_host(request)
        )
    }


# ============================================================
# Delete
# ============================================================

@app.delete(
    "/api/links/{uid}"
)
async def delete_link(
    uid: str,
    _=Depends(require_auth)
):

    link = LINKS.get(
        uid
    )

    if not link:

        raise HTTPException(
            status_code=404,
            detail=
                "کانفیگ پیدا نشد."
        )

    if link.get(
        "is_default"
    ):

        raise HTTPException(
            status_code=400,
            detail=
                "کانفیگ پیش‌فرض حذف نمی‌شود."
        )

    name = link.get(
        "label",
        uid
    )

    LINKS.pop(
        uid,
        None
    )

    await save_state()

    await add_activity(
        (
            f"کانفیگ "
            f"«{name}» "
            "حذف شد"
        ),
        "warn",
        "link"
    )

    return {
        "ok":
            True
    }


# ============================================================
# Reset Usage
# ============================================================

@app.post(
    "/api/links/{uid}/reset"
)
async def reset_usage(
    uid: str,
    _=Depends(require_auth)
):

    if uid not in LINKS:

        raise HTTPException(
            status_code=404,
            detail=
                "کانفیگ پیدا نشد."
        )

    LINKS[
        uid
    ][
        "used_bytes"
    ] = 0

    LINKS[
        uid
    ][
        "updated_at"
    ] = now_iso()

    await save_state()

    await add_activity(
        (
            f"مصرف کانفیگ "
            f"«{LINKS[uid]['label']}» "
            "ریست شد"
        ),
        "info",
        "traffic"
    )

    return {
        "ok":
            True
    }


# ============================================================
# Subscription
# ============================================================

@app.get(
    "/sub/{uid}"
)
async def subscription(
    uid: str,
    request: Request
):

    link = LINKS.get(
        uid
    )

    if not link:

        raise HTTPException(
            status_code=404,
            detail="not found"
        )

    if not is_active(
        link
    ):

        raise HTTPException(
            status_code=404,
            detail="inactive"
        )

    host = get_public_host(
        request
    )

    vless = build_vless(
        uid,
        link,
        host
    )

    encoded = (
        base64.b64encode(
            vless.encode()
        )
        .decode()
    )

    used = safe_int(
        link.get(
            "used_bytes",
            0
        )
    )

    total = safe_int(
        link.get(
            "limit_bytes",
            0
        )
    )

    return Response(

        content=encoded,

        media_type="text/plain",

        headers={

            "profile-title":
                quote(
                    link.get(
                        "label",
                        APP_NAME
                    )
                ),

            "profile-update-interval":
                "1",

            "support-url":
                SUPPORT_URL,

            "subscription-userinfo":
                (
                    "upload=0;"
                    f"download={used};"
                    f"total={total}"
                ),

            "x-pixonpanel-info":
                (
                    f"https://"
                    f"{host}/info/{uid}"
                ),
        }
    )


# ============================================================
# Info
# ============================================================

@app.get(
    "/info/{uid}",
    response_class=HTMLResponse
)
async def info_page(
    uid: str
):

    link = LINKS.get(
        uid
    )

    if not link:

        return HTMLResponse(
            """
            <h2
                style="
                    font-family:Tahoma;
                    padding:40px;
                    background:#07070a;
                    color:white;
                    min-height:100vh;
                "
            >
                کانفیگ پیدا نشد
            </h2>
            """,
            status_code=404
        )

    return HTMLResponse(
        build_info_html(
            uid,
            link
        )
    )


def build_info_html(
    uid,
    link
):

    used = safe_int(
        link.get(
            "used_bytes",
            0
        )
    )

    limit = safe_int(
        link.get(
            "limit_bytes",
            0
        )
    )

    connections = (
        connection_count(
            uid
        )
    )

    percent = (
        0
        if limit <= 0
        else min(
            100,
            round(
                used
                / limit
                * 100,
                1
            )
        )
    )

    if link.get(
        "expires_at"
    ):

        expiry = escape_html(
            link[
                "expires_at"
            ]
        )

    else:

        expiry = "بدون انقضا"

    return f"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1"
/>

<title>
{escape_html(
    link.get(
        "label",
        APP_NAME
    )
)}
</title>

<link
    rel="preconnect"
    href="https://fonts.googleapis.com"
/>

<link
    rel="preconnect"
    href="https://fonts.gstatic.com"
    crossorigin
/>

<link
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
    rel="stylesheet"
/>

<style>

* {{
    box-sizing:border-box;
}}

body {{

    margin:0;

    min-height:100vh;

    padding:20px;

    color:white;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.18),
            transparent 32%
        ),
        #07070a;
}}

.container {{

    width:100%;

    max-width:760px;

    margin:auto;
}}

.card {{

    border-radius:28px;

    padding:25px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.045);

    backdrop-filter:
        blur(28px);

    box-shadow:
        0 40px 100px
        rgba(0,0,0,.42);
}}

.logo {{

    width:46px;
    height:46px;

    border-radius:15px;

    display:flex;

    align-items:center;
    justify-content:center;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight:900;

    margin-bottom:17px;
}}

h1 {{

    margin:0;

    font-size:22px;
}}

.meta {{

    margin-top:4px;

    color:
        rgba(255,255,255,.38);

    font-size:10px;
}}

.stats {{

    display:grid;

    grid-template-columns:
        repeat(
            2,
            1fr
        );

    gap:10px;

    margin-top:20px;
}}

.item {{

    padding:14px;

    border-radius:15px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(255,255,255,.03);
}}

.item-title {{

    color:
        rgba(255,255,255,.35);

    font-size:9px;
}}

.item-value {{

    margin-top:5px;

    font-size:12px;

    font-weight:800;

    word-break:break-word;
}}

.progress-wrap {{

    margin-top:18px;
}}

.progress-head {{

    display:flex;

    justify-content:space-between;

    color:
        rgba(255,255,255,.40);

    font-size:9px;
}}

.progress {{

    margin-top:7px;

    height:8px;

    border-radius:99px;

    overflow:hidden;

    background:
        rgba(255,255,255,.07);
}}

.fill {{

    width:{percent}%;

    height:100%;

    border-radius:inherit;

    background:
        linear-gradient(
            90deg,
            #6366f1,
            #8b5cf6
        );
}}

.section {{

    margin-top:18px;

    padding-top:17px;

    border-top:
        1px solid
        rgba(255,255,255,.07);
}}

.title {{

    margin-bottom:9px;

    font-size:12px;

    font-weight:800;
}}

.linkbox {{

    padding:12px;

    border-radius:12px;

    direction:ltr;

    text-align:left;

    color:
        #c4b5fd;

    background:
        rgba(0,0,0,.20);

    border:
        1px solid
        rgba(255,255,255,.07);

    word-break:break-all;

    font-family:
        Consolas,
        monospace;

    font-size:9px;
}}

.notice {{

    color:
        rgba(255,255,255,.58);

    line-height:2;

    font-size:10px;

    padding:15px;

    border-radius:15px;

    background:
        rgba(255,255,255,.03);

    border:
        1px solid
        rgba(255,255,255,.06);
}}

.apps {{

    display:grid;

    grid-template-columns:
        repeat(
            2,
            1fr
        );

    gap:7px;

    margin-top:10px;
}}

.app {{

    color:
        rgba(255,255,255,.72);

    text-decoration:none;

    padding:10px;

    border-radius:11px;

    background:
        rgba(255,255,255,.035);

    border:
        1px solid
        rgba(255,255,255,.06);

    font-size:9px;
}}

.support {{

    margin-top:18px;

    padding-top:17px;

    border-top:
        1px solid
        rgba(255,255,255,.07);

    text-align:center;

    color:
        rgba(255,255,255,.38);

    font-size:10px;
}}

.support a {{

    color:#a78bfa;

    text-decoration:none;
}}

@media(max-width:600px) {{

    .stats {{
        grid-template-columns:1fr;
    }}

    .apps {{
        grid-template-columns:1fr;
    }}

}}

</style>

</head>

<body>

<div class="container">

<div class="card">

<div class="logo">
P
</div>

<h1>
{escape_html(
    link.get(
        "label",
        APP_NAME
    )
)}
</h1>

<div class="meta">
PixonPanel · اطلاعات سرویس
</div>

<div class="progress-wrap">

<div class="progress-head">

<span>
مصرف
</span>

<span>
{format_bytes(used)}
/
{
    "نامحدود"
    if limit <= 0
    else format_bytes(limit)
}
</span>

</div>

<div class="progress">
<div class="fill"></div>
</div>

</div>

<div class="stats">

<div class="item">
<div class="item-title">
Protocol
</div>
<div class="item-value">
{escape_html(
    link.get(
        "protocol",
        "-"
    )
)}
</div>
</div>

<div class="item">
<div class="item-title">
Fingerprint
</div>
<div class="item-value">
{escape_html(
    link.get(
        "fingerprint",
        "-"
    )
)}
</div>
</div>

<div class="item">
<div class="item-title">
Fragment
</div>
<div class="item-value">
{escape_html(
    link.get(
        "fragment_profile",
        "off"
    )
)}
</div>
</div>

<div class="item">
<div class="item-title">
اتصال همزمان
</div>
<div class="item-value">
{connections}
/
{
    link.get(
        "concurrent_limit",
        0
    )
    or "∞"
}
</div>
</div>

<div class="item">
<div class="item-title">
محدودیت IP
</div>
<div class="item-value">
{
    link.get(
        "ip_limit",
        0
    )
    or "∞"
}
</div>
</div>

<div class="item">
<div class="item-title">
تاریخ انقضا
</div>
<div class="item-value">
{expiry}
</div>
</div>

</div>

<div class="section">

<div class="title">
SUB
</div>

<div class="linkbox">
/sub/{uid}
</div>

</div>

<div class="section">

<div class="title">
📢 اطلاعیه مهم | آپدیت برنامه اتصال
</div>

<div class="notice">

دوستان عزیز ❤️

<br><br>

برای اینکه کانفیگ‌های جدید
<strong>
بهترین سازگاری، پایداری و عملکرد
</strong>
رو داشته باشن، لطفاً برنامه‌ای که برای اتصال استفاده می‌کنید رو به
<strong>
آخرین نسخه
</strong>
آپدیت کنید. 🔄⚡️

<br><br>

<strong>
📱 Android
</strong>

<div class="apps">

<a
    class="app"
    href="https://play.google.com/store/apps/details?id=com.happproxy"
    target="_blank"
>
Happ
</a>

<a
    class="app"
    href="https://dl.v2rayng.org/releases/latest/v2rayNG_2.2.6_arm64-v8a.apk"
    target="_blank"
>
v2rayNG
</a>

<a
    class="app"
    href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box"
    target="_blank"
>
V2Box
</a>

</div>

<br>

<strong>
🍎 iPhone / iPad
</strong>

<div class="apps">

<a
    class="app"
    href="https://apps.apple.com/app/happ-proxy-utility/id6504287215"
    target="_blank"
>
Happ
</a>

<a
    class="app"
    href="https://apps.apple.com/app/v2box-v2ray-client/id6446814690"
    target="_blank"
>
V2Box
</a>

<a
    class="app"
    href="https://apps.apple.com/app/streisand/id6450534064"
    target="_blank"
>
Streisand
</a>

<a
    class="app"
    href="https://apps.apple.com/app/foxray/id6448898396"
    target="_blank"
>
FoXray
</a>

</div>

<br>

<strong>
💻 Windows
</strong>

<div class="apps">

<a
    class="app"
    href="https://github.com/2dust/v2rayN/releases/latest"
    target="_blank"
>
v2rayN
</a>

<a
    class="app"
    href="https://happ-proxy.com/"
    target="_blank"
>
Happ
</a>

</div>

<br><br>

⚠️ اگر از نسخه قدیمی برنامه استفاده می‌کنید،
قبل از استفاده از کانفیگ‌های جدید، برنامه را آپدیت کنید.

<br><br>

❤️ آپدیت کنید تا بهترین تجربه اتصال را داشته باشید.

</div>

</div>

<div class="support">

پشتیبانی:

<a
    href="{SUPPORT_URL}"
    target="_blank"
>
{SUPPORT_USERNAME}
</a>

</div>

</div>

</div>

</body>

</html>
"""


# ============================================================
# Stats
# ============================================================

@app.get(
    "/api/stats"
)
async def stats_api(
    _=Depends(require_auth)
):

    global TOTAL_REQUESTS

    TOTAL_REQUESTS += 1

    used = sum(
        safe_int(
            link.get(
                "used_bytes",
                0
            )
        )
        for link
        in LINKS.values()
    )

    return {

        "links":
            len(
                LINKS
            ),

        "active_links":
            sum(
                1
                for link
                in LINKS.values()
                if is_active(
                    link
                )
            ),

        "expired_links":
            sum(
                1
                for link
                in LINKS.values()
                if is_expired(
                    link
                )
            ),

        "connections":
            len(
                ACTIVE_CONNECTIONS
            ),

        "usage":
            used,

        "usage_fmt":
            format_bytes(
                used
            ),

        "requests":
            TOTAL_REQUESTS,

        "errors":
            TOTAL_ERRORS,

        "uptime_seconds":
            int(
                time.time()
                - START_TIME
            ),

        "uptime":
            format_uptime(
                time.time()
                - START_TIME
            ),

        "server_time":
            now_iso(),

        "version":
            APP_VERSION,
    }


@app.get(
    "/api/activity"
)
async def activity_api(
    _=Depends(require_auth)
):

    async with ACTIVITY_LOCK:

        values = list(
            ACTIVITY_LOG
        )

    values.reverse()

    return {
        "items":
            values
    }


# ============================================================
# Change password
# ============================================================

@app.post(
    "/api/change-password"
)
async def change_password(
    request: Request,
    _=Depends(require_auth)
):

    data = await request.json()

    current = str(
        data.get(
            "current_password",
            ""
        )
    )

    new = str(
        data.get(
            "new_password",
            ""
        )
    )

    confirm = str(
        data.get(
            "confirm_password",
            ""
        )
    )

    if not current:

        raise HTTPException(
            status_code=400,
            detail=
                "رمز فعلی را وارد کنید."
        )

    if not new:

        raise HTTPException(
            status_code=400,
            detail=
                "رمز جدید را وارد کنید."
        )

    if new != confirm:

        raise HTTPException(
            status_code=400,
            detail=
                "تکرار رمز جدید مطابقت ندارد."
        )

    if len(new) < 8:

        raise HTTPException(
            status_code=400,
            detail=
                "رمز جدید باید حداقل ۸ کاراکتر باشد."
        )

    if (
        hash_password(current)
        != AUTH[
            "password_hash"
        ]
    ):

        raise HTTPException(
            status_code=400,
            detail=
                "رمز فعلی اشتباه است."
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new
    )

    await save_state()

    await add_activity(
        "رمز عبور مدیریت تغییر کرد",
        "ok",
        "security"
    )

    return {
        "ok":
            True
    }


# ============================================================
# Landing
# ============================================================

LANDING_HTML = r"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>
PixonPanel
</title>

<link
    rel="preconnect"
    href="https://fonts.googleapis.com"
/>

<link
    rel="preconnect"
    href="https://fonts.gstatic.com"
    crossorigin
/>

<link
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
    rel="stylesheet"
/>

<style>

* {
    box-sizing:border-box;
}

body {

    margin:0;

    min-height:100vh;

    display:flex;

    align-items:center;
    justify-content:center;

    padding:20px;

    color:#fff;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 15% 10%,
            rgba(99,102,241,.20),
            transparent 32%
        ),
        radial-gradient(
            circle at 85% 90%,
            rgba(168,85,247,.14),
            transparent 32%
        ),
        #07070a;
}

.card {

    width:100%;

    max-width:560px;

    padding:32px;

    border-radius:30px;

    border:
        1px solid
        rgba(255,255,255,.09);

    background:
        rgba(255,255,255,.045);

    backdrop-filter:
        blur(30px);

    box-shadow:
        0 40px 100px
        rgba(0,0,0,.45);
}

.logo {

    width:50px;
    height:50px;

    display:flex;

    align-items:center;
    justify-content:center;

    border-radius:16px;

    margin-bottom:20px;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight:900;
}

.status {

    display:inline-flex;

    padding:
        7px 10px;

    border-radius:999px;

    color:#86efac;

    background:
        rgba(34,197,94,.07);

    border:
        1px solid
        rgba(34,197,94,.13);

    font-size:10px;

    margin-bottom:15px;
}

h1 {

    margin:0;

    font-size:29px;

    line-height:1.5;

    font-weight:900;
}

p {

    color:
        rgba(255,255,255,.53);

    line-height:2;

    font-size:13px;

    margin-top:10px;
}

.command {

    margin-top:20px;

    padding:14px;

    border-radius:15px;

    background:
        rgba(0,0,0,.18);

    border:
        1px solid
        rgba(255,255,255,.07);

    color:#c4b5fd;

    direction:ltr;

    text-align:left;

    font-family:
        Consolas,
        monospace;
}

.buttons {

    display:flex;

    gap:9px;

    margin-top:18px;
}

.button {

    flex:1;

    padding:13px;

    border-radius:14px;

    text-decoration:none;

    text-align:center;

    font-weight:800;

    font-size:11px;
}

.primary {

    color:white;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.secondary {

    color:
        rgba(255,255,255,.75);

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);
}

.footer {

    display:flex;

    justify-content:
        space-between;

    margin-top:18px;

    padding-top:16px;

    border-top:
        1px solid
        rgba(255,255,255,.07);

    color:
        rgba(255,255,255,.28);

    font-size:9px;
}

.support {

    color:#a78bfa;

    text-decoration:none;
}

@media(max-width:600px) {

    .card {
        padding:24px;
    }

    h1 {
        font-size:24px;
    }

    .buttons {
        flex-direction:column;
    }

}

</style>

</head>

<body>

<div class="card">

<div class="logo">
P
</div>

<div class="status">
● سیستم آنلاین است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<p>
این صفحه عمومی PixonPanel است.
برای دسترسی به مدیریت سرویس، وارد بخش ورود شوید.
</p>

<div class="command">
/login
</div>

<div class="buttons">

<a
    href="/login"
    class="button primary"
>
ورود به پنل
</a>

<a
    href="https://t.me/Pixonal"
    target="_blank"
    class="button secondary"
>
پشتیبانی
</a>

</div>

<div class="footer">

<span>
PixonPanel
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
    response_class=HTMLResponse
)
async def root(
    request: Request
):

    if await valid_session(
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
# Login
# ============================================================

LOGIN_HTML = r"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>
ورود | PixonPanel
</title>

<link
    rel="preconnect"
    href="https://fonts.googleapis.com"
/>

<link
    rel="preconnect"
    href="https://fonts.gstatic.com"
    crossorigin
/>

<link
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
    rel="stylesheet"
/>

<style>

* {
    box-sizing:border-box;
}

body {

    margin:0;

    min-height:100vh;

    display:flex;

    align-items:center;
    justify-content:center;

    padding:20px;

    color:white;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.18),
            transparent 32%
        ),
        #07070a;
}

.card {

    width:100%;

    max-width:420px;

    padding:30px;

    border-radius:26px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.045);

    backdrop-filter:
        blur(28px);

    box-shadow:
        0 40px 90px
        rgba(0,0,0,.45);
}

.logo {

    width:49px;
    height:49px;

    display:flex;

    align-items:center;
    justify-content:center;

    border-radius:15px;

    margin-bottom:20px;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight:900;
}

h1 {

    margin:0;

    font-size:24px;
}

.desc {

    color:
        rgba(255,255,255,.44);

    font-size:11px;

    line-height:2;

    margin-top:8px;
}

form {

    margin-top:20px;
}

label {

    display:block;

    margin-bottom:7px;

    color:
        rgba(255,255,255,.50);

    font-size:10px;
}

input {

    width:100%;

    padding:13px;

    border-radius:13px;

    border:
        1px solid
        rgba(255,255,255,.08);

    outline:none;

    color:white;

    background:
        rgba(0,0,0,.18);

    font-family:
        "Vazirmatn",
        sans-serif;
}

input:focus {

    border-color:
        rgba(129,140,248,.55);
}

button {

    width:100%;

    margin-top:12px;

    padding:13px;

    border:0;

    border-radius:13px;

    color:white;

    cursor:pointer;

    font-family:
        "Vazirmatn",
        sans-serif;

    font-weight:800;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.error {

    margin-top:12px;

    padding:10px;

    border-radius:11px;

    color:#fca5a5;

    background:
        rgba(239,68,68,.07);

    border:
        1px solid
        rgba(239,68,68,.13);

    font-size:10px;
}

.support {

    display:block;

    text-align:center;

    margin-top:17px;

    color:#a78bfa;

    text-decoration:none;

    font-size:10px;
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

<div class="desc">
برای ورود به داشبورد مدیریت، رمز عبور را وارد کنید.
</div>

<form
    action="/login"
    method="post"
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
/>

<button>
ورود به پنل
</button>

</form>

<a
    class="support"
    href="https://t.me/Pixonal"
    target="_blank"
>
پشتیبانی @Pixonal
</a>

</div>

</body>

</html>
"""


@app.get(
    "/login",
    response_class=HTMLResponse
)
async def login_page(
    request: Request
):

    if await valid_session(
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


@app.post(
    "/login"
)
async def login(
    request: Request
):

    raw = await request.body()

    parsed = parse_qs(
        raw.decode(
            "utf-8",
            errors="ignore"
        )
    )

    password = (
        parsed
        .get(
            "password",
            [""]
        )[0]
        .strip()
    )

    if (
        hash_password(
            password
        )
        != AUTH[
            "password_hash"
        ]
    ):

        return HTMLResponse(
            LOGIN_HTML.replace(
                "</form>",
                """
                <div class="error">
                    رمز عبور اشتباه است.
                </div>
                </form>
                """
            ),
            status_code=401
        )

    token = await create_session()

    response = RedirectResponse(
        "/dashboard",
        status_code=303
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/"
    )

    await add_activity(
        "ورود موفق به پنل",
        "ok",
        "auth"
    )

    return response


@app.get(
    "/logout"
)
async def logout(
    request: Request
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
        path="/"
    )

    return response


# ============================================================
# Dashboard
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>
PixonPanel Dashboard
</title>

<link
    rel="preconnect"
    href="https://fonts.googleapis.com"
/>

<link
    rel="preconnect"
    href="https://fonts.gstatic.com"
    crossorigin
/>

<link
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
    rel="stylesheet"
/>

<style>

* {
    box-sizing:border-box;
}

html,
body {
    margin:0;
    min-height:100%;
}

body {

    min-height:100vh;

    color:white;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 5% 0%,
            rgba(99,102,241,.13),
            transparent 27%
        ),
        radial-gradient(
            circle at 100% 100%,
            rgba(168,85,247,.09),
            transparent 25%
        ),
        #07070a;
}

button,
input,
select,
textarea {
    font-family:
        "Vazirmatn",
        sans-serif;
}

button {
    cursor:pointer;
}

.app {

    width:
        min(
            1250px,
            calc(100% - 24px)
        );

    margin:auto;

    padding:
        20px 0 40px;
}

.topbar {

    display:flex;

    align-items:center;

    justify-content:space-between;

    gap:10px;

    margin-bottom:14px;
}

.brand {

    display:flex;

    align-items:center;

    gap:11px;
}

.logo {

    width:44px;
    height:44px;

    display:flex;

    align-items:center;
    justify-content:center;

    border-radius:14px;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight:900;
}

.brand-name {

    font-weight:900;
    font-size:15px;
}

.brand-sub {

    margin-top:3px;

    color:
        rgba(255,255,255,.34);

    font-size:9px;
}

.toolbar {

    display:flex;

    align-items:center;

    gap:6px;

    flex-wrap:wrap;

    justify-content:flex-end;
}

.toolbar-btn {

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.03);

    color:
        rgba(255,255,255,.72);

    border-radius:10px;

    padding:
        8px 11px;

    font-size:9px;
}

.toolbar-btn:hover {

    background:
        rgba(255,255,255,.07);
}

.grid {

    display:grid;

    grid-template-columns:
        repeat(
            4,
            1fr
        );

    gap:9px;
}

.stat {

    padding:15px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);

    border-radius:17px;
}

.stat-label {

    color:
        rgba(255,255,255,.35);

    font-size:9px;
}

.stat-value {

    margin-top:6px;

    font-size:21px;

    font-weight:900;
}

.stat-sub {

    margin-top:4px;

    color:
        rgba(255,255,255,.23);

    font-size:8px;
}

.panel {

    margin-top:10px;

    overflow:hidden;

    border:
        1px solid
        rgba(255,255,255,.08);

    border-radius:20px;

    background:
        rgba(255,255,255,.035);

    backdrop-filter:
        blur(18px);
}

.panel-head {

    padding:
        15px 16px;

    display:flex;

    align-items:center;

    justify-content:space-between;

    gap:10px;

    border-bottom:
        1px solid
        rgba(255,255,255,.06);
}

.panel-title {

    font-size:12px;

    font-weight:800;
}

.panel-sub {

    margin-top:3px;

    color:
        rgba(255,255,255,.27);

    font-size:8px;
}

.primary-btn {

    border:0;

    padding:
        9px 12px;

    border-radius:11px;

    color:white;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-size:9px;

    font-weight:800;
}

.table-scroll {

    overflow-x:auto;
}

table {

    width:100%;

    min-width:1100px;

    border-collapse:collapse;
}

th,
td {

    padding:
        11px 12px;

    text-align:right;

    border-bottom:
        1px solid
        rgba(255,255,255,.045);

    font-size:9px;
}

th {

    color:
        rgba(255,255,255,.27);

    font-weight:500;
}

.name {

    font-size:10px;

    font-weight:800;
}

.uuid {

    margin-top:3px;

    direction:ltr;

    text-align:right;

    color:
        rgba(255,255,255,.20);

    font-family:
        Consolas,
        monospace;

    font-size:7px;
}

.badge {

    display:inline-flex;

    padding:
        4px 7px;

    border-radius:999px;

    font-size:8px;
}

.badge.active {

    color:#86efac;

    background:
        rgba(34,197,94,.07);
}

.badge.off {

    color:#fca5a5;

    background:
        rgba(239,68,68,.07);
}

.usage {

    min-width:120px;
}

.usage-bar {

    height:6px;

    margin-top:6px;

    overflow:hidden;

    border-radius:999px;

    background:
        rgba(255,255,255,.06);
}

.usage-fill {

    width:var(--usage);

    height:100%;

    border-radius:inherit;

    background:
        linear-gradient(
            90deg,
            #6366f1,
            #8b5cf6
        );
}

.actions {

    display:flex;

    flex-wrap:wrap;

    gap:4px;
}

.action {

    padding:
        6px 8px;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:8px;

    background:
        rgba(255,255,255,.03);

    color:
        rgba(255,255,255,.75);

    font-size:7px;
}

.action:hover {

    background:
        rgba(255,255,255,.07);
}

.action.danger {

    color:#fca5a5;
}

.action.success {

    color:#86efac;
}

/* ---------------------------------------------------------
   Modal
--------------------------------------------------------- */

.modal {

    position:fixed;

    inset:0;

    z-index:5000;

    display:none;

    align-items:center;
    justify-content:center;

    padding:14px;

    background:
        rgba(0,0,0,.72);

    backdrop-filter:
        blur(14px);
}

.modal.show {
    display:flex;
}

.modal-card {

    width:100%;

    max-width:720px;

    max-height:
        calc(100vh - 20px);

    overflow:auto;

    border-radius:23px;

    border:
        1px solid
        rgba(255,255,255,.09);

    background:
        linear-gradient(
            145deg,
            rgba(24,24,31,.99),
            rgba(9,9,12,.99)
        );

    box-shadow:
        0 50px 120px
        rgba(0,0,0,.65);
}

.modal-head {

    padding:
        17px 18px;

    display:flex;

    justify-content:space-between;

    gap:10px;

    align-items:center;

    border-bottom:
        1px solid
        rgba(255,255,255,.06);
}

.modal-title {

    font-size:14px;

    font-weight:900;
}

.modal-desc {

    margin-top:3px;

    color:
        rgba(255,255,255,.30);

    font-size:8px;
}

.close {

    width:32px;
    height:32px;

    border:0;

    border-radius:10px;

    color:
        rgba(255,255,255,.65);

    background:
        rgba(255,255,255,.05);

    font-size:18px;
}

.form {

    display:grid;

    grid-template-columns:
        repeat(
            2,
            minmax(
                0,
                1fr
            )
        );

    gap:12px;

    padding:18px;
}

.field.full {

    grid-column:
        1 / -1;
}

.field label {

    display:block;

    margin-bottom:6px;

    color:
        rgba(255,255,255,.50);

    font-size:9px;
}

.input,
.select,
.textarea {

    width:100%;

    min-height:41px;

    padding:
        9px 10px;

    border:
        1px solid
        rgba(255,255,255,.08);

    border-radius:11px;

    outline:none;

    color:white;

    background:
        rgba(255,255,255,.04);

    font-size:9px;
}

.input:focus,
.select:focus,
.textarea:focus {

    border-color:
        rgba(129,140,248,.55);
}

.textarea {

    resize:vertical;

    min-height:80px;
}

.inline {

    display:flex;

    gap:5px;
}

.inline > *:first-child {

    flex:1;
}

.inline .select {

    width:90px;
}

.hint {

    margin-top:4px;

    color:
        rgba(255,255,255,.23);

    font-size:7px;
}

.modal-footer {

    display:flex;

    gap:7px;

    padding:
        14px 18px;

    border-top:
        1px solid
        rgba(255,255,255,.06);
}

.modal-btn {

    flex:1;

    min-height:41px;

    border:0;

    border-radius:11px;

    font-size:9px;

    font-weight:800;
}

.cancel {

    color:
        rgba(255,255,255,.65);

    background:
        rgba(255,255,255,.05);
}

.save {

    color:white;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.result {

    padding:
        18px;
}

.result-group {

    margin-bottom:13px;
}

.result-label {

    margin-bottom:6px;

    color:
        rgba(255,255,255,.35);

    font-size:8px;
}

.result-row {

    display:flex;

    gap:5px;
}

.result-input {

    flex:1;

    min-width:0;

    padding:
        10px;

    direction:ltr;

    text-align:left;

    color:#c4b5fd;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:10px;

    background:
        rgba(0,0,0,.20);

    outline:none;

    font-family:
        Consolas,
        monospace;

    font-size:8px;
}

.copy-btn {

    border:0;

    border-radius:10px;

    padding:
        0 11px;

    color:white;

    background:
        rgba(255,255,255,.07);

    font-size:8px;
}

.logs {

    max-height:250px;

    overflow:auto;

    padding:15px;
}

.log {

    display:flex;

    gap:9px;

    padding:8px 0;

    border-bottom:
        1px solid
        rgba(255,255,255,.04);
}

.log-time {

    color:
        rgba(255,255,255,.22);

    white-space:nowrap;

    font-size:7px;
}

.log-text {

    color:
        rgba(255,255,255,.55);

    font-size:8px;
}

.toast-wrap {

    position:fixed;

    left:16px;
    bottom:16px;

    z-index:10000;

    display:flex;

    flex-direction:column;

    gap:5px;
}

.toast {

    padding:
        10px 12px;

    border-radius:11px;

    background:
        rgba(17,24,39,.96);

    border:
        1px solid
        rgba(255,255,255,.08);

    box-shadow:
        0 20px 40px
        rgba(0,0,0,.38);

    font-size:8px;

    animation:
        toastIn .18s ease;
}

@keyframes toastIn {

    from {
        opacity:0;
        transform:
            translateY(7px);
    }

    to {
        opacity:1;
        transform:
            translateY(0);
    }
}

@media(max-width:800px) {

    .grid {
        grid-template-columns:
            repeat(
                2,
                1fr
            );
    }
}

@media(max-width:600px) {

    .app {
        width:
            calc(100% - 12px);
    }

    .grid {
        grid-template-columns:1fr;
    }

    .form {
        grid-template-columns:1fr;
    }

    .field.full {
        grid-column:auto;
    }

    .topbar {
        align-items:flex-start;
    }

}

</style>

</head>

<body>

<div class="app">

<div class="topbar">

<div class="brand">

<div class="logo">
P
</div>

<div>

<div class="brand-name">
PixonPanel
</div>

<div class="brand-sub">
پنل مدیریت سرویس
</div>

</div>

</div>


<div class="toolbar">

<button
    class="toolbar-btn"
    onclick="openAutoCreate()"
>
ساخت خودکار
</button>

<button
    class="toolbar-btn"
    onclick="openManualCreate()"
>
ساخت دستی
</button>

<button
    class="toolbar-btn"
    onclick="openPasswordModal()"
>
تغییر رمز
</button>

<a
    class="toolbar-btn"
    href="/logout"
>
خروج
</a>

</div>

</div>


<!-- ======================================================
     Stats
======================================================= -->

<div class="grid">

<div class="stat">

<div class="stat-label">
کل کانفیگ‌ها
</div>

<div
    class="stat-value"
    id="statLinks"
>
0
</div>

<div class="stat-sub">
تعداد سرویس‌ها
</div>

</div>


<div class="stat">

<div class="stat-label">
کانفیگ فعال
</div>

<div
    class="stat-value"
    id="statActive"
>
0
</div>

<div class="stat-sub">
در حال سرویس
</div>

</div>


<div class="stat">

<div class="stat-label">
اتصالات
</div>

<div
    class="stat-value"
    id="statConnections"
>
0
</div>

<div class="stat-sub">
اتصال همزمان
</div>

</div>


<div class="stat">

<div class="stat-label">
آپتایم
</div>

<div
    class="stat-value"
    id="statUptime"
>
00:00:00
</div>

<div
    class="stat-sub"
    id="statClock"
>
-
</div>

</div>

</div>


<!-- ======================================================
     Configs
======================================================= -->

<section class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
کانفیگ‌ها
</div>

<div class="panel-sub">
مدیریت کامل سرویس‌ها
</div>

</div>

<button
    class="primary-btn"
    onclick="openAutoCreate()"
>
+ ساخت خودکار
</button>

</div>


<div class="table-scroll">

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
اتصال
</th>

<th>
انقضا
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

</section>


<!-- ======================================================
     Activity
======================================================= -->

<section class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
فعالیت‌ها
</div>

<div class="panel-sub">
رویدادهای پنل
</div>

</div>

</div>

<div
    class="logs"
    id="logs"
>
در حال بارگذاری...
</div>

</section>

</div>


<!-- ======================================================
     Config Modal
======================================================= -->

<div
    class="modal"
    id="configModal"
>

<div class="modal-card">

<div class="modal-head">

<div>

<div
    class="modal-title"
    id="configModalTitle"
>
ساخت کانفیگ دستی
</div>

<div class="modal-desc">
تنظیمات کامل سرویس
</div>

</div>

<button
    class="close"
    onclick="closeConfigModal()"
>
×
</button>

</div>


<div class="form">


<div class="field full">

<label>
نام کانفیگ
</label>

<input
    id="fieldLabel"
    class="input"
    maxlength="80"
    placeholder="مثلاً VIP Tehran"
/>

</div>


<div class="field">

<label>
حجم
</label>

<div class="inline">

<input
    id="fieldVolume"
    class="input"
    type="number"
    min="0"
    step="0.1"
    placeholder="100"
/>

<select
    id="fieldVolumeUnit"
    class="select"
>

<option value="GB">
GB
</option>

<option value="MB">
MB
</option>

</select>

</div>

<div class="hint">
0 = نامحدود
</div>

</div>


<div class="field">

<label>
مدت اعتبار
</label>

<input
    id="fieldDays"
    class="input"
    type="number"
    min="0"
    placeholder="30"
/>

<div class="hint">
0 = بدون انقضا
</div>

</div>


<div class="field">

<label>
اتصال همزمان
</label>

<input
    id="fieldConcurrent"
    class="input"
    type="number"
    min="0"
    placeholder="2"
/>

<div class="hint">
0 = نامحدود
</div>

</div>


<div class="field">

<label>
محدودیت IP
</label>

<input
    id="fieldIp"
    class="input"
    type="number"
    min="0"
    placeholder="1"
/>

<div class="hint">
0 = بدون محدودیت
</div>

</div>


<div class="field">

<label>
Protocol
</label>

<select
    id="fieldProtocol"
    class="select"
>

<option value="vless-ws">
VLESS + WebSocket
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
Fragment
</label>

<select
    id="fieldFragment"
    class="select"
>

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
Fingerprint
</label>

<select
    id="fieldFingerprint"
    class="select"
>

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

<option value="random">
Random
</option>

</select>

</div>


<div class="field">

<label>
سرعت
</label>

<div class="inline">

<input
    id="fieldSpeed"
    class="input"
    type="number"
    min="0"
    step="0.1"
    placeholder="0"
/>

<select
    id="fieldSpeedUnit"
    class="select"
>

<option value="MBIT">
Mbit/s
</option>

<option value="GBIT">
Gbit/s
</option>

<option value="MB">
MB/s
</option>

<option value="KB">
KB/s
</option>

</select>

</div>

</div>


<div class="field">

<label>
Port
</label>

<input
    id="fieldPort"
    class="input"
    type="number"
    min="1"
    max="65535"
    value="443"
/>

</div>


<div class="field full">

<label>
ALPN
</label>

<input
    id="fieldAlpn"
    class="input"
    placeholder="http/1.1"
/>

</div>


<div class="field full">

<label>
توضیحات
</label>

<textarea
    id="fieldNote"
    class="textarea"
    placeholder="توضیحات اختیاری..."
></textarea>

</div>


</div>


<div class="modal-footer">

<button
    class="modal-btn cancel"
    onclick="closeConfigModal()"
>
انصراف
</button>

<button
    id="saveButton"
    class="modal-btn save"
    onclick="saveConfig()"
>
ساخت کانفیگ
</button>

</div>

</div>

</div>


<!-- ======================================================
     Result Modal
======================================================= -->

<div
    class="modal"
    id="resultModal"
>

<div
    class="modal-card"
    style="max-width:720px"
>

<div class="modal-head">

<div>

<div class="modal-title">
کانفیگ آماده شد
</div>

<div class="modal-desc">
VLESS / SUB / اطلاعات
</div>

</div>

<button
    class="close"
    onclick="closeResultModal()"
>
×
</button>

</div>

<div class="result">


<div class="result-group">

<div class="result-label">
VLESS
</div>

<div class="result-row">

<input
    id="resultVless"
    class="result-input"
    readonly
>

<button
    class="copy-btn"
    onclick="copyInput('resultVless')"
>
کپی
</button>

</div>

</div>


<div class="result-group">

<div class="result-label">
SUB
</div>

<div class="result-row">

<input
    id="resultSub"
    class="result-input"
    readonly
>

<button
    class="copy-btn"
    onclick="copyInput('resultSub')"
>
کپی
</button>

</div>

</div>


<div class="result-group">

<div class="result-label">
INFO
</div>

<div class="result-row">

<input
    id="resultInfo"
    class="result-input"
    readonly
>

<button
    class="copy-btn"
    onclick="copyInput('resultInfo')"
>
کپی
</button>

</div>

</div>

</div>

</div>

</div>


<!-- ======================================================
     Delete Modal
======================================================= -->

<div
    class="modal"
    id="deleteModal"
>

<div
    class="modal-card"
    style="max-width:430px"
>

<div class="modal-head">

<div>

<div class="modal-title">
حذف کانفیگ
</div>

<div class="modal-desc">
این عملیات قابل برگشت نیست
</div>

</div>

<button
    class="close"
    onclick="closeDeleteModal()"
>
×
</button>

</div>


<div
    style="
        padding:18px;
    "
>

<div
    style="
        color:
            rgba(255,255,255,.50);
        font-size:10px;
        line-height:2;
    "
>
آیا مطمئن هستید که می‌خواهید این کانفیگ را حذف کنید؟
</div>

<div
    id="deleteTarget"
    style="
        margin-top:10px;
        padding:11px;
        border-radius:10px;
        color:#fca5a5;
        background:
            rgba(239,68,68,.07);
        border:
            1px solid
            rgba(239,68,68,.12);
        font-size:9px;
    "
>
-
</div>

</div>


<div class="modal-footer">

<button
    class="modal-btn cancel"
    onclick="closeDeleteModal()"
>
انصراف
</button>

<button
    class="modal-btn"
    id="deleteButton"
    style="
        color:#fff;
        background:
            linear-gradient(
                135deg,
                #dc2626,
                #991b1b
            );
    "
    onclick="confirmDelete()"
>
حذف
</button>

</div>

</div>

</div>


<!-- ======================================================
     Password Modal
======================================================= -->

<div
    class="modal"
    id="passwordModal"
>

<div
    class="modal-card"
    style="max-width:430px"
>

<div class="modal-head">

<div>

<div class="modal-title">
تغییر رمز عبور
</div>

<div class="modal-desc">
رمز جدید حداقل ۸ کاراکتر
</div>

</div>

<button
    class="close"
    onclick="closePasswordModal()"
>
×
</button>

</div>


<div class="form">

<div class="field full">

<label>
رمز عبور فعلی
</label>

<input
    id="currentPassword"
    class="input"
    type="password"
    autocomplete="current-password"
/>

</div>


<div class="field full">

<label>
رمز عبور جدید
</label>

<input
    id="newPassword"
    class="input"
    type="password"
    autocomplete="new-password"
/>

</div>


<div class="field full">

<label>
تکرار رمز عبور جدید
</label>

<input
    id="confirmPassword"
    class="input"
    type="password"
    autocomplete="new-password"
/>

</div>

</div>


<div class="modal-footer">

<button
    class="modal-btn cancel"
    onclick="closePasswordModal()"
>
انصراف
</button>

<button
    class="modal-btn save"
    onclick="changePassword()"
>
ذخیره رمز
</button>

</div>

</div>

</div>


<div
    class="toast-wrap"
    id="toastWrap"
></div>


<script>

/* =========================================================
   State
========================================================= */

let editingUuid = null;
let deletingUuid = null;

let uptimeBase = null;


/* =========================================================
   API
========================================================= */

async function api(
    url,
    options = {}
) {

    const response =
        await fetch(
            url,
            options
        );

    if (
        response.status === 401
    ) {

        location.href =
            "/login";

        return null;
    }

    let data = {};

    try {

        data =
            await response.json();

    } catch {

        data = {};
    }


    if (!response.ok) {

        throw new Error(
            data.detail
            ||
            data.error
            ||
            "خطای ناشناخته"
        );
    }

    return data;
}


/* =========================================================
   Toast
========================================================= */

function toast(
    text,
    error = false
) {

    const element =
        document.createElement(
            "div"
        );

    element.className =
        "toast";

    if (error) {

        element.style.borderColor =
            "rgba(239,68,68,.25)";
    }

    element.textContent =
        text;

    document
        .getElementById(
            "toastWrap"
        )
        .appendChild(
            element
        );

    setTimeout(
        () => {

            element.style.opacity =
                "0";

            setTimeout(
                () => element.remove(),
                180
            );

        },
        2500
    );
}


/* =========================================================
   Config Modal
========================================================= */

function openManualCreate() {

    editingUuid =
        null;

    document.getElementById(
        "configModalTitle"
    ).textContent =
        "ساخت کانفیگ دستی";

    document.getElementById(
        "saveButton"
    ).textContent =
        "ساخت کانفیگ";

    resetForm();

    document.getElementById(
        "configModal"
    ).classList.add(
        "show"
    );
}


function openEdit(
    link
) {

    editingUuid =
        link.uuid;

    document.getElementById(
        "configModalTitle"
    ).textContent =
        "ویرایش کانفیگ";

    document.getElementById(
        "saveButton"
    ).textContent =
        "ذخیره تغییرات";


    document.getElementById(
        "fieldLabel"
    ).value =
        link.label || "";


    document.getElementById(
        "fieldVolume"
    ).value =
        link.limit_bytes
        ? (
            link.limit_bytes
            / (
                1024 ** 3
            )
        ).toFixed(2)
        : "";


    document.getElementById(
        "fieldVolumeUnit"
    ).value =
        "GB";


    document.getElementById(
        "fieldDays"
    ).value =
        link.duration_days
        || "";


    document.getElementById(
        "fieldConcurrent"
    ).value =
        link.concurrent_limit
        || "";


    document.getElementById(
        "fieldIp"
    ).value =
        link.ip_limit
        || "";


    document.getElementById(
        "fieldProtocol"
    ).value =
        link.protocol
        || "vless-ws";


    document.getElementById(
        "fieldFragment"
    ).value =
        link.fragment_profile
        || "off";


    document.getElementById(
        "fieldFingerprint"
    ).value =
        link.fingerprint
        || "chrome";


    document.getElementById(
        "fieldSpeed"
    ).value =
        link.speed_limit_bytes
        ? (
            link.speed_limit_bytes
            * 8
            / 1024
            / 1024
        ).toFixed(2)
        : "";


    document.getElementById(
        "fieldSpeedUnit"
    ).value =
        "MBIT";


    document.getElementById(
        "fieldPort"
    ).value =
        link.port
        || 443;


    document.getElementById(
        "fieldAlpn"
    ).value =
        link.alpn
        || "";


    document.getElementById(
        "fieldNote"
    ).value =
        link.note
        || "";


    document.getElementById(
        "configModal"
    ).classList.add(
        "show"
    );
}


function closeConfigModal() {

    document.getElementById(
        "configModal"
    ).classList.remove(
        "show"
    );
}


function resetForm() {

    document.getElementById(
        "fieldLabel"
    ).value = "";

    document.getElementById(
        "fieldVolume"
    ).value = "";

    document.getElementById(
        "fieldVolumeUnit"
    ).value = "GB";

    document.getElementById(
        "fieldDays"
    ).value = "";

    document.getElementById(
        "fieldConcurrent"
    ).value = "";

    document.getElementById(
        "fieldIp"
    ).value = "";

    document.getElementById(
        "fieldProtocol"
    ).value =
        "vless-ws";

    document.getElementById(
        "fieldFragment"
    ).value =
        "off";

    document.getElementById(
        "fieldFingerprint"
    ).value =
        "chrome";

    document.getElementById(
        "fieldSpeed"
    ).value = "";

    document.getElementById(
        "fieldSpeedUnit"
    ).value =
        "MBIT";

    document.getElementById(
        "fieldPort"
    ).value =
        "443";

    document.getElementById(
        "fieldAlpn"
    ).value = "";

    document.getElementById(
        "fieldNote"
    ).value = "";
}


/* =========================================================
   Auto Create
========================================================= */

async function openAutoCreate() {

    try {

        const result =
            await api(
                "/api/links/auto",
                {
                    method:
                        "POST"
                }
            );

        if (!result)
            return;

        showResult(
            result
        );

        toast(
            `${result.label} ساخته شد.`
        );

        await refreshLinks();
        await refreshStats();

    } catch (error) {

        toast(
            error.message,
            true
        );
    }
}


/* =========================================================
   Manual / Edit Save
========================================================= */

async function saveConfig() {

    const button =
        document.getElementById(
            "saveButton"
        );

    const payload = {

        label:
            document.getElementById(
                "fieldLabel"
            ).value.trim(),

        volume_value:
            Number(
                document.getElementById(
                    "fieldVolume"
                ).value || 0
            ),

        volume_unit:
            document.getElementById(
                "fieldVolumeUnit"
            ).value,

        duration_days:
            Number(
                document.getElementById(
                    "fieldDays"
                ).value || 0
            ),

        concurrent_limit:
            Number(
                document.getElementById(
                    "fieldConcurrent"
                ).value || 0
            ),

        ip_limit:
            Number(
                document.getElementById(
                    "fieldIp"
                ).value || 0
            ),

        protocol:
            document.getElementById(
                "fieldProtocol"
            ).value,

        fragment:
            document.getElementById(
                "fieldFragment"
            ).value,

        fingerprint:
            document.getElementById(
                "fieldFingerprint"
            ).value,

        speed_limit_value:
            Number(
                document.getElementById(
                    "fieldSpeed"
                ).value || 0
            ),

        speed_limit_unit:
            document.getElementById(
                "fieldSpeedUnit"
            ).value,

        port:
            Number(
                document.getElementById(
                    "fieldPort"
                ).value || 443
            ),

        alpn:
            document.getElementById(
                "fieldAlpn"
            ).value.trim(),

        note:
            document.getElementById(
                "fieldNote"
            ).value.trim()
    };


    if (!payload.label) {

        toast(
            "نام کانفیگ را وارد کنید.",
            true
        );

        return;
    }


    button.disabled = true;

    const oldText =
        button.textContent;

    button.textContent =
        "در حال ذخیره...";


    try {

        let result;


        if (
            editingUuid
        ) {

            result =
                await api(
                    "/api/links/" +
                    encodeURIComponent(
                        editingUuid
                    ),
                    {
                        method:
                            "PATCH",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify(
                                payload
                            )
                    }
                );

            closeConfigModal();

            toast(
                "تغییرات ذخیره شد."
            );

        } else {

            result =
                await api(
                    "/api/links/manual",
                    {
                        method:
                            "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body:
                            JSON.stringify(
                                payload
                            )
                    }
                );

            closeConfigModal();

            showResult(
                result
            );

            toast(
                "کانفیگ ساخته شد."
            );
        }


        await refreshAll();


    } catch (error) {

        toast(
            error.message,
            true
        );

    } finally {

        button.disabled =
            false;

        button.textContent =
            oldText;
    }
}


/* =========================================================
   Result
========================================================= */

function showResult(
    result
) {

    document.getElementById(
        "resultVless"
    ).value =
        result.vless_link
        || "";

    document.getElementById(
        "resultSub"
    ).value =
        result.sub_url
        || "";

    document.getElementById(
        "resultInfo"
    ).value =
        result.info_url
        || "";

    document.getElementById(
        "resultModal"
    ).classList.add(
        "show"
    );
}


function closeResultModal() {

    document.getElementById(
        "resultModal"
    ).classList.remove(
        "show"
    );
}


async function copyInput(
    id
) {

    const input =
        document.getElementById(
            id
        );

    try {

        await navigator.clipboard
            .writeText(
                input.value
            );

    } catch {

        input.select();

        document.execCommand(
            "copy"
        );
    }

    toast(
        "کپی شد."
    );
}


/* =========================================================
   Delete
========================================================= */

function openDelete(
    uuid,
    label
) {

    deletingUuid =
        uuid;

    document.getElementById(
        "deleteTarget"
    ).textContent =
        label;

    document.getElementById(
        "deleteModal"
    ).classList.add(
        "show"
    );
}


function closeDeleteModal() {

    deletingUuid =
        null;

    document.getElementById(
        "deleteModal"
    ).classList.remove(
        "show"
    );
}


async function confirmDelete() {

    if (!deletingUuid)
        return;

    const button =
        document.getElementById(
            "deleteButton"
        );

    button.disabled = true;

    button.textContent =
        "در حال حذف...";


    try {

        await api(
            "/api/links/" +
            encodeURIComponent(
                deletingUuid
            ),
            {
                method:
                    "DELETE"
            }
        );

        closeDeleteModal();

        toast(
            "کانفیگ حذف شد."
        );

        await refreshAll();

    } catch (error) {

        toast(
            error.message,
            true
        );

    } finally {

        button.disabled =
            false;

        button.textContent =
            "حذف";
    }
}


/* =========================================================
   Toggle
========================================================= */

async function toggleLink(
    uuid,
    active
) {

    try {

        await api(
            "/api/links/" +
            encodeURIComponent(
                uuid
            ),
            {
                method:
                    "PATCH",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        active:
                            active
                    })
            }
        );

        toast(
            active
            ? "کانفیگ فعال شد."
            : "کانفیگ غیرفعال شد."
        );

        await refreshAll();

    } catch (error) {

        toast(
            error.message,
            true
        );
    }
}


/* =========================================================
   Reset usage
========================================================= */

async function resetUsage(
    uuid
) {

    try {

        await api(
            "/api/links/" +
            encodeURIComponent(
                uuid
            ) +
            "/reset",
            {
                method:
                    "POST"
            }
        );

        toast(
            "مصرف ریست شد."
        );

        await refreshAll();

    } catch (error) {

        toast(
            error.message,
            true
        );
    }
}


/* =========================================================
   Stats
========================================================= */

async function refreshStats() {

    try {

        const data =
            await api(
                "/api/stats"
            );

        if (!data)
            return;

        document.getElementById(
            "statLinks"
        ).textContent =
            data.links;


        document.getElementById(
            "statActive"
        ).textContent =
            data.active_links;


        document.getElementById(
            "statConnections"
        ).textContent =
            data.connections;


        document.getElementById(
            "statUptime"
        ).textContent =
            data.uptime;


        document.getElementById(
            "statClock"
        ).textContent =
            new Date(
                data.server_time
            ).toLocaleTimeString(
                "fa-IR"
            );


        uptimeBase =
            Date.now()
            -
            (
                Number(
                    data.uptime_seconds
                )
                * 1000
            );

    } catch (error) {

        console.error(
            error
        );
    }
}


/* =========================================================
   Local uptime
========================================================= */

function tickUptime() {

    if (!uptimeBase)
        return;

    const seconds =
        Math.floor(
            (
                Date.now()
                -
                uptimeBase
            )
            / 1000
        );

    document.getElementById(
        "statUptime"
    ).textContent =
        formatUptime(
            seconds
        );
}


function formatUptime(
    seconds
) {

    seconds =
        Math.max(
            0,
            Math.floor(
                seconds
            )
        );

    const days =
        Math.floor(
            seconds / 86400
        );

    const hours =
        Math.floor(
            (
                seconds % 86400
            ) / 3600
        );

    const minutes =
        Math.floor(
            (
                seconds % 3600
            ) / 60
        );

    const secs =
        seconds % 60;

    const text =
        [
            String(
                hours
            ).padStart(
                2,
                "0"
            ),

            String(
                minutes
            ).padStart(
                2,
                "0"
            ),

            String(
                secs
            ).padStart(
                2,
                "0"
            )
        ].join(":");

    return days
        ? `${days}d ${text}`
        : text;
}


/* =========================================================
   Links
========================================================= */

async function refreshLinks() {

    try {

        const data =
            await api(
                "/api/links"
            );

        if (!data)
            return;

        renderLinks(
            data.links
        );

    } catch (error) {

        console.error(
            error
        );
    }
}


function renderLinks(
    links
) {

    const table =
        document.getElementById(
            "linksTable"
        );

    if (!links.length) {

        table.innerHTML = `

        <tr>

            <td
                colspan="7"
                style="
                    text-align:center;
                    padding:38px;
                    color:
                        rgba(
                            255,
                            255,
                            255,
                            .24
                        );
                "
            >

                هنوز کانفیگی ساخته نشده است.

            </td>

        </tr>

        `;

        return;
    }


    table.innerHTML = "";


    for (
        const link
        of links
    ) {

        const tr =
            document.createElement(
                "tr"
            );


        tr.innerHTML = `

<td>

<div class="name">

${escapeHtml(
    link.label
)}

</div>

<div class="uuid">

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
        link.online
        ? "active"
        : "off"
    }
">

${
    link.online
    ? "فعال"
    : "غیرفعال"
}

</span>

</td>


<td>

<div class="usage">

<div>

${escapeHtml(
    link.used_fmt
)}
/
${escapeHtml(
    link.limit_fmt
)}

</div>

<div
    class="usage-bar"
    style="
        --usage:${Number(
            link.usage_percent
            || 0
        )}%;
    "
>

<div
    class="usage-fill"
></div>

</div>

</div>

</td>


<td>

${Number(
    link.connections
    || 0
)}

/

${
    Number(
        link.concurrent_limit
        || 0
    )
    || "∞"
}

</td>


<td>

${
    link.expires_at
    ? new Date(
        link.expires_at
      ).toLocaleString(
        "fa-IR"
      )
    : "بدون انقضا"
}

</td>


<td>

<div class="actions">


<button
    class="action"
    onclick='copyDirect(
        ${JSON.stringify(
            link.vless_link
        )}
    )'
>
VLESS
</button>


<button
    class="action"
    onclick='copyDirect(
        ${JSON.stringify(
            link.sub_url
        )}
    )'
>
SUB
</button>


<button
    class="action"
    onclick='window.open(
        ${JSON.stringify(
            link.info_url
        )},
        "_blank"
    )'
>
INFO
</button>


<button
    class="action"
    onclick='openEdit(
        ${JSON.stringify(
            link
        )}
    )'
>
ویرایش
</button>


<button
    class="
        action
        ${
            link.online
            ? ""
            : "success"
        }
    "
    onclick='toggleLink(
        ${JSON.stringify(
            link.uuid
        )},
        ${!link.online}
    )'
>
${
    link.online
    ? "خاموش"
    : "فعال"
}
</button>


<button
    class="action"
    onclick='resetUsage(
        ${JSON.stringify(
            link.uuid
        )}
    )'
>
ریست
</button>


<button
    class="action danger"
    onclick='openDelete(
        ${JSON.stringify(
            link.uuid
        )},
        ${JSON.stringify(
            link.label
        )}
    )'
>
حذف
</button>


</div>

</td>

`;

        table.appendChild(
            tr
        );
    }
}


/* =========================================================
   Copy
========================================================= */

async function copyDirect(
    text
) {

    try {

        await navigator.clipboard
            .writeText(
                text
            );

        toast(
            "لینک کپی شد."
        );

    } catch {

        const value =
            window.prompt(
                "لینک:",
                text
            );

        if (value !== null) {

            try {

                await navigator.clipboard
                    .writeText(
                        value
                    );

            } catch {}

        }
    }
}


/* =========================================================
   Escape
========================================================= */

function escapeHtml(
    value
) {

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


/* =========================================================
   Activity
========================================================= */

async function refreshActivity() {

    try {

        const data =
            await api(
                "/api/activity"
            );

        if (!data)
            return;

        const container =
            document.getElementById(
                "logs"
            );


        if (
            !data.items.length
        ) {

            container.innerHTML =
                `
                <div
                    style="
                        color:
                            rgba(
                                255,
                                255,
                                255,
                                .25
                            );
                        font-size:8px;
                    "
                >
                    فعالیتی ثبت نشده است.
                </div>
                `;

            return;
        }


        container.innerHTML =
            data.items
                .slice(
                    0,
                    80
                )
                .map(
                    item => `

<div class="log">

<div class="log-time">

${new Date(
    item.time
).toLocaleTimeString(
    "fa-IR"
)}

</div>

<div class="log-text">

${escapeHtml(
    item.message
)}

</div>

</div>

`
                )
                .join("");

    } catch {}
}


/* =========================================================
   Password
========================================================= */

function openPasswordModal() {

    document.getElementById(
        "currentPassword"
    ).value = "";

    document.getElementById(
        "newPassword"
    ).value = "";

    document.getElementById(
        "confirmPassword"
    ).value = "";

    document.getElementById(
        "passwordModal"
    ).classList.add(
        "show"
    );
}


function closePasswordModal() {

    document.getElementById(
        "passwordModal"
    ).classList.remove(
        "show"
    );
}


async function changePassword() {

    const current =
        document.getElementById(
            "currentPassword"
        ).value;

    const next =
        document.getElementById(
            "newPassword"
        ).value;

    const confirm =
        document.getElementById(
            "confirmPassword"
        ).value;


    if (!current || !next || !confirm) {

        toast(
            "هر سه فیلد را کامل کنید.",
            true
        );

        return;
    }


    if (
        next !== confirm
    ) {

        toast(
            "تکرار رمز جدید مطابقت ندارد.",
            true
        );

        return;
    }


    if (
        next.length < 8
    ) {

        toast(
            "رمز جدید حداقل ۸ کاراکتر باشد.",
            true
        );

        return;
    }


    try {

        await api(
            "/api/change-password",
            {
                method:
                    "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({

                        current_password:
                            current,

                        new_password:
                            next,

                        confirm_password:
                            confirm
                    })
            }
        );


        closePasswordModal();

        toast(
            "رمز عبور تغییر کرد."
        );

    } catch (error) {

        toast(
            error.message,
            true
        );
    }
}


/* =========================================================
   Refresh
========================================================= */

async function refreshAll() {

    await Promise.all([
        refreshStats(),
        refreshLinks(),
        refreshActivity()
    ]);
}


/* =========================================================
   Modal Outside
========================================================= */

for (
    const id
    of [
        "configModal",
        "resultModal",
        "deleteModal",
        "passwordModal"
    ]
) {

    document
        .getElementById(
            id
        )
        .addEventListener(
            "click",
            function(event) {

                if (
                    event.target
                    === this
                ) {

                    this.classList.remove(
                        "show"
                    );
                }

            }
        );
}


document.addEventListener(
    "keydown",
    function(event) {

        if (
            event.key !==
            "Escape"
        ) {
            return;
        }

        [
            "configModal",
            "resultModal",
            "deleteModal",
            "passwordModal"
        ].forEach(
            id => {

                document
                    .getElementById(
                        id
                    )
                    .classList.remove(
                        "show"
                    );
            }
        );

    }
);


/* =========================================================
   Initial
========================================================= */

refreshAll();

/*
    تمام آمار: هر ۱ ثانیه
*/
setInterval(
    refreshStats,
    1000
);

/*
    لیست کانفیگ‌ها: هر ۱ ثانیه
*/
setInterval(
    refreshLinks,
    1000
);

/*
    لاگ‌ها: هر ۱ ثانیه
*/
setInterval(
    refreshActivity,
    1000
);

/*
    آپتایم محلی بین درخواست‌ها
*/
setInterval(
    tickUptime,
    1000
);

</script>

</body>

</html>
"""


@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
async def dashboard(
    request: Request
):

    if not await valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):

        return RedirectResponse(
            "/login"
        )

    return HTMLResponse(
        DASHBOARD_HTML
    )


# ============================================================
# Health
# ============================================================

@app.get(
    "/health"
)
async def health():

    return {

        "status":
            "ok",

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "uptime":
            format_uptime(
                time.time()
                - START_TIME
            ),

        "port":
            PORT,
    }


# ============================================================
# Startup
# ============================================================

@app.on_event(
    "startup"
)
async def startup():

    await load_state()

    # کانفیگ پیش‌فرض
    if not LINKS:

        uid = (
            "00000000-"
            "0000-"
            "4000-"
            "8000-"
            "000000000001"
        )

        LINKS[
            uid
        ] = {

            "label":
                "لینک پیش‌فرض",

            "limit_bytes":
                0,

            "used_bytes":
                0,

            "duration_days":
                0,

            "expires_at":
                None,

            "active":
                True,

            "protocol":
                "vless-ws",

            "fingerprint":
                "chrome",

            "fragment":
                None,

            "fragment_profile":
                "off",

            "alpn":
                "http/1.1",

            "port":
                443,

            "concurrent_limit":
                0,

            "ip_limit":
                0,

            "speed_limit_bytes":
                0,

            "note":
                "کانفیگ پیش‌فرض",

            "created_at":
                now_iso(),

            "updated_at":
                now_iso(),

            "is_default":
                True,
        }

        await save_state()

    await add_activity(
        f"{APP_NAME} v{APP_VERSION} راه‌اندازی شد",
        "ok",
        "system"
    )

    logger.info(
        "%s started on 0.0.0.0:%s",
        APP_NAME,
        PORT
    )

    logger.info(
        "Data directory: %s",
        DATA_DIR
    )


@app.on_event(
    "shutdown"
)
async def shutdown():

    await save_state()


# ============================================================
# Error handler
# ============================================================

@app.exception_handler(
    Exception
)
async def global_exception(
    request: Request,
    exc: Exception
):

    global TOTAL_ERRORS

    TOTAL_ERRORS += 1

    ERROR_LOG.append({

        "time":
            now_iso(),

        "path":
            str(
                request.url.path
            ),

        "error":
            str(exc),
    })

    logger.exception(
        "Unhandled exception"
    )

    return JSONResponse(
        {
            "ok":
                False,

            "error":
                "internal server error",
        },
        status_code=500
    )


# ============================================================
# Run
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        workers=1,
    )

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
    Depends,
    FastAPI,
    HTTPException,
    Request,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)

# ============================================================
# PixonPanel
# Railway Ready / Single File
# ============================================================

APP_NAME = "PixonPanel"
APP_VERSION = "11.0"

SUPPORT_USERNAME = "@Pixonal"
SUPPORT_URL = "https://t.me/Pixonal"

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(APP_NAME)

# ------------------------------------------------------------
# Railway
# ------------------------------------------------------------

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

# ------------------------------------------------------------
# App
# ------------------------------------------------------------

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
CONNECTION_LOCK = asyncio.Lock()

# ============================================================
# Persistent Secret
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")

    if env_secret:
        return env_secret

    try:
        if SECRET_FILE.exists():
            value = SECRET_FILE.read_text(
                encoding="utf-8"
            ).strip()

            if value:
                return value

        value = secrets.token_urlsafe(48)

        SECRET_FILE.write_text(
            value,
            encoding="utf-8",
        )

        return value

    except Exception as exc:
        logger.warning(
            "Could not persist secret: %s",
            exc,
        )

        return secrets.token_urlsafe(48)


SECRET_KEY = load_or_create_secret()

# ============================================================
# Password
# ============================================================

def hash_password(
    password: str,
) -> str:

    raw = (
        password
        + SECRET_KEY
    ).encode(
        "utf-8"
    )

    return hashlib.sha256(
        raw
    ).hexdigest()


DEFAULT_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "pxpanel2026",
)

AUTH = {
    "password_hash":
        hash_password(
            DEFAULT_PASSWORD
        )
}

# ============================================================
# Storage
# ============================================================

LINKS = {}
SUBSCRIPTIONS = {}

SESSIONS = {}

# ============================================================
# Runtime state
# ============================================================

START_TIME = time.time()

TOTAL_REQUESTS = 0
TOTAL_BYTES = 0
TOTAL_ERRORS = 0

ACTIVE_CONNECTIONS = {}

ACTIVITY_LOG = deque(
    maxlen=300
)

ERROR_LOG = deque(
    maxlen=100
)

TRAFFIC_BY_HOUR = defaultdict(
    int
)

HTTP_CLIENT = None

SESSION_COOKIE = "pixonpanel_session"

SESSION_TTL = (
    60
    * 60
    * 24
    * 365
)

# ============================================================
# Protocols
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

FRAGMENT_OPTIONS = {
    "off": None,
    "tlshello":
        "packets=1-3,10-20;length=1-1;interval=10-20",
    "safe":
        "packets=1-3;length=1-1;interval=10-20",
    "balanced":
        "packets=1-3,10-20;length=1-1;interval=10-20",
    "aggressive":
        "packets=1-3,10-20;length=1-2;interval=5-15",
}

DEFAULT_PROTOCOL = "vless-ws"
DEFAULT_FINGERPRINT = "chrome"
DEFAULT_PORT = 443

# ============================================================
# Utility
# ============================================================

def now_iso() -> str:
    return datetime.now().isoformat()


def uptime_seconds() -> int:
    return int(
        time.time()
        - START_TIME
    )


def format_uptime(
    seconds: int,
) -> str:

    seconds = max(
        0,
        int(seconds),
    )

    days = seconds // 86400

    hours = (
        seconds
        % 86400
    ) // 3600

    minutes = (
        seconds
        % 3600
    ) // 60

    secs = (
        seconds
        % 60
    )

    if days > 0:
        return (
            f"{days}d "
            f"{hours:02d}:"
            f"{minutes:02d}:"
            f"{secs:02d}"
        )

    return (
        f"{hours:02d}:"
        f"{minutes:02d}:"
        f"{secs:02d}"
    )


def format_bytes(
    value: int | float,
) -> str:

    value = max(
        0,
        int(value or 0),
    )

    if value < 1024:
        return f"{value} B"

    if value < 1024 ** 2:
        return (
            f"{value / 1024:.2f} KB"
        )

    if value < 1024 ** 3:
        return (
            f"{value / 1024**2:.2f} MB"
        )

    if value < 1024 ** 4:
        return (
            f"{value / 1024**3:.2f} GB"
        )

    return (
        f"{value / 1024**4:.2f} TB"
    )


def parse_size(
    value,
    unit,
) -> int:

    try:
        number = float(
            value or 0
        )
    except Exception:
        number = 0

    unit = str(
        unit or "GB"
    ).upper()

    if number <= 0:
        return 0

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

    return int(
        number
    )


def parse_speed(
    value,
    unit,
) -> int:

    try:
        number = float(
            value or 0
        )
    except Exception:
        number = 0

    unit = str(
        unit or "MBIT"
    ).upper()

    if number <= 0:
        return 0

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

    return int(
        number
    )


def safe_int(
    value,
    default=0,
):
    try:
        return int(
            value
        )
    except Exception:
        return default


def safe_float(
    value,
    default=0.0,
):
    try:
        return float(
            value
        )
    except Exception:
        return default


def generate_uuid() -> str:

    raw = secrets.token_hex(
        16
    )

    return (
        f"{raw[:8]}-"
        f"{raw[8:12]}-"
        f"{raw[12:16]}-"
        f"{raw[16:20]}-"
        f"{raw[20:32]}"
    )


def get_client_ip(
    request: Request,
) -> str:

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


def get_public_host(
    request: Request,
) -> str:

    forwarded_host = request.headers.get(
        "x-forwarded-host"
    )

    if forwarded_host:
        return (
            forwarded_host
            .split(",")[0]
            .strip()
            .split(":")[0]
        )

    host = request.headers.get(
        "host"
    )

    if host:
        return host.split(":")[0]

    railway_domain = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway_domain:
        return railway_domain

    return "localhost"


# ============================================================
# Logging
# ============================================================

async def activity(
    message: str,
    level: str = "info",
    kind: str = "system",
):

    async with ACTIVITY_LOCK:

        ACTIVITY_LOG.append(
            {
                "time": now_iso(),
                "message": message,
                "level": level,
                "kind": kind,
            }
        )


# ============================================================
# State
# ============================================================

async def save_state():

    async with STATE_LOCK:

        try:

            payload = {
                "links":
                    dict(LINKS),

                "subscriptions":
                    dict(SUBSCRIPTIONS),

                "password_hash":
                    AUTH[
                        "password_hash"
                    ],

                "saved_at":
                    now_iso(),
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
                "save_state failed"
            )

            ERROR_LOG.append(
                {
                    "time": now_iso(),
                    "error":
                        str(exc),
                }
            )


async def load_state():

    try:

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8",
        ) as file:

            raw = await file.read()

        payload = json.loads(
            raw
        )

        LINKS.clear()
        SUBSCRIPTIONS.clear()

        LINKS.update(
            payload.get(
                "links",
                {},
            )
        )

        SUBSCRIPTIONS.update(
            payload.get(
                "subscriptions",
                {},
            )
        )

        stored_hash = payload.get(
            "password_hash"
        )

        if stored_hash:
            AUTH[
                "password_hash"
            ] = stored_hash

        logger.info(
            "Loaded %d links and %d subscriptions",
            len(LINKS),
            len(SUBSCRIPTIONS),
        )

    except Exception as exc:

        logger.exception(
            "load_state failed"
        )

        ERROR_LOG.append(
            {
                "time": now_iso(),
                "error":
                    str(exc),
            }
        )


# ============================================================
# Sessions
# ============================================================

async def create_session() -> str:

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


async def session_valid(
    token: str | None,
) -> bool:

    if not token:
        return False

    async with SESSION_LOCK:

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

    async with SESSION_LOCK:

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

    if not await session_valid(
        token
    ):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )

    return token


# ============================================================
# Link Helpers
# ============================================================

def link_expired(
    link: dict,
) -> bool:

    value = link.get(
        "expires_at"
    )

    if not value:
        return False

    try:

        expires = datetime.fromisoformat(
            value
        )

        return (
            datetime.now()
            >= expires
        )

    except Exception:

        return False


def link_active(
    link: dict,
) -> bool:

    if not link.get(
        "active",
        True,
    ):
        return False

    if link_expired(
        link
    ):
        return False

    limit = safe_int(
        link.get(
            "limit_bytes",
            0,
        )
    )

    used = safe_int(
        link.get(
            "used_bytes",
            0,
        )
    )

    if (
        limit > 0
        and used >= limit
    ):
        return False

    return True


def current_connections_for(
    uuid: str,
) -> int:

    return sum(
        1
        for value
        in ACTIVE_CONNECTIONS.values()
        if value.get(
            "uuid"
        ) == uuid
    )


def current_ips_for(
    uuid: str,
):

    return {
        value.get(
            "ip"
        )
        for value
        in ACTIVE_CONNECTIONS.values()
        if (
            value.get(
                "uuid"
            ) == uuid
            and value.get(
                "ip"
            )
        )
    }


def can_accept_connection(
    uuid: str,
    ip: str,
):

    link = LINKS.get(
        uuid
    )

    if not link:
        return False, "not_found"

    if not link_active(
        link
    ):
        return False, "inactive"

    connection_limit = safe_int(
        link.get(
            "concurrent_limit",
            0,
        )
    )

    if (
        connection_limit > 0
        and
        current_connections_for(
            uuid
        )
        >= connection_limit
    ):
        return False, "concurrent_limit"

    ip_limit = safe_int(
        link.get(
            "ip_limit",
            0,
        )
    )

    if ip_limit > 0:

        current_ips = (
            current_ips_for(
                uuid
            )
        )

        if (
            ip not in current_ips
            and
            len(current_ips)
            >= ip_limit
        ):
            return False, "ip_limit"

    return True, "ok"


# ============================================================
# VLESS Generator
# ============================================================

def build_vless(
    uid: str,
    link: dict,
    host: str,
) -> str:

    protocol = link.get(
        "protocol",
        DEFAULT_PROTOCOL,
    )

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = link.get(
        "fingerprint",
        DEFAULT_FINGERPRINT,
    )

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    port = safe_int(
        link.get(
            "port",
            DEFAULT_PORT,
        ),
        DEFAULT_PORT,
    )

    if not (
        1 <= port <= 65535
    ):
        port = DEFAULT_PORT

    alpn = (
        link.get(
            "alpn",
            "",
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

        params.update(
            {
                "type":
                    "ws",

                "host":
                    host,

                "path":
                    f"/ws/{uid}",
            }
        )

    else:

        mode = protocol.replace(
            "xhttp-",
            "",
        )

        params.update(
            {
                "type":
                    "xhttp",

                "mode":
                    mode,

                "host":
                    host,

                "path":
                    f"/xhttp-siz10/"
                    f"{mode}/"
                    f"{uid}",
            }
        )

    fragment = link.get(
        "fragment"
    )

    if fragment:
        params[
            "fragment"
        ] = fragment

    query = "&".join(
        f"{key}="
        f"{quote(str(value), safe='')}"
        for key, value in params.items()
        if value is not None
        and str(value) != ""
    )

    remark = (
        link.get(
            "label",
            "PixonPanel",
        )
        or "PixonPanel"
    )

    return (
        f"vless://"
        f"{uid}@"
        f"{host}:"
        f"{port}?"
        f"{query}"
        f"#"
        f"{quote(remark)}"
    )


# ============================================================
# Create Link
# ============================================================

async def create_link(
    data: dict,
):

    label = str(
        data.get(
            "label",
            "",
        )
    ).strip()

    if not label:
        raise ValueError(
            "نام کانفیگ الزامی است."
        )

    protocol = str(
        data.get(
            "protocol",
            DEFAULT_PROTOCOL,
        )
    )

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        data.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        )
    ).lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    volume_value = safe_float(
        data.get(
            "volume_value",
            0,
        )
    )

    volume_unit = str(
        data.get(
            "volume_unit",
            "GB",
        )
    )

    limit_bytes = parse_size(
        volume_value,
        volume_unit,
    )

    days = safe_int(
        data.get(
            "duration_days",
            0,
        )
    )

    if days > 0:

        expires_at = (
            datetime.now()
            + timedelta(
                days=days
            )
        ).isoformat()

    else:

        expires_at = None

    port = safe_int(
        data.get(
            "port",
            DEFAULT_PORT,
        ),
        DEFAULT_PORT,
    )

    if not (
        1 <= port <= 65535
    ):
        port = DEFAULT_PORT

    speed = parse_speed(
        data.get(
            "speed_limit_value",
            0,
        ),
        data.get(
            "speed_limit_unit",
            "MBIT",
        ),
    )

    fragment_key = str(
        data.get(
            "fragment",
            "off",
        )
    )

    fragment = (
        FRAGMENT_OPTIONS.get(
            fragment_key
        )
    )

    concurrent_limit = max(
        0,
        safe_int(
            data.get(
                "concurrent_limit",
                0,
            )
        ),
    )

    ip_limit = max(
        0,
        safe_int(
            data.get(
                "ip_limit",
                0,
            )
        ),
    )

    uid = generate_uuid()

    link = {

        "label":
            label[:80],

        "limit_bytes":
            limit_bytes,

        "used_bytes":
            0,

        "duration_days":
            max(
                0,
                days,
            ),

        "expires_at":
            expires_at,

        "active":
            True,

        "protocol":
            protocol,

        "fingerprint":
            fingerprint,

        "fragment":
            fragment,

        "fragment_profile":
            fragment_key,

        "alpn":
            str(
                data.get(
                    "alpn",
                    "",
                )
            )[:100],

        "port":
            port,

        "concurrent_limit":
            concurrent_limit,

        "ip_limit":
            ip_limit,

        "speed_limit_bytes":
            speed,

        "note":
            str(
                data.get(
                    "note",
                    "",
                )
            )[:300],

        "created_at":
            now_iso(),

        "updated_at":
            now_iso(),

        "is_default":
            False,
    }

    async with STATE_LOCK:

        LINKS[
            uid
        ] = link

    await save_state()

    await activity(
        (
            f"کانفیگ "
            f"«{label}» "
            f"ساخته شد"
        ),
        "ok",
        "link",
    )

    return uid, link


# ============================================================
# Dashboard Result
# ============================================================

def serialize_link(
    uid: str,
    link: dict,
    host: str,
):

    used = safe_int(
        link.get(
            "used_bytes",
            0,
        )
    )

    limit = safe_int(
        link.get(
            "limit_bytes",
            0,
        )
    )

    active_conn = (
        current_connections_for(
            uid
        )
    )

    return {

        "uuid":
            uid,

        **link,

        "expired":
            link_expired(
                link
            ),

        "is_online":
            link_active(
                link
            ),

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

        "usage_percent":
            (
                0
                if limit <= 0
                else min(
                    100,
                    round(
                        used
                        / limit
                        * 100,
                        1,
                    ),
                )
            ),

        "connections":
            active_conn,

        "vless_link":
            build_vless(
                uid,
                link,
                host,
            ),

        "sub_url":
            (
                f"https://"
                f"{host}/sub/{uid}"
            ),

        "info_url":
            (
                f"https://"
                f"{host}/info/{uid}"
            ),

        "subscription_userinfo":
            (
                "upload=0;"
                f"download={used};"
                f"total={limit}"
            ),
    }


# ============================================================
# Root
# ============================================================

LANDING_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0"
>

<title>PixonPanel</title>

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
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
    rel="stylesheet"
>

<style>

* {
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    min-height: 100%;
}

body {

    min-height: 100vh;

    display: flex;

    align-items: center;
    justify-content: center;

    padding: 20px;

    color: #fff;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 15% 10%,
            rgba(99,102,241,.20),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 90%,
            rgba(168,85,247,.15),
            transparent 30%
        ),
        #07070a;

    overflow: hidden;
}

.background-grid {

    position: fixed;

    inset: 0;

    opacity: .025;

    background-size: 32px 32px;

    background-image:
        linear-gradient(
            rgba(255,255,255,.3) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,.3) 1px,
            transparent 1px
        );
}

.glow {

    position: fixed;

    width: 280px;
    height: 280px;

    border-radius: 999px;

    filter: blur(110px);

    opacity: .16;

    pointer-events: none;
}

.glow-one {

    top: -130px;
    right: -80px;

    background: #6366f1;
}

.glow-two {

    bottom: -130px;
    left: -90px;

    background: #a855f7;
}

.wrapper {

    width: 100%;

    max-width: 570px;

    position: relative;

    z-index: 10;
}

.card {

    padding: 33px;

    border-radius: 30px;

    border:
        1px solid
        rgba(255,255,255,.09);

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.075),
            rgba(255,255,255,.025)
        );

    backdrop-filter:
        blur(30px)
        saturate(145%);

    -webkit-backdrop-filter:
        blur(30px)
        saturate(145%);

    box-shadow:
        0 45px 110px
        rgba(0,0,0,.48);

    animation:
        appear .45s ease both;
}

@keyframes appear {

    from {
        opacity: 0;
        transform:
            translateY(18px)
            scale(.985);
    }

    to {
        opacity: 1;
        transform:
            translateY(0)
            scale(1);
    }
}

.brand {

    display: flex;

    align-items: center;

    gap: 13px;

    margin-bottom: 28px;
}

.logo {

    width: 51px;
    height: 51px;

    border-radius: 16px;

    display: flex;

    align-items: center;
    justify-content: center;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-size: 18px;

    font-weight: 900;

    box-shadow:
        0 16px 36px
        rgba(99,102,241,.28);
}

.brand-name {

    font-size: 17px;

    font-weight: 900;
}

.brand-sub {

    margin-top: 4px;

    font-size: 11px;

    color:
        rgba(255,255,255,.40);
}

.status {

    display: inline-flex;

    padding:
        7px 11px;

    border-radius: 999px;

    background:
        rgba(34,197,94,.07);

    border:
        1px solid
        rgba(34,197,94,.14);

    color:
        #86efac;

    font-size: 10px;

    margin-bottom: 17px;
}

h1 {

    margin: 0;

    font-size: 30px;

    line-height: 1.5;

    font-weight: 900;
}

.desc {

    margin-top: 13px;

    color:
        rgba(255,255,255,.54);

    font-size: 13px;

    line-height: 2;
}

.command {

    margin-top: 22px;

    padding: 15px;

    border-radius: 17px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(0,0,0,.18);
}

.command-title {

    font-size: 10px;

    color:
        rgba(255,255,255,.38);

    margin-bottom: 8px;
}

.command-code {

    padding:
        12px 13px;

    border-radius: 12px;

    background:
        rgba(255,255,255,.04);

    border:
        1px solid
        rgba(255,255,255,.06);

    color:
        #c4b5fd;

    direction: ltr;

    text-align: left;

    font-family:
        Consolas,
        monospace;
}

.actions {

    display: flex;

    gap: 10px;

    margin-top: 20px;
}

.button {

    flex: 1;

    padding: 13px;

    border-radius: 14px;

    text-align: center;

    text-decoration: none;

    font-size: 12px;

    font-weight: 800;

    transition: .18s ease;
}

.button:hover {

    transform:
        translateY(-2px);
}

.primary {

    color: white;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.secondary {

    color:
        rgba(255,255,255,.80);

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);
}

.footer {

    display: flex;

    justify-content:
        space-between;

    margin-top: 20px;

    padding-top: 17px;

    border-top:
        1px solid
        rgba(255,255,255,.07);

    color:
        rgba(255,255,255,.33);

    font-size: 10px;
}

.support {

    color:
        #a78bfa;

    text-decoration: none;
}

@media(max-width:600px) {

    .card {
        padding: 24px;
        border-radius: 24px;
    }

    h1 {
        font-size: 24px;
    }

    .actions {
        flex-direction: column;
    }

}

</style>

</head>

<body>

<div class="background-grid"></div>

<div class="glow glow-one"></div>

<div class="glow glow-two"></div>

<main class="wrapper">

<section class="card">

<div class="brand">

<div class="logo">
P
</div>

<div>

<div class="brand-name">
PixonPanel
</div>

<div class="brand-sub">
مدیریت سرویس و کانفیگ
</div>

</div>

</div>

<div class="status">
● سرویس آنلاین است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<div class="desc">
این صفحه عمومی PixonPanel است.
برای دسترسی به داشبورد مدیریت، وارد بخش ورود شوید.
</div>

<div class="command">

<div class="command-title">
مسیر ورود
</div>

<div class="command-code">
/login
</div>

</div>

<div class="actions">

<a
    href="/login"
    class="button primary"
>
ورود به پنل
</a>

<a
    href="https://t.me/Pixonal"
    target="_blank"
    rel="noopener"
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
    class="support"
    href="https://t.me/Pixonal"
    target="_blank"
>
@Pixonal
</a>

</div>

</section>

</main>

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

    if await session_valid(
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
>

<title>ورود | PixonPanel</title>

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
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
    rel="stylesheet"
>

<style>

* {
    box-sizing:border-box;
}

body {

    margin:0;

    min-height:100vh;

    display:flex;

    justify-content:center;

    align-items:center;

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

    border-radius:27px;

    border:
        1px solid
        rgba(255,255,255,.09);

    background:
        rgba(255,255,255,.045);

    backdrop-filter:
        blur(30px);

    box-shadow:
        0 35px 90px
        rgba(0,0,0,.45);
}

.logo {

    width:50px;
    height:50px;

    border-radius:16px;

    display:flex;

    align-items:center;
    justify-content:center;

    margin-bottom:20px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

h1 {

    margin:0;

    font-size:24px;

    font-weight:900;
}

.desc {

    margin-top:8px;

    color:
        rgba(255,255,255,.45);

    font-size:12px;

    line-height:2;
}

form {

    margin-top:22px;
}

label {

    display:block;

    margin-bottom:7px;

    font-size:11px;

    color:
        rgba(255,255,255,.55);
}

input {

    width:100%;

    padding:14px;

    border-radius:13px;

    outline:none;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(0,0,0,.18);

    color:white;

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

    margin-top:13px;

    padding:14px;

    border:0;

    border-radius:14px;

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

    padding:11px;

    border-radius:12px;

    color:#fca5a5;

    background:
        rgba(239,68,68,.08);

    border:
        1px solid
        rgba(239,68,68,.14);

    font-size:11px;
}

.support {

    display:block;

    text-align:center;

    margin-top:17px;

    color:
        #a78bfa;

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
برای ورود به داشبورد، رمز عبور مدیریت را وارد کنید.
</div>

<form
    method="post"
    action="/login"
>

<label>
رمز عبور
</label>

<input
    name="password"
    type="password"
    autocomplete="current-password"
    autofocus
    placeholder="رمز عبور"
/>

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


def login_error(
    message: str,
):

    safe = (
        str(message)
        .replace(
            "&",
            "&amp;",
        )
        .replace(
            "<",
            "&lt;",
        )
        .replace(
            ">",
            "&gt;",
        )
    )

    return LOGIN_HTML.replace(
        "</form>",
        (
            f"""
            <div class="error">
                {safe}
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

    if await session_valid(
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
    request: Request,
):

    try:

        raw = await request.body()

        parsed = parse_qs(
            raw.decode(
                "utf-8",
                errors="ignore",
            )
        )

        password = (
            parsed
            .get(
                "password",
                [""],
            )[0]
            .strip()
        )

    except Exception as exc:

        logger.exception(
            "login parse error"
        )

        return HTMLResponse(
            login_error(
                f"خطا در پردازش فرم: {exc}"
            ),
            status_code=400,
        )

    if not password:

        return HTMLResponse(
            login_error(
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

        await activity(
            (
                "تلاش ناموفق برای ورود "
                f"از {get_client_ip(request)}"
            ),
            "warn",
            "auth",
        )

        return HTMLResponse(
            login_error(
                "رمز عبور اشتباه است."
            ),
            status_code=401,
        )

    token = await create_session()

    response = RedirectResponse(
        "/dashboard",
        status_code=303,
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/",
    )

    await activity(
        "ورود موفق به پنل",
        "ok",
        "auth",
    )

    return response


@app.get(
    "/logout"
)
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


# ============================================================
# Link APIs
# ============================================================

@app.get(
    "/api/links"
)
async def api_links(
    request: Request,
    _=Depends(require_auth),
):

    host = get_public_host(
        request
    )

    async with STATE_LOCK:

        items = [
            serialize_link(
                uid,
                link,
                host,
            )

            for uid, link
            in LINKS.items()
        ]

    items.sort(
        key=lambda x:
            x.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "links":
            items
    }


@app.post(
    "/api/links"
)
async def api_create_link(
    request: Request,
    _=Depends(require_auth),
):

    global TOTAL_REQUESTS

    TOTAL_REQUESTS += 1

    try:

        data = await request.json()

        uid, link = (
            await create_link(
                data
            )
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
                host,
            ),
        }

    except ValueError as exc:

        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    except Exception as exc:

        logger.exception(
            "create link failed"
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "خطا در ساخت کانفیگ: "
                f"{exc}"
            ),
        )


@app.patch(
    "/api/links/{uid}"
)
async def api_update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    global TOTAL_REQUESTS

    TOTAL_REQUESTS += 1

    body = await request.json()

    async with STATE_LOCK:

        link = LINKS.get(
            uid
        )

        if not link:

            raise HTTPException(
                status_code=404,
                detail="کانفیگ پیدا نشد.",
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
                ] = label[:80]

        if "active" in body:

            link[
                "active"
            ] = bool(
                body[
                    "active"
                ]
            )

        if "note" in body:

            link[
                "note"
            ] = str(
                body.get(
                    "note",
                    "",
                )
            )[:300]

        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                )
            )

            if protocol in PROTOCOLS:

                link[
                    "protocol"
                ] = protocol

        if "fingerprint" in body:

            fp = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).lower()

            if fp in FINGERPRINTS:

                link[
                    "fingerprint"
                ] = fp

        if "fragment" in body:

            fragment_key = str(
                body.get(
                    "fragment",
                    "off",
                )
            )

            if (
                fragment_key
                in FRAGMENT_OPTIONS
            ):

                link[
                    "fragment_profile"
                ] = fragment_key

                link[
                    "fragment"
                ] = FRAGMENT_OPTIONS[
                    fragment_key
                ]

        if (
            "volume_value"
            in body
        ):

            link[
                "limit_bytes"
            ] = parse_size(
                body.get(
                    "volume_value",
                    0,
                ),
                body.get(
                    "volume_unit",
                    "GB",
                ),
            )

        if (
            "duration_days"
            in body
        ):

            days = max(
                0,
                safe_int(
                    body.get(
                        "duration_days",
                        0,
                    )
                ),
            )

            link[
                "duration_days"
            ] = days

            if days > 0:

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

        if (
            "concurrent_limit"
            in body
        ):

            link[
                "concurrent_limit"
            ] = max(
                0,
                safe_int(
                    body.get(
                        "concurrent_limit",
                        0,
                    )
                ),
            )

        if (
            "ip_limit"
            in body
        ):

            link[
                "ip_limit"
            ] = max(
                0,
                safe_int(
                    body.get(
                        "ip_limit",
                        0,
                    )
                ),
            )

        if (
            "speed_limit_value"
            in body
        ):

            link[
                "speed_limit_bytes"
            ] = parse_speed(
                body.get(
                    "speed_limit_value",
                    0,
                ),
                body.get(
                    "speed_limit_unit",
                    "MBIT",
                ),
            )

        if "port" in body:

            port = safe_int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                ),
                DEFAULT_PORT,
            )

            if (
                1 <= port <= 65535
            ):

                link[
                    "port"
                ] = port

        if "alpn" in body:

            link[
                "alpn"
            ] = str(
                body.get(
                    "alpn",
                    "",
                )
            )[:100]

        link[
            "updated_at"
        ] = now_iso()

        snapshot = dict(
            link
        )

    await save_state()

    await activity(
        (
            f"کانفیگ "
            f"«{snapshot.get('label', uid)}» "
            f"ویرایش شد"
        ),
        "info",
        "link",
    )

    return {
        "ok":
            True,

        **serialize_link(
            uid,
            snapshot,
            get_public_host(
                request
            ),
        ),
    }


@app.delete(
    "/api/links/{uid}"
)
async def api_delete_link(
    uid: str,
    _=Depends(require_auth),
):

    async with STATE_LOCK:

        link = LINKS.get(
            uid
        )

        if not link:

            raise HTTPException(
                status_code=404,
                detail="کانفیگ پیدا نشد.",
            )

        if link.get(
            "is_default",
            False,
        ):

            raise HTTPException(
                status_code=400,
                detail=(
                    "کانفیگ پیش‌فرض قابل حذف نیست."
                ),
            )

        label = link.get(
            "label",
            uid,
        )

        LINKS.pop(
            uid,
            None,
        )

    await save_state()

    await activity(
        (
            f"کانفیگ "
            f"«{label}» حذف شد"
        ),
        "warn",
        "link",
    )

    return {
        "ok":
            True
    }


@app.post(
    "/api/links/{uid}/reset"
)
async def api_reset_usage(
    uid: str,
    _=Depends(require_auth),
):

    async with STATE_LOCK:

        link = LINKS.get(
            uid
        )

        if not link:

            raise HTTPException(
                status_code=404,
                detail="کانفیگ پیدا نشد.",
            )

        link[
            "used_bytes"
        ] = 0

        link[
            "updated_at"
        ] = now_iso()

    await save_state()

    await activity(
        (
            f"مصرف کانفیگ "
            f"«{link.get('label', uid)}» "
            f"ریست شد"
        ),
        "info",
        "traffic",
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
    request: Request,
):

    link = LINKS.get(
        uid
    )

    if not link:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    if not link_active(
        link
    ):

        raise HTTPException(
            status_code=404,
            detail="inactive",
        )

    host = get_public_host(
        request
    )

    vless = build_vless(
        uid,
        link,
        host,
    )

    encoded = base64.b64encode(
        vless.encode(
            "utf-8"
        )
    ).decode(
        "ascii"
    )

    used = safe_int(
        link.get(
            "used_bytes",
            0,
        )
    )

    total = safe_int(
        link.get(
            "limit_bytes",
            0,
        )
    )

    headers = {

        "profile-title":
            quote(
                link.get(
                    "label",
                    APP_NAME,
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

    return Response(
        content=encoded,
        media_type="text/plain",
        headers=headers,
    )


@app.get(
    "/info/{uid}",
    response_class=HTMLResponse,
)
async def info_page(
    uid: str,
):

    link = LINKS.get(
        uid
    )

    if not link:

        return HTMLResponse(
            """
            <h2
                style="
                    padding:40px;
                    font-family:Tahoma;
                    color:white;
                    background:#07070a;
                    min-height:100vh;
                "
            >
                کانفیگ پیدا نشد
            </h2>
            """,
            status_code=404,
        )

    return HTMLResponse(
        build_info_html(
            uid,
            link,
        )
    )


# ============================================================
# Dashboard API
# ============================================================

@app.get(
    "/api/stats"
)
async def api_stats(
    _=Depends(require_auth),
):

    global TOTAL_REQUESTS

    TOTAL_REQUESTS += 1

    active = len(
        ACTIVE_CONNECTIONS
    )

    active_links = sum(
        1
        for link
        in LINKS.values()
        if link_active(
            link
        )
    )

    expired = sum(
        1
        for link
        in LINKS.values()
        if link_expired(
            link
        )
    )

    total_usage = sum(
        safe_int(
            link.get(
                "used_bytes",
                0,
            )
        )
        for link
        in LINKS.values()
    )

    return {

        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "links":
            len(
                LINKS
            ),

        "active_links":
            active_links,

        "expired_links":
            expired,

        "subscriptions":
            len(
                SUBSCRIPTIONS
            ),

        "connections":
            active,

        "requests":
            TOTAL_REQUESTS,

        "bytes":
            TOTAL_BYTES,

        "bytes_fmt":
            format_bytes(
                TOTAL_BYTES
            ),

        "usage":
            total_usage,

        "usage_fmt":
            format_bytes(
                total_usage
            ),

        "errors":
            TOTAL_ERRORS,

        "uptime_seconds":
            uptime_seconds(),

        "uptime":
            format_uptime(
                uptime_seconds()
            ),

        "server_time":
            now_iso(),
    }


@app.get(
    "/api/activity"
)
async def api_activity(
    _=Depends(require_auth),
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


@app.get(
    "/api/connections"
)
async def api_connections(
    _=Depends(require_auth),
):

    async with CONNECTION_LOCK:

        values = [
            dict(
                item
            )
            for item
            in ACTIVE_CONNECTIONS.values()
        ]

    return {
        "connections":
            values,

        "count":
            len(
                values
            ),
    }


# ============================================================
# Change Password
# ============================================================

@app.post(
    "/api/change-password"
)
async def change_password(
    request: Request,
    current_session=Depends(
        require_auth
    ),
):

    body = await request.json()

    current = str(
        body.get(
            "current_password",
            "",
        )
    )

    new_password = str(
        body.get(
            "new_password",
            "",
        )
    )

    if (
        hash_password(
            current
        )
        != AUTH[
            "password_hash"
        ]
    ):

        raise HTTPException(
            status_code=400,
            detail="رمز فعلی اشتباه است.",
        )

    if len(
        new_password
    ) < 4:

        raise HTTPException(
            status_code=400,
            detail=(
                "رمز جدید باید حداقل "
                "۴ کاراکتر باشد."
            ),
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )

    await save_state()

    await activity(
        "رمز عبور مدیریت تغییر کرد",
        "ok",
        "security",
    )

    return {
        "ok":
            True
    }


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

<title>PixonPanel Dashboard</title>

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
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
    rel="stylesheet"
>

<style>

:root {

    color-scheme: dark;

    --bg:
        #07070a;

    --panel:
        rgba(255,255,255,.035);

    --panel-strong:
        rgba(255,255,255,.055);

    --border:
        rgba(255,255,255,.08);

    --text:
        #fff;

    --muted:
        rgba(255,255,255,.40);

    --purple:
        #8b5cf6;

    --indigo:
        #6366f1;

    --green:
        #86efac;

    --red:
        #fca5a5;
}

* {

    box-sizing:
        border-box;
}

html,
body {

    margin:0;

    min-height:100%;
}

body {

    min-height:100vh;

    color:
        var(--text);

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 5% 0%,
            rgba(99,102,241,.12),
            transparent 27%
        ),

        radial-gradient(
            circle at 100% 100%,
            rgba(168,85,247,.09),
            transparent 25%
        ),

        var(--bg);
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
            calc(100% - 28px)
        );

    margin:
        0 auto;

    padding:
        22px 0 40px;
}

.topbar {

    display:
        flex;

    align-items:
        center;

    justify-content:
        space-between;

    gap:15px;

    margin-bottom:
        17px;
}

.brand {

    display:
        flex;

    align-items:
        center;

    gap:12px;
}

.logo {

    width:45px;
    height:45px;

    display:
        flex;

    align-items:center;
    justify-content:center;

    border-radius:
        14px;

    background:
        linear-gradient(
            135deg,
            var(--indigo),
            var(--purple)
        );

    font-weight:
        900;
}

.brand-name {

    font-size:
        16px;

    font-weight:
        900;
}

.brand-sub {

    margin-top:3px;

    font-size:10px;

    color:
        var(--muted);
}

.top-actions {

    display:flex;

    align-items:center;

    gap:8px;
}

.top-btn {

    padding:
        9px 12px;

    border-radius:
        11px;

    border:
        1px solid
        var(--border);

    color:
        rgba(255,255,255,.72);

    background:
        rgba(255,255,255,.03);

    font-size:
        10px;
}

.top-btn:hover {

    background:
        rgba(255,255,255,.06);
}

.grid {

    display:
        grid;

    grid-template-columns:
        repeat(
            4,
            1fr
        );

    gap:10px;
}

.stat {

    padding:
        16px;

    border-radius:
        18px;

    border:
        1px solid
        var(--border);

    background:
        var(--panel);

    backdrop-filter:
        blur(16px);
}

.stat-top {

    display:flex;

    align-items:center;

    justify-content:space-between;

    gap:10px;
}

.stat-title {

    color:
        var(--muted);

    font-size:
        10px;
}

.stat-value {

    margin-top:
        7px;

    font-size:
        23px;

    font-weight:
        900;

    letter-spacing:
        -.3px;
}

.stat-sub {

    margin-top:
        5px;

    color:
        rgba(255,255,255,.25);

    font-size:
        9px;
}

.panel {

    margin-top:
        11px;

    overflow:
        hidden;

    border-radius:
        20px;

    border:
        1px solid
        var(--border);

    background:
        var(--panel);

    backdrop-filter:
        blur(18px);
}

.panel-head {

    display:
        flex;

    align-items:center;

    justify-content:
        space-between;

    gap:10px;

    padding:
        16px 17px;

    border-bottom:
        1px solid
        rgba(255,255,255,.06);
}

.panel-title {

    font-size:
        12px;

    font-weight:
        800;
}

.panel-desc {

    margin-top:
        3px;

    color:
        rgba(255,255,255,.30);

    font-size:
        9px;
}

.primary-btn {

    border:0;

    padding:
        10px 13px;

    border-radius:
        11px;

    color:#fff;

    background:
        linear-gradient(
            135deg,
            var(--indigo),
            var(--purple)
        );

    font-size:
        10px;

    font-weight:
        800;

    box-shadow:
        0 10px 25px
        rgba(99,102,241,.17);
}

.table-scroll {

    overflow-x:auto;
}

table {

    width:100%;

    min-width:1000px;

    border-collapse:
        collapse;
}

th,
td {

    padding:
        12px 13px;

    text-align:right;

    border-bottom:
        1px solid
        rgba(255,255,255,.045);

    font-size:
        10px;
}

th {

    color:
        rgba(255,255,255,.30);

    font-weight:
        500;
}

.name {

    font-weight:
        800;

    font-size:
        11px;
}

.uuid {

    margin-top:
        3px;

    color:
        rgba(255,255,255,.23);

    font-family:
        Consolas,
        monospace;

    direction:ltr;

    text-align:right;

    font-size:
        8px;
}

.status {

    display:
        inline-flex;

    align-items:center;

    padding:
        4px 8px;

    border-radius:
        999px;

    font-size:
        8px;
}

.status.active {

    color:
        var(--green);

    background:
        rgba(34,197,94,.08);

    border:
        1px solid
        rgba(34,197,94,.10);
}

.status.off {

    color:
        var(--red);

    background:
        rgba(239,68,68,.08);

    border:
        1px solid
        rgba(239,68,68,.10);
}

.usage {

    min-width:
        100px;
}

.usage-bar {

    height:
        6px;

    overflow:
        hidden;

    margin-top:
        6px;

    border-radius:
        999px;

    background:
        rgba(255,255,255,.07);
}

.usage-fill {

    width:
        var(--usage);

    height:100%;

    background:
        linear-gradient(
            90deg,
            var(--indigo),
            var(--purple)
        );

    border-radius:
        inherit;
}

.actions {

    display:
        flex;

    flex-wrap:
        wrap;

    gap:5px;
}

.action {

    padding:
        7px 9px;

    border-radius:
        9px;

    border:
        1px solid
        rgba(255,255,255,.07);

    color:
        rgba(255,255,255,.72);

    background:
        rgba(255,255,255,.035);

    font-size:
        8px;
}

.action:hover {

    background:
        rgba(255,255,255,.07);
}

.action.danger {

    color:
        var(--red);
}

.action.success {

    color:
        var(--green);
}

.logs {

    max-height:
        270px;

    overflow:auto;

    padding:
        17px;
}

.log {

    display:
        flex;

    align-items:
        flex-start;

    gap:10px;

    padding:
        9px 0;

    border-bottom:
        1px solid
        rgba(255,255,255,.04);
}

.log-time {

    color:
        rgba(255,255,255,.22);

    font-size:
        8px;

    white-space:
        nowrap;
}

.log-text {

    color:
        rgba(255,255,255,.60);

    font-size:
        9px;
}

/* ----------------------------------------------------------
   Modal
---------------------------------------------------------- */

.modal {

    position:
        fixed;

    inset:0;

    z-index:5000;

    display:none;

    align-items:center;
    justify-content:center;

    padding:16px;

    background:
        rgba(0,0,0,.68);

    backdrop-filter:
        blur(15px);

    -webkit-backdrop-filter:
        blur(15px);
}

.modal.show {

    display:flex;
}

.modal-card {

    width:
        100%;

    max-width:
        720px;

    max-height:
        calc(100vh - 24px);

    overflow:
        auto;

    border-radius:
        24px;

    border:
        1px solid
        rgba(255,255,255,.10);

    background:
        linear-gradient(
            145deg,
            rgba(24,24,31,.98),
            rgba(9,9,12,.98)
        );

    box-shadow:
        0 50px 140px
        rgba(0,0,0,.65);

    animation:
        modalIn .18s ease;
}

@keyframes modalIn {

    from {

        opacity:0;

        transform:
            translateY(15px)
            scale(.985);
    }

    to {

        opacity:1;

        transform:
            translateY(0)
            scale(1);
    }
}

.modal-head {

    display:flex;

    align-items:center;

    justify-content:
        space-between;

    gap:10px;

    padding:
        18px 19px;

    border-bottom:
        1px solid
        rgba(255,255,255,.07);
}

.modal-title {

    font-size:
        15px;

    font-weight:
        900;
}

.modal-desc {

    margin-top:
        3px;

    color:
        rgba(255,255,255,.30);

    font-size:
        9px;
}

.close-btn {

    width:
        34px;

    height:
        34px;

    border:0;

    border-radius:
        10px;

    color:
        rgba(255,255,255,.70);

    background:
        rgba(255,255,255,.05);

    font-size:
        19px;
}

.form {

    display:
        grid;

    grid-template-columns:
        repeat(
            2,
            minmax(
                0,
                1fr
            )
        );

    gap:13px;

    padding:
        19px;
}

.field.full {

    grid-column:
        1 / -1;
}

.field label {

    display:
        block;

    margin-bottom:
        6px;

    color:
        rgba(255,255,255,.54);

    font-size:
        9px;
}

.input,
.select,
.textarea {

    width:100%;

    min-height:
        42px;

    border:
        1px solid
        rgba(255,255,255,.08);

    border-radius:
        11px;

    outline:none;

    padding:
        10px 11px;

    color:white;

    background:
        rgba(255,255,255,.04);

    font-size:
        10px;
}

.input:focus,
.select:focus,
.textarea:focus {

    border-color:
        rgba(129,140,248,.55);
}

.textarea {

    resize:
        vertical;

    min-height:
        90px;
}

.inline {

    display:
        flex;

    gap:6px;
}

.inline .input {

    flex:1;
}

.inline .select {

    width:
        92px;
}

.hint {

    margin-top:
        4px;

    color:
        rgba(255,255,255,.24);

    font-size:
        8px;
}

.switch {

    display:
        flex;

    align-items:center;

    justify-content:
        space-between;

    gap:12px;

    min-height:
        42px;

    padding:
        9px 11px;

    border-radius:
        11px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.04);
}

.checkbox {

    width:
        18px;

    height:
        18px;

    accent-color:
        var(--purple);
}

.modal-footer {

    display:
        flex;

    gap:7px;

    padding:
        15px 19px;

    border-top:
        1px solid
        rgba(255,255,255,.07);
}

.modal-btn {

    flex:1;

    min-height:
        42px;

    border:0;

    border-radius:
        12px;

    font-size:
        10px;

    font-weight:
        800;
}

.modal-btn.cancel {

    color:
        rgba(255,255,255,.65);

    background:
        rgba(255,255,255,.05);
}

.modal-btn.save {

    color:white;

    background:
        linear-gradient(
            135deg,
            var(--indigo),
            var(--purple)
        );
}

/* ----------------------------------------------------------
   Result Modal
---------------------------------------------------------- */

.result-box {

    padding:
        17px 19px;
}

.result-group {

    margin-bottom:
        13px;
}

.result-label {

    margin-bottom:
        6px;

    color:
        rgba(255,255,255,.40);

    font-size:
        9px;
}

.result-row {

    display:
        flex;

    gap:6px;
}

.result-input {

    flex:1;

    min-width:0;

    padding:
        11px;

    border-radius:
        11px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(0,0,0,.20);

    color:
        #c4b5fd;

    outline:none;

    direction:ltr;

    font-family:
        Consolas,
        monospace;

    font-size:
        9px;
}

.result-copy {

    padding:
        0 12px;

    border:0;

    border-radius:
        10px;

    color:white;

    background:
        rgba(255,255,255,.07);

    font-size:
        9px;
}

.delete-title {

    font-size:
        15px;

    font-weight:
        900;
}

.delete-text {

    margin-top:
        8px;

    color:
        rgba(255,255,255,.48);

    line-height:
        1.9;

    font-size:
        10px;
}

.delete-name {

    margin-top:
        11px;

    padding:
        12px;

    border-radius:
        11px;

    background:
        rgba(239,68,68,.07);

    border:
        1px solid
        rgba(239,68,68,.12);

    color:
        #fca5a5;

    font-size:
        10px;
}

/* ----------------------------------------------------------
   Toast
---------------------------------------------------------- */

.toast-wrap {

    position:
        fixed;

    left:
        18px;

    bottom:
        18px;

    z-index:
        9999;

    display:
        flex;

    flex-direction:
        column;

    gap:6px;
}

.toast {

    min-width:
        220px;

    max-width:
        340px;

    padding:
        11px 13px;

    border-radius:
        12px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(17,24,39,.94);

    backdrop-filter:
        blur(20px);

    color:white;

    font-size:
        9px;

    box-shadow:
        0 20px 50px
        rgba(0,0,0,.38);

    animation:
        toastIn .18s ease;
}

@keyframes toastIn {

    from {

        opacity:0;

        transform:
            translateY(8px);
    }

    to {

        opacity:1;

        transform:
            translateY(0);
    }
}

@media(max-width:850px) {

    .grid {

        grid-template-columns:
            repeat(
                2,
                1fr
            );
    }
}

@media(max-width:650px) {

    .app {

        width:
            calc(100% - 16px);
    }

    .grid {

        grid-template-columns:
            1fr;
    }

    .form {

        grid-template-columns:
            1fr;
    }

    .field.full {

        grid-column:
            auto;
    }

    .top-actions {

        flex-wrap:wrap;

        justify-content:
            flex-end;
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
داشبورد مدیریت سرویس
</div>

</div>

</div>

<div class="top-actions">

<button
    class="top-btn"
    onclick="openPasswordModal()"
>
تغییر رمز
</button>

<button
    class="top-btn"
    onclick="location.href='/logout'"
>
خروج
</button>

</div>

</div>


<!-- ========================================================
     STATS
========================================================= -->

<div class="grid">

<div class="stat">

<div class="stat-top">
<div class="stat-title">
کل کانفیگ‌ها
</div>
</div>

<div
    id="statLinks"
    class="stat-value"
>
0
</div>

<div class="stat-sub">
تعداد کل
</div>

</div>


<div class="stat">

<div class="stat-title">
کانفیگ‌های فعال
</div>

<div
    id="statActive"
    class="stat-value"
>
0
</div>

<div class="stat-sub">
در حال سرویس
</div>

</div>


<div class="stat">

<div class="stat-title">
اتصالات فعال
</div>

<div
    id="statConnections"
    class="stat-value"
>
0
</div>

<div class="stat-sub">
اتصال همزمان
</div>

</div>


<div class="stat">

<div class="stat-title">
آپ‌تایم
</div>

<div
    id="statUptime"
    class="stat-value"
>
00:00:00
</div>

<div
    id="statTime"
    class="stat-sub"
>
-
</div>

</div>

</div>


<!-- ========================================================
     LINKS
========================================================= -->

<section class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
مدیریت کانفیگ‌ها
</div>

<div class="panel-desc">
ساخت، ویرایش، حذف و مدیریت سرویس‌ها
</div>

</div>

<button
    class="primary-btn"
    onclick="openCreateModal()"
>
+ ساخت کانفیگ
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


<!-- ========================================================
     ACTIVITY
========================================================= -->

<section class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
آخرین فعالیت‌ها
</div>

<div class="panel-desc">
رویدادهای مدیریتی و امنیتی
</div>

</div>

</div>

<div
    id="activity"
    class="logs"
>
در حال دریافت...
</div>

</section>

</div>


<!-- ========================================================
     CREATE / EDIT MODAL
========================================================= -->

<div
    id="configModal"
    class="modal"
>

<div class="modal-card">

<div class="modal-head">

<div>

<div
    id="modalTitle"
    class="modal-title"
>
ساخت کانفیگ جدید
</div>

<div class="modal-desc">
تنظیمات کامل سرویس
</div>

</div>

<button
    class="close-btn"
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
۰ = نامحدود
</div>

</div>


<div class="field">

<label>
مدت اعتبار
</label>

<div class="inline">

<input
    id="fieldDays"
    class="input"
    type="number"
    min="0"
    placeholder="30"
/>

<div
    class="switch"
    style="
        width:92px;
        justify-content:center;
    "
>
روز
</div>

</div>

<div class="hint">
۰ = بدون انقضا
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
۰ = نامحدود
</div>

</div>


<div class="field">

<label>
محدودیت IP
</label>

<input
    id="fieldIpLimit"
    class="input"
    type="number"
    min="0"
    placeholder="1"
/>

<div class="hint">
۰ = بدون محدودیت
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

<option value="tlshello">
TLS Hello
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
    maxlength="300"
    placeholder="توضیحات اختیاری"
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
    id="configSaveButton"
    class="modal-btn save"
    onclick="saveConfig()"
>
ساخت کانفیگ
</button>

</div>

</div>

</div>


<!-- ========================================================
     RESULT MODAL
========================================================= -->

<div
    id="resultModal"
    class="modal"
>

<div class="modal-card">

<div class="modal-head">

<div>

<div class="modal-title">
کانفیگ ساخته شد
</div>

<div class="modal-desc">
VLESS ،SUB و صفحه اطلاعات
</div>

</div>

<button
    class="close-btn"
    onclick="closeResultModal()"
>
×
</button>

</div>


<div class="result-box">


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
    class="result-copy"
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
    class="result-copy"
    onclick="copyInput('resultSub')"
>
کپی
</button>

</div>

</div>


<div class="result-group">

<div class="result-label">
صفحه اطلاعات
</div>

<div class="result-row">

<input
    id="resultInfo"
    class="result-input"
    readonly
>

<button
    class="result-copy"
    onclick="copyInput('resultInfo')"
>
کپی
</button>

</div>

</div>


</div>

</div>

</div>


<!-- ========================================================
     DELETE MODAL
========================================================= -->

<div
    id="deleteModal"
    class="modal"
>

<div
    class="modal-card"
    style="max-width:450px"
>

<div class="modal-head">

<div class="delete-title">
حذف کانفیگ
</div>

<button
    class="close-btn"
    onclick="closeDeleteModal()"
>
×
</button>

</div>

<div
    style="
        padding:18px 19px;
    "
>

<div class="delete-text">
این عملیات دائمی است و اطلاعات این کانفیگ از پنل حذف خواهد شد.
</div>

<div
    id="deleteName"
    class="delete-name"
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
    id="deleteConfirmButton"
    class="modal-btn"
    style="
        background:
            linear-gradient(
                135deg,
                #dc2626,
                #991b1b
            );
        color:#fff;
    "
    onclick="confirmDelete()"
>
حذف کانفیگ
</button>

</div>

</div>

</div>


<!-- ========================================================
     PASSWORD MODAL
========================================================= -->

<div
    id="passwordModal"
    class="modal"
>

<div
    class="modal-card"
    style="max-width:450px"
>

<div class="modal-head">

<div>

<div class="modal-title">
تغییر رمز عبور
</div>

<div class="modal-desc">
رمز جدید فوراً ذخیره می‌شود
</div>

</div>

<button
    class="close-btn"
    onclick="closePasswordModal()"
>
×
</button>

</div>


<div class="form">

<div class="field full">

<label>
رمز فعلی
</label>

<input
    id="currentPassword"
    class="input"
    type="password"
/>

</div>

<div class="field full">

<label>
رمز جدید
</label>

<input
    id="newPassword"
    class="input"
    type="password"
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
ذخیره
</button>

</div>

</div>

</div>


<div
    id="toastWrap"
    class="toast-wrap"
></div>


<script>

/* ==========================================================
   Global
========================================================== */

let editUuid = null;
let deleteUuid = null;


/* ==========================================================
   API
========================================================== */

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

    let data = null;

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


/* ==========================================================
   Toast
========================================================== */

function toast(
    message,
    type = "success"
) {

    const element =
        document.createElement(
            "div"
        );

    element.className =
        "toast";

    if (
        type === "error"
    ) {

        element.style.borderColor =
            "rgba(239,68,68,.22)";
    }

    element.textContent =
        message;

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

            element.style.transform =
                "translateY(8px)";

            setTimeout(
                () => {
                    element.remove();
                },
                180
            );

        },
        2500
    );
}


/* ==========================================================
   Modal
========================================================== */

function openCreateModal() {

    editUuid = null;

    document.getElementById(
        "modalTitle"
    ).textContent =
        "ساخت کانفیگ جدید";

    document.getElementById(
        "configSaveButton"
    ).textContent =
        "ساخت کانفیگ";

    resetForm();

    document.getElementById(
        "configModal"
    ).classList.add(
        "show"
    );
}


function openEditModal(
    link
) {

    editUuid =
        link.uuid;

    document.getElementById(
        "modalTitle"
    ).textContent =
        "ویرایش کانفیگ";

    document.getElementById(
        "configSaveButton"
    ).textContent =
        "ذخیره تغییرات";


    document.getElementById(
        "fieldLabel"
    ).value =
        link.label
        || "";

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
        "fieldIpLimit"
    ).value =
        link.ip_limit
        || "";

    document.getElementById(
        "fieldProtocol"
    ).value =
        link.protocol
        || "vless-ws";

    document.getElementById(
        "fieldFingerprint"
    ).value =
        link.fingerprint
        || "chrome";

    document.getElementById(
        "fieldFragment"
    ).value =
        link.fragment_profile
        || "off";

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
        "fieldIpLimit"
    ).value = "";

    document.getElementById(
        "fieldProtocol"
    ).value =
        "vless-ws";

    document.getElementById(
        "fieldFingerprint"
    ).value =
        "chrome";

    document.getElementById(
        "fieldFragment"
    ).value =
        "off";

    document.getElementById(
        "fieldSpeed"
    ).value =
        "";

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
    ).value =
        "";

    document.getElementById(
        "fieldNote"
    ).value =
        "";
}


/* ==========================================================
   Save
========================================================== */

async function saveConfig() {

    const button =
        document.getElementById(
            "configSaveButton"
        );

    const original =
        button.textContent;

    const payload = {

        label:
            document.getElementById(
                "fieldLabel"
            ).value.trim(),

        volume_value:
            Number(
                document.getElementById(
                    "fieldVolume"
                ).value
                || 0
            ),

        volume_unit:
            document.getElementById(
                "fieldVolumeUnit"
            ).value,

        duration_days:
            Number(
                document.getElementById(
                    "fieldDays"
                ).value
                || 0
            ),

        concurrent_limit:
            Number(
                document.getElementById(
                    "fieldConcurrent"
                ).value
                || 0
            ),

        ip_limit:
            Number(
                document.getElementById(
                    "fieldIpLimit"
                ).value
                || 0
            ),

        protocol:
            document.getElementById(
                "fieldProtocol"
            ).value,

        fingerprint:
            document.getElementById(
                "fieldFingerprint"
            ).value,

        fragment:
            document.getElementById(
                "fieldFragment"
            ).value,

        speed_limit_value:
            Number(
                document.getElementById(
                    "fieldSpeed"
                ).value
                || 0
            ),

        speed_limit_unit:
            document.getElementById(
                "fieldSpeedUnit"
            ).value,

        port:
            Number(
                document.getElementById(
                    "fieldPort"
                ).value
                || 443
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


    if (
        !payload.label
    ) {

        toast(
            "نام کانفیگ را وارد کنید.",
            "error"
        );

        return;
    }


    try {

        button.disabled = true;

        button.textContent =
            "در حال ذخیره...";


        let result;


        if (editUuid) {

            result =
                await api(
                    "/api/links/" +
                    encodeURIComponent(
                        editUuid
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

            toast(
                "تغییرات ذخیره شد."
            );

            closeConfigModal();


        } else {

            result =
                await api(
                    "/api/links",
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
                "کانفیگ با موفقیت ساخته شد."
            );
        }


        await refreshAll();


    } catch (error) {

        toast(
            error.message,
            "error"
        );

    } finally {

        button.disabled =
            false;

        button.textContent =
            original;
    }
}


/* ==========================================================
   Result
========================================================== */

function showResult(
    data
) {

    document.getElementById(
        "resultVless"
    ).value =
        data.vless_link
        || "";

    document.getElementById(
        "resultSub"
    ).value =
        data.sub_url
        || "";

    document.getElementById(
        "resultInfo"
    ).value =
        data.info_url
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

        await navigator
            .clipboard
            .writeText(
                input.value
            );

        toast(
            "کپی شد."
        );

    } catch {

        input.select();

        document.execCommand(
            "copy"
        );

        toast(
            "کپی شد."
        );
    }
}


/* ==========================================================
   Delete
========================================================== */

function openDeleteModal(
    uuid,
    name
) {

    deleteUuid =
        uuid;

    document.getElementById(
        "deleteName"
    ).textContent =
        name;

    document.getElementById(
        "deleteModal"
    ).classList.add(
        "show"
    );
}


function closeDeleteModal() {

    deleteUuid =
        null;

    document.getElementById(
        "deleteModal"
    ).classList.remove(
        "show"
    );
}


async function confirmDelete() {

    if (!deleteUuid)
        return;

    const button =
        document.getElementById(
            "deleteConfirmButton"
        );

    button.disabled = true;

    button.textContent =
        "در حال حذف...";


    try {

        await api(
            "/api/links/" +
            encodeURIComponent(
                deleteUuid
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
            "error"
        );

    } finally {

        button.disabled = false;

        button.textContent =
            "حذف کانفیگ";
    }
}


/* ==========================================================
   Toggle
========================================================== */

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
            "error"
        );
    }
}


/* ==========================================================
   Reset Usage
========================================================== */

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
            "error"
        );
    }
}


/* ==========================================================
   Escape
========================================================== */

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


/* ==========================================================
   Render Links
========================================================== */

function renderLinks(
    links
) {

    const table =
        document.getElementById(
            "linksTable"
        );

    if (
        !links.length
    ) {

        table.innerHTML = `

        <tr>

            <td
                colspan="7"
                style="
                    text-align:center;
                    padding:40px 10px;
                    color:
                        rgba(255,255,255,.30);
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

        const usage =
            Math.min(
                100,
                Number(
                    link.usage_percent
                    || 0
                )
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
    status
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
        --usage:${usage}%;
    "
>

<div
    class="usage-fill"
></div>

</div>

</div>

</td>


<td>

<strong>
${Number(
    link.connections
    || 0
)}
</strong>

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
    onclick='openInfo(
        ${JSON.stringify(
            link.info_url
        )}
    )'
>
اطلاعات
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
            link.active
            ? ""
            : "success"
        }
    "
    onclick='toggleLink(
        ${JSON.stringify(
            link.uuid
        )},
        ${!link.active}
    )'
>
${
    link.active
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
ریست مصرف
</button>


<button
    class="action danger"
    onclick='openDeleteModal(
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


/* ==========================================================
   Copy Direct
========================================================== */

async function copyDirect(
    text
) {

    try {

        await navigator
            .clipboard
            .writeText(
                text
            );

        toast(
            "لینک کپی شد."
        );

    } catch {

        window.prompt(
            "لینک:",
            text
        );
    }
}


/* ==========================================================
   Open Info
========================================================== */

function openInfo(
    url
) {

    window.open(
        url,
        "_blank",
        "noopener"
    );
}


/* ==========================================================
   Edit wrapper
========================================================== */

function openEdit(
    link
) {

    openEditModal(
        link
    );
}


/* ==========================================================
   Stats
========================================================== */

let serverStartTime = null;
let lastStatsAt = null;


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
            "statTime"
        ).textContent =
            new Date(
                data.server_time
            ).toLocaleTimeString(
                "fa-IR"
            );


        serverStartTime =
            Date.now()
            - (
                Number(
                    data.uptime_seconds
                )
                * 1000
            );

        lastStatsAt =
            Date.now();

    } catch (error) {

        console.error(
            error
        );
    }
}


/* ==========================================================
   Local uptime tick
========================================================== */

function tickUptime() {

    if (
        !serverStartTime
    ) {
        return;
    }

    const seconds =
        Math.floor(
            (
                Date.now()
                - serverStartTime
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

    const d =
        Math.floor(
            seconds / 86400
        );

    const h =
        Math.floor(
            (
                seconds % 86400
            ) / 3600
        );

    const m =
        Math.floor(
            (
                seconds % 3600
            ) / 60
        );

    const s =
        seconds % 60;


    const base =
        [
            String(h).padStart(
                2,
                "0"
            ),
            String(m).padStart(
                2,
                "0"
            ),
            String(s).padStart(
                2,
                "0"
            )
        ].join(":");


    if (d > 0) {

        return (
            d +
            "d " +
            base
        );
    }

    return base;
}


/* ==========================================================
   Activity
========================================================== */

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
                "activity"
            );

        if (
            !data.items.length
        ) {

            container.innerHTML =
                `
                <div
                    style="
                        color:
                            rgba(255,255,255,.25);
                        font-size:9px;
                        padding:8px 0;
                    "
                >
                    هنوز فعالیتی ثبت نشده است.
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
        
    } catch (error) {

        console.error(
            error
        );
    }
}


/* ==========================================================
   Refresh Links
========================================================== */

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


/* ==========================================================
   Refresh All
========================================================== */

async function refreshAll() {

    await Promise.all([
        refreshStats(),
        refreshLinks(),
        refreshActivity()
    ]);
}


/* ==========================================================
   Password
========================================================== */

function openPasswordModal() {

    document.getElementById(
        "currentPassword"
    ).value = "";

    document.getElementById(
        "newPassword"
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
                            document
                            .getElementById(
                                "currentPassword"
                            )
                            .value,

                        new_password:
                            document
                            .getElementById(
                                "newPassword"
                            )
                            .value
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
            "error"
        );
    }
}


/* ==========================================================
   Modal click outside
========================================================== */

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
                    event.target ===
                    this
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
                .classList.remove(
                    "show"
                );
        }

    }
);


/* ==========================================================
   Start
========================================================== */

refreshAll();

/*
    Backend stats هر ۱ ثانیه
*/
setInterval(
    refreshStats,
    1000
);

/*
    جدول کانفیگ‌ها هر ۱ ثانیه
*/
setInterval(
    refreshLinks,
    1000
);

/*
    Activity هر ۱ ثانیه
*/
setInterval(
    refreshActivity,
    1000
);

/*
    آپتایم بین درخواست‌ها هم هر ۱ ثانیه tick می‌شود
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
    response_class=HTMLResponse,
)
async def dashboard(
    request: Request,
):

    if not await session_valid(
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
# Info Page
# ============================================================

def build_info_html(
    uid: str,
    link: dict,
):

    used = safe_int(
        link.get(
            "used_bytes",
            0,
        )
    )

    limit = safe_int(
        link.get(
            "limit_bytes",
            0,
        )
    )

    connections = (
        current_connections_for(
            uid
        )
    )

    usage_percent = (
        0
        if limit <= 0
        else min(
            100,
            round(
                used
                / limit
                * 100,
                1,
            ),
        )
    )

    if link.get(
        "expires_at"
    ):

        try:

            expiration_text = (
                datetime.fromisoformat(
                    link[
                        "expires_at"
                    ]
                ).strftime(
                    "%Y/%m/%d %H:%M"
                )
            )

        except Exception:

            expiration_text = (
                link.get(
                    "expires_at"
                )
            )

    else:

        expiration_text = (
            "بدون انقضا"
        )

    limit_text = (
        "نامحدود"
        if limit <= 0
        else format_bytes(
            limit
        )
    )

    concurrent_limit = safe_int(
        link.get(
            "concurrent_limit",
            0,
        )
    )

    fragment_name = {
        "off":
            "خاموش",

        "tlshello":
            "TLS Hello",

        "safe":
            "Safe",

        "balanced":
            "Balanced",

        "aggressive":
            "Aggressive",
    }.get(
        link.get(
            "fragment_profile",
            "off",
        ),
        "خاموش",
    )

    return rf"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>
{escape_html_server(
    link.get(
        "label",
        "PixonPanel",
    )
)}
</title>

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
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
    rel="stylesheet"
>

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
            transparent 31%
        ),
        radial-gradient(
            circle at bottom left,
            rgba(168,85,247,.12),
            transparent 30%
        ),
        #07070a;
}}

.container {{

    width:100%;

    max-width:760px;

    margin:auto;
}}

.card {{

    border-radius:26px;

    padding:24px;

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

.brand {{

    display:flex;

    align-items:center;

    gap:12px;
}}

.logo {{

    width:47px;
    height:47px;

    display:flex;

    align-items:center;
    justify-content:center;

    border-radius:15px;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight:900;
}}

h1 {{

    margin:0;

    font-size:22px;

    font-weight:900;
}}

.subtext {{

    margin-top:3px;

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

    margin-top:19px;
}}

.item {{

    padding:14px;

    border-radius:15px;

    border:
        1px solid
        rgba(255,255,255,.06);

    background:
        rgba(255,255,255,.03);
}}

.item-label {{

    color:
        rgba(255,255,255,.36);

    font-size:9px;
}}

.item-value {{

    margin-top:5px;

    font-size:12px;

    font-weight:800;

    word-break:break-word;
}}

.usage {{

    margin-top:18px;
}}

.usage-top {{

    display:flex;

    justify-content:space-between;

    color:
        rgba(255,255,255,.42);

    font-size:9px;
}}

.progress {{

    height:8px;

    margin-top:7px;

    overflow:hidden;

    border-radius:999px;

    background:
        rgba(255,255,255,.07);
}}

.progress-fill {{

    width:
        {usage_percent}%;

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

    margin-top:17px;

    padding-top:17px;

    border-top:
        1px solid
        rgba(255,255,255,.07);
}}

.section-title {{

    font-size:12px;

    font-weight:800;

    margin-bottom:9px;
}}

.link {{

    display:block;

    padding:11px 12px;

    margin-top:6px;

    border-radius:11px;

    color:
        rgba(255,255,255,.72);

    text-decoration:none;

    background:
        rgba(255,255,255,.035);

    border:
        1px solid
        rgba(255,255,255,.06);

    direction:ltr;

    text-align:left;

    word-break:break-all;

    font-family:
        Consolas,
        monospace;

    font-size:9px;
}}

.notice {{

    padding:15px;

    border-radius:15px;

    background:
        rgba(255,255,255,.03);

    border:
        1px solid
        rgba(255,255,255,.07);

    color:
        rgba(255,255,255,.62);

    line-height:2;

    font-size:10px;
}}

.app-section {{

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

    display:block;

    text-decoration:none;

    padding:10px 11px;

    border-radius:11px;

    background:
        rgba(255,255,255,.035);

    border:
        1px solid
        rgba(255,255,255,.06);

    color:
        rgba(255,255,255,.72);

    font-size:9px;

    transition:.18s ease;
}}

.app:hover {{

    background:
        rgba(255,255,255,.06);
}}

.support {{

    margin-top:19px;

    padding-top:16px;

    border-top:
        1px solid
        rgba(255,255,255,.07);

    text-align:center;

    color:
        rgba(255,255,255,.36);

    font-size:10px;
}}

.support a {{

    color:#a78bfa;

    text-decoration:none;
}}

@media(max-width:600px) {{

    .stats {{
        grid-template-columns:
            1fr;
    }}

    .app-section {{
        grid-template-columns:
            1fr;
    }}

}}

</style>

</head>

<body>

<div class="container">

<div class="card">

<div class="brand">

<div class="logo">
P
</div>

<div>

<h1>
{escape_html_server(
    link.get(
        "label",
        "PixonPanel",
    )
)}
</h1>

<div class="subtext">
PixonPanel · اطلاعات سرویس
</div>

</div>

</div>


<div class="usage">

<div class="usage-top">

<span>
مصرف
</span>

<span>
{format_bytes(used)}
/
{limit_text}
</span>

</div>

<div class="progress">

<div class="progress-fill"></div>

</div>

</div>


<div class="stats">


<div class="item">

<div class="item-label">
Protocol
</div>

<div class="item-value">
{escape_html_server(
    link.get(
        "protocol",
        "-"
    )
)}
</div>

</div>


<div class="item">

<div class="item-label">
Fingerprint
</div>

<div class="item-value">
{escape_html_server(
    link.get(
        "fingerprint",
        "-"
    )
)}
</div>

</div>


<div class="item">

<div class="item-label">
Fragment
</div>

<div class="item-value">
{escape_html_server(
    fragment_name
)}
</div>

</div>


<div class="item">

<div class="item-label">
اتصالات فعال
</div>

<div class="item-value">
{connections}
/
{concurrent_limit or "∞"}
</div>

</div>


<div class="item">

<div class="item-label">
محدودیت IP
</div>

<div class="item-value">
{safe_int(
    link.get(
        "ip_limit",
        0,
    )
) or "∞"}
</div>

</div>


<div class="item">

<div class="item-label">
تاریخ انقضا
</div>

<div class="item-value">
{escape_html_server(
    expiration_text
)}
</div>

</div>

</div>


<div class="section">

<div class="section-title">
لینک‌های سرویس
</div>

<a
    class="link"
    href="/sub/{uid}"
    target="_blank"
>
SUB
</a>

</div>


<div class="section">

<div class="section-title">
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

<br><br>

🔹 Happ

<div class="app-section">

<a
    class="app"
    href="https://play.google.com/store/apps/details?id=com.happproxy"
    target="_blank"
>
Google Play · Happ
</a>

<a
    class="app"
    href="https://dl.v2rayng.org/releases/latest/v2rayNG_2.2.6_arm64-v8a.apk"
    target="_blank"
>
APK · v2rayNG
</a>

<a
    class="app"
    href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box"
    target="_blank"
>
Google Play · V2Box
</a>

</div>

<br>

<strong>
🍎 iPhone / iPad
</strong>

<div class="app-section">

<a
    class="app"
    href="https://apps.apple.com/app/happ-proxy-utility/id6504287215"
    target="_blank"
>
App Store · Happ
</a>

<a
    class="app"
    href="https://apps.apple.com/app/v2box-v2ray-client/id6446814690"
    target="_blank"
>
App Store · V2Box
</a>

<a
    class="app"
    href="https://apps.apple.com/app/streisand/id6450534064"
    target="_blank"
>
App Store · Streisand
</a>

<a
    class="app"
    href="https://apps.apple.com/app/foxray/id6448898396"
    target="_blank"
>
App Store · FoXray
</a>

</div>

<br>

<strong>
💻 Windows
</strong>

<div class="app-section">

<a
    class="app"
    href="https://github.com/2dust/v2rayN/releases/latest"
    target="_blank"
>
Windows · v2rayN
</a>

<a
    class="app"
    href="https://happ-proxy.com/"
    target="_blank"
>
Windows · Happ
</a>

</div>

<br><br>

⚠️ اگر از نسخه قدیمی برنامه استفاده می‌کنید،
قبل از استفاده از کانفیگ‌های جدید، برنامه را آپدیت کنید.

<br><br>

🚀 کانفیگ‌های جدید با نسخه‌های جدید برنامه‌ها
سازگاری بهتری دارند و استفاده از نسخه‌های قدیمی
ممکن است باعث مشکل اتصال یا عملکرد شود.

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


def escape_html_server(
    value,
) -> str:

    return (
        str(
            value
            or ""
        )
        .replace(
            "&",
            "&amp;",
        )
        .replace(
            "<",
            "&lt;",
        )
        .replace(
            ">",
            "&gt;",
        )
        .replace(
            '"',
            "&quot;",
        )
        .replace(
            "'",
            "&#039;",
        )
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
            uptime_seconds(),

        "port":
            PORT,

        "data_dir":
            str(
                DATA_DIR
            ),
    }


# ============================================================
# Optional relay integration
# ============================================================

try:

    import relay_vless  # noqa

    logger.info(
        "relay_vless module detected."
    )

except Exception:

    relay_vless = None


try:

    import xhttp_siz10  # noqa

    logger.info(
        "xhttp_siz10 module detected."
    )

except Exception:

    xhttp_siz10 = None


# ============================================================
# Startup
# ============================================================

@app.on_event(
    "startup"
)
async def startup():

    global HTTP_CLIENT

    HTTP_CLIENT = httpx.AsyncClient(
        timeout=httpx.Timeout(
            30.0,
            connect=10.0,
        ),
        follow_redirects=True,
        limits=httpx.Limits(
            max_connections=300,
            max_keepalive_connections=80,
        ),
    )

    await load_state()

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
                DEFAULT_PROTOCOL,

            "fingerprint":
                DEFAULT_FINGERPRINT,

            "fragment":
                None,

            "fragment_profile":
                "off",

            "alpn":
                "http/1.1",

            "port":
                DEFAULT_PORT,

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

    await activity(
        (
            f"{APP_NAME} "
            f"v{APP_VERSION} "
            "راه‌اندازی شد"
        ),
        "ok",
        "system",
    )

    logger.info(
        "%s started on 0.0.0.0:%s",
        APP_NAME,
        PORT,
    )

    logger.info(
        "Data directory: %s",
        DATA_DIR,
    )


@app.on_event(
    "shutdown"
)
async def shutdown():

    await save_state()

    if HTTP_CLIENT:

        await HTTP_CLIENT.aclose()


# ============================================================
# Error handler
# ============================================================

@app.exception_handler(
    Exception
)
async def exception_handler(
    request: Request,
    exc: Exception,
):

    global TOTAL_ERRORS

    TOTAL_ERRORS += 1

    ERROR_LOG.append(
        {
            "time":
                now_iso(),

            "method":
                request.method,

            "path":
                str(
                    request.url.path
                ),

            "error":
                str(exc),
        }
    )

    logger.exception(
        "Unhandled exception"
    )

    return JSONResponse(
        {
            "ok":
                False,

            "error":
                "internal server error",

            "path":
                str(
                    request.url.path
                ),
        },
        status_code=500,
    )


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        workers=1,
    )

# ============================================================
# PixonPanel - Railway Ready
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
APP_VERSION = "10.0"

SUPPORT_USERNAME = "@Pixonal"
SUPPORT_URL = "https://t.me/Pixonal"

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
# RAILWAY CONFIG
# ============================================================

PORT = int(
    os.environ.get(
        "PORT",
        "8000",
    )
)

# Railway Volume:
# اگر Volume متصل باشد Railway مقدار RAILWAY_VOLUME_MOUNT_PATH
# را در اختیار برنامه قرار می‌دهد.
#
# در غیر این صورت ./data استفاده می‌شود.

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
    """
    SECRET_KEY دائمی برای Railway.
    اگر متغیر محیطی SECRET_KEY وجود داشته باشد همان استفاده می‌شود.
    در غیر این صورت روی Volume ذخیره می‌شود.
    """

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
# HOST
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

error_logs = deque(
    maxlen=100
)

activity_logs = deque(
    maxlen=250
)

hourly_traffic = defaultdict(
    int
)

http_client: httpx.AsyncClient | None = None


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
# PASSWORD
# ============================================================

def hash_password(
    password: str,
) -> str:

    payload = (
        password
        + SECRET_KEY
    ).encode(
        "utf-8"
    )

    return hashlib.sha256(
        payload
    ).hexdigest()


# رمز پیش‌فرض
DEFAULT_ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "pxpanel2026",
)

AUTH = {
    "password_hash": hash_password(
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


async def create_session() -> str:

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
) -> bool:

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
                "links": dict(
                    LINKS
                ),
                "subs": dict(
                    SUBS
                ),
                "password_hash": AUTH[
                    "password_hash"
                ],
                "saved_at": datetime.now().isoformat(),
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
# HOST
# ============================================================

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

            host = host.split(
                ":"
            )[0].strip()

            CONFIG[
                "host"
            ] = host

            return host

    railway_domain = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway_domain:
        return railway_domain

    return CONFIG[
        "host"
    ]


# ============================================================
# HELPERS
# ============================================================

def generate_uuid():

    value = secrets.token_hex(
        16
    )

    return (
        f"{value[:8]}-"
        f"{value[8:12]}-"
        f"{value[12:16]}-"
        f"{value[16:20]}-"
        f"{value[20:32]}"
    )


def now_ir():

    if IRAN_TZ:

        return datetime.now(
            IRAN_TZ
        )

    return datetime.now()


def uptime():

    seconds = int(
        time.time()
        - stats[
            "start_time"
        ]
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


def fmt_bytes(
    value: int,
):

    value = int(
        value or 0
    )

    if value < 1024:

        return (
            f"{value} B"
        )

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

    return int(
        value
    )


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
            value
            * 1024
        )

    if unit == "MB":

        return int(
            value
            * 1024
            * 1024
        )

    return int(
        value
    )


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
        if connection.get(
            "uuid"
        ) == uuid
        and connection.get(
            "ip"
        )
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


# ============================================================
# VLESS LINK GENERATION
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

    if protocol == "vless-ws":

        path = (
            f"/ws/{uuid}"
        )

        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_value,
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
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_value,
        }

    query = "&".join(
        f"{key}="
        f"{quote(str(value))}"
        for key, value in params.items()
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
            for item in LINKS.values()
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

            LINKS[
                uid
            ] = {

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
                    "",

                "port":
                    DEFAULT_PORT,

                "ip_limit":
                    0,

                "speed_limit_bytes":
                    DEFAULT_SPEED_LIMIT,
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
            ).strip()[:200],

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
                int(
                    ip_limit
                ),
            ),

        "speed_limit_bytes":
            max(
                0,
                int(
                    speed_limit_bytes
                ),
            ),
    }

    async with LINKS_LOCK:

        LINKS[
            uid
        ] = record

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

                    ids.append(
                        uid
                    )

    asyncio.create_task(
        save_state()
    )

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

        del LINKS[
            uid
        ]

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

                    ids.remove(
                        uid
                    )

    asyncio.create_task(
        save_state()
    )

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
        ] = bool(
            active
        )

        record = LINKS[
            uid
        ]

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

    asyncio.create_task(
        save_state()
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

    asyncio.create_task(
        save_state()
    )

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

        if old_sub and old_sub in SUBS:

            ids = SUBS[
                old_sub
            ].get(
                "link_ids",
                [],
            )

            if uid in ids:
                ids.remove(
                    uid
                )

        if sub_id and sub_id in SUBS:

            ids = SUBS[
                sub_id
            ].setdefault(
                "link_ids",
                [],
            )

            if uid not in ids:

                ids.append(
                    uid
                )

    async with LINKS_LOCK:

        if uid in LINKS:

            LINKS[
                uid
            ][
                "sub_id"
            ] = sub_id

    asyncio.create_task(
        save_state()
    )

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

    asyncio.create_task(
        save_state()
    )

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

@app.on_event(
    "startup"
)
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

    http_client = (
        httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
        )
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

    logger.info(
        "Data directory: %s",
        DATA_DIR,
    )


@app.on_event(
    "shutdown"
)
async def shutdown():

    await save_state()

    if http_client:

        await http_client.aclose()


# ============================================================
# LANDING PAGE
# ============================================================

LANDING_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
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

:root {
    color-scheme: dark;
}

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

    padding: 22px;

    overflow: hidden;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(99,102,241,.22),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 85%,
            rgba(139,92,246,.18),
            transparent 30%
        ),
        #07070a;

    color: white;
}

.background {

    position: fixed;

    inset: 0;

    pointer-events: none;

    overflow: hidden;
}

.glow {

    position: absolute;

    width: 260px;
    height: 260px;

    border-radius: 999px;

    filter: blur(100px);

    opacity: .18;
}

.glow-1 {

    top: -100px;
    right: -60px;

    background: #6366f1;
}

.glow-2 {

    bottom: -120px;
    left: -80px;

    background: #a855f7;
}

.grid {

    position: absolute;

    inset: 0;

    opacity: .035;

    background-size:
        32px 32px;

    background-image:
        linear-gradient(
            rgba(255,255,255,.2) 1px,
            transparent 1px
        ),
        linear-gradient(
            90deg,
            rgba(255,255,255,.2) 1px,
            transparent 1px
        );
}

.shell {

    width: 100%;

    max-width: 560px;

    position: relative;

    z-index: 2;
}

.card {

    padding: 32px;

    border-radius: 30px;

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.075),
            rgba(255,255,255,.025)
        );

    border:
        1px solid
        rgba(255,255,255,.09);

    backdrop-filter:
        blur(28px)
        saturate(150%);

    -webkit-backdrop-filter:
        blur(28px)
        saturate(150%);

    box-shadow:
        0 30px 90px
        rgba(0,0,0,.45),

        inset
        0 1px 0
        rgba(255,255,255,.05);

    animation:
        cardIn
        .55s ease both;
}

@keyframes cardIn {

    from {
        opacity: 0;
        transform:
            translateY(18px)
            scale(.98);
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

    width: 50px;
    height: 50px;

    border-radius: 16px;

    display: flex;

    align-items: center;
    justify-content: center;

    font-size: 18px;

    font-weight: 900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    box-shadow:
        0 14px 35px
        rgba(99,102,241,.25);
}

.brand-title {

    font-weight: 900;

    font-size: 17px;
}

.brand-sub {

    margin-top: 4px;

    font-size: 11px;

    color:
        rgba(255,255,255,.42);
}

.status {

    width: fit-content;

    padding:
        7px 11px;

    margin-bottom: 17px;

    border-radius: 999px;

    font-size: 11px;

    color:
        #86efac;

    background:
        rgba(34,197,94,.07);

    border:
        1px solid
        rgba(34,197,94,.15);
}

h1 {

    margin: 0;

    font-size: 29px;

    line-height: 1.5;

    font-weight: 900;

    letter-spacing: -.5px;
}

.description {

    margin-top: 13px;

    color:
        rgba(255,255,255,.56);

    line-height: 2;

    font-size: 13px;
}

.command-box {

    margin-top: 24px;

    padding: 15px;

    border-radius: 18px;

    background:
        rgba(0,0,0,.18);

    border:
        1px solid
        rgba(255,255,255,.08);
}

.command-label {

    margin-bottom: 8px;

    font-size: 11px;

    color:
        rgba(255,255,255,.38);
}

.command {

    padding:
        12px 14px;

    direction: ltr;

    text-align: left;

    border-radius: 13px;

    font-family:
        Consolas,
        monospace;

    color:
        #c4b5fd;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.07);
}

.actions {

    display: flex;

    gap: 10px;

    margin-top: 21px;
}

.button {

    flex: 1;

    padding:
        13px 16px;

    border-radius: 14px;

    text-decoration: none;

    text-align: center;

    font-size: 13px;

    font-weight: 800;

    transition:
        transform .2s ease,
        opacity .2s ease;
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
        rgba(255,255,255,.85);

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);
}

.footer {

    display: flex;

    align-items: center;

    justify-content:
        space-between;

    margin-top: 21px;

    padding-top: 17px;

    border-top:
        1px solid
        rgba(255,255,255,.07);

    font-size: 10px;

    color:
        rgba(255,255,255,.35);
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

<div class="background">

    <div class="glow glow-1"></div>
    <div class="glow glow-2"></div>

    <div class="grid"></div>

</div>

<main class="shell">

<section class="card">

<div class="brand">

<div class="logo">
P
</div>

<div>

<div class="brand-title">
PixonPanel
</div>

<div class="brand-sub">
پنل مدیریت سرویس و کانفیگ
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

<div class="description">
این صفحه، درگاه عمومی PixonPanel است.
برای دسترسی به داشبورد مدیریت، از مسیر ورود استفاده کنید.
</div>

<div class="command-box">

<div class="command-label">
مسیر ورود
</div>

<div class="command">
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
    rel="noopener"
>
@Pixonal
</a>

</div>

</section>

</main>

</body>

</html>
"""


# ============================================================
# ROOT
# ============================================================

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

@app.get(
    "/health"
)
async def health():

    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "connections": len(
            connections
        ),
        "uptime": uptime(),
    }


# ============================================================
# LOGIN PAGE
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
    box-sizing: border-box;
}

html,
body {
    margin: 0;
}

body {

    min-height: 100vh;

    display: flex;

    justify-content: center;

    align-items: center;

    padding: 20px;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(99,102,241,.20),
            transparent 32%
        ),
        #07070a;

    color: white;
}

.card {

    width: 100%;

    max-width: 420px;

    padding: 30px;

    border-radius: 27px;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.09);

    backdrop-filter:
        blur(28px);

    box-shadow:
        0 30px 90px
        rgba(0,0,0,.45);
}

.logo {

    width: 49px;
    height: 49px;

    display: flex;

    justify-content: center;
    align-items: center;

    border-radius: 16px;

    margin-bottom: 22px;

    font-weight: 900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

h1 {

    margin: 0;

    font-size: 25px;

    font-weight: 900;
}

.description {

    margin-top: 9px;

    color:
        rgba(255,255,255,.48);

    line-height: 1.9;

    font-size: 12px;
}

form {
    margin-top: 22px;
}

label {

    display: block;

    margin-bottom: 8px;

    font-size: 12px;

    color:
        rgba(255,255,255,.55);
}

.input {

    width: 100%;

    border:
        1px solid
        rgba(255,255,255,.08);

    outline: none;

    border-radius: 14px;

    padding: 14px;

    direction: ltr;

    text-align: left;

    color: white;

    background:
        rgba(0,0,0,.18);

    font-family:
        "Vazirmatn",
        sans-serif;
}

.input:focus {

    border-color:
        rgba(129,140,248,.6);

    box-shadow:
        0 0 0
        4px
        rgba(99,102,241,.08);
}

button {

    width: 100%;

    border: 0;

    margin-top: 13px;

    padding: 14px;

    border-radius: 14px;

    color: white;

    cursor: pointer;

    font-family:
        "Vazirmatn",
        sans-serif;

    font-weight: 800;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.error {

    margin-top: 12px;

    padding: 11px 12px;

    border-radius: 12px;

    color: #fca5a5;

    background:
        rgba(239,68,68,.08);

    border:
        1px solid
        rgba(239,68,68,.16);

    font-size: 11px;
}

.support {

    display: block;

    margin-top: 18px;

    text-align: center;

    color:
        #a78bfa;

    text-decoration: none;

    font-size: 11px;
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

<div class="description">
برای ادامه، رمز عبور پنل مدیریت را وارد کنید.
</div>

<form
    method="post"
    action="/login"
>

<label>
رمز عبور
</label>

<input
    class="input"
    type="password"
    name="password"
    autocomplete="current-password"
    autofocus
    placeholder="رمز عبور"
/>

<button type="submit">
ورود به پنل
</button>

</form>

<a
    class="support"
    href="https://t.me/Pixonal"
    target="_blank"
    rel="noopener"
>
پشتیبانی @Pixonal
</a>

</div>

</body>

</html>
"""


# ============================================================
# LOGIN HELPERS
# ============================================================

def login_error_html(
    message: str,
):

    safe_message = (
        message
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
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


# ============================================================
# LOGIN GET
# ============================================================

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


# ============================================================
# LOGIN POST
# ============================================================

@app.post(
    "/login"
)
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

        ip = client_ip(
            request
        )

        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق "
                f"از {ip}"
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

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=True,
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

@app.post(
    "/api/login"
)
async def api_login(
    request: Request,
):

    body = await request.json()

    password = str(
        body.get(
            "password",
            "",
        )
    )

    ip = client_ip(
        request
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
                f"از {ip}"
            ),
            "err",
        )

        raise HTTPException(
            status_code=401,
            detail="رمز عبور اشتباه است",
        )

    token = await create_session()

    response = JSONResponse(
        {
            "ok": True,
            "authenticated": True,
        }
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=True,
    )

    log_activity(
        "auth",
        (
            f"ورود موفق به پنل "
            f"از {ip}"
        ),
        "ok",
    )

    return response


# ============================================================
# LOGOUT
# ============================================================

@app.get(
    "/logout"
)
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


@app.post(
    "/api/logout"
)
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


@app.get(
    "/api/me"
)
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

@app.post(
    "/api/change-password"
)
async def api_change_password(
    request: Request,
    token=Depends(require_auth),
):

    body = await request.json()

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

    if len(
        new_password
    ) < 4:

        raise HTTPException(
            status_code=400,
            detail=(
                "رمز جدید باید حداقل "
                "۴ کاراکتر باشد"
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
        "ok": True
    }


# ============================================================
# LINKS API
# ============================================================

@app.post(
    "/api/links"
)
async def create_link_api(
    request: Request,
    _=Depends(require_auth),
):

    body = await request.json()

    try:

        limit_value = float(
            body.get(
                "limit_value",
                0,
            )
            or 0
        )

    except Exception:

        limit_value = 0

    limit_unit = (
        body.get(
            "limit_unit",
            "GB",
        )
        or "GB"
    )

    limit_bytes = (
        0
        if limit_value <= 0
        else parse_size_to_bytes(
            limit_value,
            limit_unit,
        )
    )

    try:

        expires_days = int(
            body.get(
                "expires_days",
                0,
            )
            or 0
        )

    except Exception:

        expires_days = 0

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

    try:

        port = int(
            body.get(
                "port",
                DEFAULT_PORT,
            )
            or DEFAULT_PORT
        )

    except Exception:

        port = DEFAULT_PORT

    try:

        ip_limit = int(
            body.get(
                "ip_limit",
                0,
            )
            or 0
        )

    except Exception:

        ip_limit = 0

    try:

        speed_value = float(
            body.get(
                "speed_limit_value",
                0,
            )
            or 0
        )

    except Exception:

        speed_value = 0

    speed_unit = (
        body.get(
            "speed_limit_unit",
            "MBIT",
        )
        or "MBIT"
    )

    speed_bytes = (
        0
        if speed_value <= 0
        else parse_speed_to_bytes(
            speed_value,
            speed_unit,
        )
    )

    uid, link = await make_link(
        label=body.get(
            "label",
            "لینک جدید",
        ),
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get(
            "note",
            "",
        ),
        sub_id=body.get(
            "sub_id"
        ),
        protocol=body.get(
            "protocol",
            DEFAULT_PROTOCOL,
        ),
        fingerprint=body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        ),
        alpn=body.get(
            "alpn",
            "",
        ),
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_bytes,
    )

    host = get_host(
        request
    )

    return {
        "uuid": uid,
        **link,
        "expired":
            is_link_expired(
                link
            ),
        "vless_link":
            vless_link_for_link(
                link,
                uid,
                host,
            ),
        "sub_url":
            f"https://{host}/sub/{uid}",
    }


@app.get(
    "/api/links"
)
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

        result.append(
            {
                "uuid":
                    uid,

                **link,

                "expired":
                    is_link_expired(
                        link
                    ),

                "vless_link":
                    vless_link_for_link(
                        link,
                        uid,
                        host,
                    ),

                "sub_url":
                    f"https://{host}/sub/{uid}",

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


@app.patch(
    "/api/links/{uid}"
)
async def update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    body = await request.json()

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

        label = link.get(
            "label"
        )

        if "active" in body:

            link[
                "active"
            ] = bool(
                body[
                    "active"
                ]
            )

        if "label" in body:

            link[
                "label"
            ] = str(
                body[
                    "label"
                ]
            )[:60]

        if "note" in body:

            link[
                "note"
            ] = str(
                body[
                    "note"
                ]
            )[:200]

        if body.get(
            "reset_usage",
            False,
        ):

            link[
                "used_bytes"
            ] = 0

        if "limit_value" in body:

            try:

                value = float(
                    body.get(
                        "limit_value",
                        0,
                    )
                    or 0
                )

            except Exception:

                value = 0

            unit = (
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

            try:

                days = int(
                    body.get(
                        "expires_days",
                        0,
                    )
                    or 0
                )

            except Exception:

                days = 0

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
                if fingerprint
                in FINGERPRINTS
                else DEFAULT_FINGERPRINT
            )

        if "alpn" in body:

            link[
                "alpn"
            ] = str(
                body.get(
                    "alpn",
                    "",
                )
            )[:100]

        if "port" in body:

            try:

                p = int(
                    body.get(
                        "port",
                        DEFAULT_PORT,
                    )
                    or DEFAULT_PORT
                )

            except Exception:

                p = DEFAULT_PORT

            link[
                "port"
            ] = (
                p
                if (
                    MIN_PORT
                    <= p
                    <= MAX_PORT
                )
                else DEFAULT_PORT
            )

        if "ip_limit" in body:

            try:

                ip_limit = int(
                    body.get(
                        "ip_limit",
                        0,
                    )
                    or 0
                )

            except Exception:

                ip_limit = 0

            link[
                "ip_limit"
            ] = max(
                0,
                ip_limit,
            )

        if "speed_limit_value" in body:

            try:

                speed_value = float(
                    body.get(
                        "speed_limit_value",
                        0,
                    )
                    or 0
                )

            except Exception:

                speed_value = 0

            unit = (
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

                    ids.remove(
                        uid
                    )

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

                    ids.append(
                        uid
                    )

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


@app.delete(
    "/api/links/{uid}"
)
async def delete_link(
    uid: str,
    _=Depends(require_auth),
):

    label = await remove_link(
        uid
    )

    if label is None:

        raise HTTPException(
            status_code=404,
            detail="link not found",
        )

    return {
        "ok": True,
        "deleted": uid,
    }


# ============================================================
# SUBSCRIPTION SINGLE
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
                    link[
                        "label"
                    ]
                ),

            "support-url":
                SUPPORT_URL,

            "profile-update-interval":
                "12",
        },
    )


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
# SUB GROUP API
# ============================================================

@app.post(
    "/api/subs"
)
async def create_sub_api(
    request: Request,
    _=Depends(require_auth),
):

    body = await request.json()

    sub_id, sub = (
        await create_sub_group(
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
    )

    host = get_host(
        request
    )

    return {
        "sub_id": sub_id,
        **sub,
        "password_hash":
            None,
        "public_url":
            (
                f"https://"
                f"{host}/p/"
                f"{sub['uuid_key']}"
            ),
        "sub_url":
            (
                f"https://"
                f"{host}/sub-group/"
                f"{sub['uuid_key']}"
            ),
    }


@app.get(
    "/api/subs"
)
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

            if lid
            in snapshot_links
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
                    )
                    is not None,

                "links_count":
                    len(
                        link_ids
                    ),

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
                        f"https://"
                        f"{host}/p/"
                        f"{sub['uuid_key']}"
                    ),

                "sub_url":
                    (
                        f"https://"
                        f"{host}/sub-group/"
                        f"{sub['uuid_key']}"
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


@app.patch(
    "/api/subs/{sub_id}"
)
async def update_sub_api(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    body = await request.json()

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
        "ok": True
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
        "ok": True,
        "deleted": sub_id,
    }


@app.post(
    "/api/subs/{sub_id}/links"
)
async def assign_link_to_sub(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    body = await request.json()

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

        success = (
            await set_link_sub(
                link_id,
                sub_id,
            )
        )

    else:

        success = (
            await set_link_sub(
                link_id,
                None,
            )
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
# SUB GROUP SUBSCRIPTION
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

            if link and is_link_allowed(
                link
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
# PUBLIC SUB PAGE
# ============================================================

PUBLIC_SUB_HTML = r"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

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
    href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800&display=swap"
    rel="stylesheet"
>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    display: flex;

    justify-content: center;

    align-items: center;

    padding: 20px;

    font-family:
        "Vazirmatn",
        sans-serif;

    color: white;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.17),
            transparent 30%
        ),
        #07070a;
}

.card {

    width: 100%;

    max-width: 560px;

    padding: 28px;

    border-radius: 26px;

    background:
        rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:
        blur(25px);
}

h1 {
    margin-top: 0;
}

.text {

    color:
        rgba(255,255,255,.55);

    line-height: 2;

    font-size: 13px;
}

.url {

    margin-top: 20px;

    direction: ltr;

    word-break: break-all;

    padding: 14px;

    border-radius: 13px;

    background:
        rgba(0,0,0,.22);

    color:
        #c4b5fd;

    font-family:
        Consolas,
        monospace;
}

.support {

    display: inline-block;

    margin-top: 18px;

    color:
        #a78bfa;

    text-decoration: none;
}

</style>

</head>

<body>

<div class="card">

<h1>
PixonPanel
</h1>

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
            )
            == uuid_key
            for item
            in SUBS.values()
        )

    if not exists:

        return HTMLResponse(
            (
                "<h2 "
                "style='font-family:sans-serif;"
                "padding:40px'"
                ">"
                "گروه پیدا نشد"
                "</h2>"
            ),
            status_code=404,
        )

    return HTMLResponse(
        PUBLIC_SUB_HTML
    )


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

    has_password = (
        sub.get(
            "password_hash"
        )
        is not None
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
            hash_password(
                password
            )
            != sub[
                "password_hash"
            ]
        ):

            return JSONResponse(
                {
                    "locked": True,
                    "name":
                        sub[
                            "name"
                        ],
                }
            )

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
                    link[
                        "label"
                    ],

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
                        f"https://"
                        f"{host}/sub/"
                        f"{link_id}"
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
        "locked": False,

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
                f"https://"
                f"{host}/sub-group/"
                f"{uuid_key}"
            ),

        "active_connections":
            active_connections,

        "total_used_fmt":
            fmt_bytes(
                total_used
            ),

        "links":
            links_out,
    }


# ============================================================
# STATS
# ============================================================

@app.get(
    "/stats"
)
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

        "recent_errors":
            list(
                error_logs
            )[-10:],

        "links_count":
            len(
                snapshot
            ),

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
            len(
                SUBS
            ),
    }


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
            else "نامشخص"
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
        ] += connection.get(
            "bytes",
            0,
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

                "labels":
                    sorted(
                        group[
                            "labels"
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
                        else "نامشخص"
                    ),

                "transports":
                    sorted(
                        group[
                            "transports"
                        ]
                    ),

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
            len(
                result
            ),

        "raw_count":
            len(
                connections
            ),
    }


# ============================================================
# OPTIONAL / EXISTING PROJECT MODULES
# ============================================================
#
# این قسمت‌ها را عمداً نگه می‌داریم تا قابلیت‌های پروژه‌ی اصلی
# مثل VLESS Relay / XHTTP / Telegram باقی بمانند.
#
# اگر فایل‌های زیر در repository شما هستند، فعال می‌شوند.
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


# ============================================================
# TELEGRAM START PATCH
# ============================================================

_original_startup = startup


@app.on_event(
    "startup"
)
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

    if not target_url.startswith(
        "http"
    ):

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

        stats[
            "total_bytes"
        ] += len(
            response.content
        )

        stats[
            "total_requests"
        ] += 1

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

            if (
                key.lower()
                not in _HOP
            )
        }

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=output_headers,
        )

    except Exception as exc:

        stats[
            "total_errors"
        ] += 1

        error_logs.append(
            {
                "error":
                    str(
                        exc
                    ),

                "url":
                    target_url,

                "time":
                    datetime.now().isoformat(),
            }
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

    color: white;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 10% 0%,
            rgba(99,102,241,.13),
            transparent 25%
        ),
        radial-gradient(
            circle at 100% 100%,
            rgba(139,92,246,.10),
            transparent 25%
        ),
        #07070a;
}

.wrapper {

    width:
        min(
            1180px,
            calc(100% - 28px)
        );

    margin: 0 auto;

    padding: 24px 0;
}

.topbar {

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    gap: 15px;

    margin-bottom: 20px;
}

.brand {

    display: flex;

    align-items: center;

    gap: 12px;
}

.logo {

    width: 45px;
    height: 45px;

    display: flex;

    align-items: center;
    justify-content: center;

    border-radius: 14px;

    font-weight: 900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.brand-name {

    font-weight: 900;

    font-size: 16px;
}

.brand-desc {

    color:
        rgba(255,255,255,.38);

    margin-top: 3px;

    font-size: 10px;
}

.logout {

    color:
        #fca5a5;

    text-decoration: none;

    padding:
        9px 12px;

    border-radius: 12px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.03);

    font-size: 11px;
}

.grid {

    display: grid;

    grid-template-columns:
        repeat(4,1fr);

    gap: 11px;
}

.stat {

    padding: 17px;

    border-radius: 18px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);
}

.stat-label {

    color:
        rgba(255,255,255,.38);

    font-size: 10px;
}

.stat-value {

    margin-top: 8px;

    font-size: 22px;

    font-weight: 900;
}

.panel {

    margin-top: 12px;

    border-radius: 20px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);

    overflow: hidden;
}

.panel-head {

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    padding: 17px 18px;

    border-bottom:
        1px solid
        rgba(255,255,255,.07);
}

.panel-title {

    font-size: 13px;

    font-weight: 800;
}

.button {

    border: 0;

    cursor: pointer;

    color: white;

    padding:
        9px 12px;

    border-radius: 11px;

    font-family:
        "Vazirmatn",
        sans-serif;

    font-size: 10px;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.table {

    overflow-x: auto;
}

table {

    width: 100%;

    border-collapse:
        collapse;

    min-width: 760px;
}

th,
td {

    text-align:
        right;

    padding:
        12px 14px;

    border-bottom:
        1px solid
        rgba(255,255,255,.05);

    font-size: 11px;
}

th {

    color:
        rgba(255,255,255,.35);
}

.badge {

    display: inline-block;

    padding:
        4px 8px;

    border-radius: 999px;

    font-size: 9px;
}

.badge-active {

    color:
        #86efac;

    background:
        rgba(34,197,94,.08);
}

.badge-disabled {

    color:
        #fca5a5;

    background:
        rgba(239,68,68,.08);
}

.action {

    border: 0;

    cursor: pointer;

    padding:
        7px 9px;

    margin-left: 4px;

    border-radius: 9px;

    color:
        rgba(255,255,255,.8);

    background:
        rgba(255,255,255,.05);

    font-family:
        "Vazirmatn",
        sans-serif;

    font-size: 9px;
}

.action-danger {

    color:
        #fca5a5;
}

pre {

    margin: 0;

    padding: 18px;

    max-height: 260px;

    overflow: auto;

    color:
        rgba(255,255,255,.45);

    font-family:
        Consolas,
        monospace;

    font-size: 10px;

    white-space: pre-wrap;
}

@media(max-width:900px) {

    .grid {
        grid-template-columns:
            repeat(2,1fr);
    }
}

@media(max-width:600px) {

    .wrapper {
        width:
            calc(100% - 18px);
    }

    .grid {
        grid-template-columns:
            1fr;
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

<div class="brand-desc">
داشبورد مدیریت سرویس
</div>

</div>

</div>

<a
    href="/logout"
    class="logout"
>
خروج
</a>

</div>

<div class="grid">

<div class="stat">

<div class="stat-label">
کل کانفیگ‌ها
</div>

<div
    class="stat-value"
    id="totalLinks"
>
-
</div>

</div>

<div class="stat">

<div class="stat-label">
کانفیگ‌های فعال
</div>

<div
    class="stat-value"
    id="activeLinks"
>
-
</div>

</div>

<div class="stat">

<div class="stat-label">
اتصالات فعال
</div>

<div
    class="stat-value"
    id="connections"
>
-
</div>

</div>

<div class="stat">

<div class="stat-label">
آپ‌تایم
</div>

<div
    class="stat-value"
    id="uptime"
>
-
</div>

</div>

</div>

<div class="panel">

<div class="panel-head">

<div class="panel-title">
مدیریت کانفیگ‌ها
</div>

<button
    class="button"
    onclick="createLink()"
>
+ ساخت کانفیگ
</button>

</div>

<div class="table">

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
اتصالات
</th>

<th>
عملیات
</th>

</tr>

</thead>

<tbody id="linksTable">

</tbody>

</table>

</div>

</div>

<div class="panel">

<div class="panel-head">

<div class="panel-title">
آخرین فعالیت‌ها
</div>

</div>

<pre id="logs">
در حال بارگذاری...
</pre>

</div>

</div>

<script>

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

    return response.json();
}


function escapeHtml(value) {

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


function formatBytes(value) {

    value =
        Number(value || 0);

    if (
        value < 1024
    ) {

        return (
            value +
            " B"
        );
    }

    if (
        value <
        1024 ** 2
    ) {

        return (
            (
                value /
                1024
            ).toFixed(1)
            +
            " KB"
        );
    }

    if (
        value <
        1024 ** 3
    ) {

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


async function refresh() {

    const stats =
        await api(
            "/stats"
        );

    if (!stats)
        return;

    document.getElementById(
        "totalLinks"
    ).textContent =
        stats.links_count;

    document.getElementById(
        "activeLinks"
    ).textContent =
        stats.active_links;

    document.getElementById(
        "connections"
    ).textContent =
        stats.active_connections;

    document.getElementById(
        "uptime"
    ).textContent =
        stats.uptime;


    const data =
        await api(
            "/api/links"
        );

    if (!data)
        return;

    const table =
        document.getElementById(
            "linksTable"
        );

    table.innerHTML = "";


    for (
        const link
        of data.links
    ) {

        const row =
            document.createElement(
                "tr"
            );

        row.innerHTML = `

<td>
    ${escapeHtml(
        link.label
    )}
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
        ? "badge-active"
        : "badge-disabled"
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
${formatBytes(
    link.used_bytes
)}
</td>

<td>
${link.connected_ips || 0}
</td>

<td>

<button
    class="action"
    onclick="copyLink(${JSON.stringify(
        link.vless_link
    )})"
>
کپی
</button>

<button
    class="action"
    onclick="toggleLink(
        ${JSON.stringify(link.uuid)},
        ${!link.active}
    )"
>
${
    link.active
    ? "خاموش"
    : "فعال"
}
</button>

<button
    class="action action-danger"
    onclick="deleteLink(
        ${JSON.stringify(link.uuid)}
    )"
>
حذف
</button>

</td>

`;

        table.appendChild(
            row
        );
    }


    const activity =
        await api(
            "/api/activity"
        );

    if (
        activity
        &&
        activity.logs
    ) {

        document.getElementById(
            "logs"
        ).textContent =
            activity.logs
                .slice()
                .reverse()
                .map(
                    item =>
                        `[${item.level}] ${item.message}`
                )
                .join(
                    "\\n"
                )
                ||
                "فعالیتی ثبت نشده است";
    }
}


async function createLink() {

    const label =
        prompt(
            "نام کانفیگ:",
            "کانفیگ جدید"
        );

    if (!label)
        return;

    const result =
        await api(
            "/api/links",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({
                        label:
                            label,

                        protocol:
                            "vless-ws",

                        fingerprint:
                            "chrome",

                        port:
                            443
                    })
            }
        );

    if (!result)
        return;

    await navigator
        .clipboard
        .writeText(
            result.vless_link
        );

    alert(
        "کانفیگ ساخته شد و لینک VLESS کپی شد."
    );

    refresh();
}


async function toggleLink(
    uuid,
    active
) {

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

    refresh();
}


async function deleteLink(
    uuid
) {

    if (
        !confirm(
            "این کانفیگ حذف شود؟"
        )
    ) {

        return;
    }

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

    refresh();
}


async function copyLink(
    text
) {

    try {

        await navigator
            .clipboard
            .writeText(
                text
            );

        alert(
            "لینک کپی شد."
        );

    } catch {

        prompt(
            "لینک:",
            text
        );
    }
}


refresh();

setInterval(
    refresh,
    5000
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
# TEST
# ============================================================

@app.get(
    "/test-ws",
    response_class=HTMLResponse,
)
async def test_ws():

    return HTMLResponse(
        (
            "<script>"
            "location.href='/dashboard'"
            "</script>"
        )
    )


# ============================================================
# ERROR HANDLER
# ============================================================

@app.exception_handler(
    Exception
)
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
                str(
                    exc
                ),

            "path":
                str(
                    request.url
                ),

            "time":
                datetime.now().isoformat(),
        }
    )

    logger.exception(
        "Unhandled exception"
    )

    return JSONResponse(
        {
            "ok": False,
            "error":
                "internal server error",
        },
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

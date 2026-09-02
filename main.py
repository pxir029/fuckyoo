# ============================================================
# PixonPanel - Railway Ready
# Version: 12.0.1 Beta
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

DATA_FILE = (
    DATA_DIR
    / "pixonpanel_state.json"
)

SECRET_FILE = (
    DATA_DIR
    / "pixonpanel_secret.key"
)


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

def load_or_create_secret():

    env_secret = os.environ.get(
        "SECRET_KEY"
    )

    if env_secret:
        return env_secret

    try:

        if SECRET_FILE.exists():

            current = (
                SECRET_FILE
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )

            if current:
                return current

        generated = (
            secrets.token_urlsafe(48)
        )

        SECRET_FILE.write_text(
            generated,
            encoding="utf-8",
        )

        return generated

    except Exception as exc:

        logger.warning(
            "Could not persist secret: %s",
            exc,
        )

        return secrets.token_urlsafe(48)


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format=(
        "%(asctime)s "
        "[%(levelname)s] "
        "%(message)s"
    ),
)

logger = logging.getLogger(
    APP_NAME
)


SECRET_KEY = load_or_create_secret()


# ============================================================
# PASSWORD
# ============================================================

def hash_password(
    password: str,
):

    payload = (
        str(password)
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
# STATE
# ============================================================

LINKS = {}
SUBS = {}
SESSIONS = {}

connections = {}

activity_logs = deque(
    maxlen=300
)

error_logs = deque(
    maxlen=100
)

hourly_traffic = defaultdict(
    int
)

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}


http_client = None


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
    "vless-ws":
        "http/1.1",

    "xhttp-packet-up":
        "h2,http/1.1",

    "xhttp-stream-up":
        "h2,http/1.1",

    "xhttp-stream-one":
        "h2,http/1.1",
}

DEFAULT_PORT = 443

MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_SPEED_LIMIT = 0


# ============================================================
# FRAGMENT
# ============================================================

FRAGMENT_PROFILES = {

    "off":
        None,

    "safe":
        "packets=1-3;length=1-1;interval=10-20",

    "balanced":
        "packets=1-3,10-20;length=1-1;interval=10-20",

    "aggressive":
        "packets=1-3,10-20;length=1-2;interval=5-15",
}


# ============================================================
# HELPERS
# ============================================================

def generate_uuid():

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


def generate_auto_name():

    chars = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "23456789"
    )

    suffix = "".join(
        secrets.choice(chars)
        for _ in range(6)
    )

    return (
        f"pxpanel_"
        f"{suffix}"
    )


def now_iso():

    return datetime.now().isoformat()


def now_ir():

    if IRAN_TZ:
        return datetime.now(
            IRAN_TZ
        )

    return datetime.now()


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


def fmt_bytes(
    value,
):

    value = max(
        0,
        safe_int(value)
    )

    if value < 1024:

        return (
            f"{value} B"
        )

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


def uptime():

    seconds = int(
        time.time()
        - stats[
            "start_time"
        ]
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

    base = (
        f"{hours:02d}:"
        f"{minutes:02d}:"
        f"{secs:02d}"
    )

    if days:

        return (
            f"{days}d "
            f"{base}"
        )

    return base


def parse_size_to_bytes(
    value,
    unit,
):

    value = safe_float(value)

    if value <= 0:
        return 0

    unit = str(
        unit or "GB"
    ).upper()

    if unit == "MB":

        return int(
            value
            * 1024 ** 2
        )

    if unit == "GB":

        return int(
            value
            * 1024 ** 3
        )

    if unit == "TB":

        return int(
            value
            * 1024 ** 4
        )

    return int(value)


def parse_speed_to_bytes(
    value,
    unit,
):

    value = safe_float(value)

    if value <= 0:
        return 0

    unit = str(
        unit or "MBIT"
    ).upper()

    if unit == "MBIT":

        return int(
            value
            * 1024
            * 1024
            / 8
        )

    if unit == "GBIT":

        return int(
            value
            * 1024
            * 1024
            * 1024
            / 8
        )

    if unit == "MB":

        return int(
            value
            * 1024
            * 1024
        )

    if unit == "KB":

        return int(
            value
            * 1024
        )

    return int(value)


def is_link_expired(
    link,
):

    expiry = link.get(
        "expires_at"
    )

    if not expiry:
        return False

    try:

        return (
            datetime.now()
            >= datetime.fromisoformat(
                expiry
            )
        )

    except Exception:

        return False


def is_link_allowed(
    link,
):

    if not link:
        return False

    if not link.get(
        "active",
        True
    ):
        return False

    if is_link_expired(
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
        and
        used >= limit
    ):
        return False

    return True


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


def get_host(
    request=None,
):

    if request:

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

            return host.split(
                ":"
            )[0]

    railway = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway:
        return railway

    return "localhost"


# ============================================================
# ACTIVITY
# ============================================================

def log_activity(
    kind,
    message,
    level="info",
):

    activity_logs.append(
        {
            "kind":
                kind,

            "message":
                message,

            "level":
                level,

            "time":
                now_iso(),
        }
    )


# ============================================================
# PERSISTENCE
# ============================================================

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

        data = json.loads(
            raw
        )

        LINKS.update(
            data.get(
                "links",
                {}
            )
        )

        SUBS.update(
            data.get(
                "subs",
                {}
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
            "Loaded %d links / %d subs",
            len(LINKS),
            len(SUBS),
        )

    except Exception as exc:

        logger.exception(
            "load_state failed"
        )

        error_logs.append(
            {
                "time":
                    now_iso(),

                "error":
                    str(exc),
            }
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
                    now_iso(),
            }

            temp = (
                DATA_FILE.with_suffix(
                    ".tmp"
                )
            )

            async with aiofiles.open(
                temp,
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

            temp.replace(
                DATA_FILE
            )

        except Exception as exc:

            logger.exception(
                "save_state failed"
            )


# ============================================================
# SESSIONS
# ============================================================

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
    token,
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
                None
            )

            return False

        return True


async def destroy_session(
    token,
):

    if not token:
        return

    async with SESSIONS_LOCK:

        SESSIONS.pop(
            token,
            None
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
# VLESS
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

    # --------------------------------------------------------
    # Keep the working VLESS WS endpoint exactly the same.
    # --------------------------------------------------------

    if protocol == "vless-ws":

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
                f"/ws/{uuid}",

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
                (
                    f"/xhttp-siz10/"
                    f"{mode}/"
                    f"{uuid}"
                ),

            "sni":
                host,

            "fp":
                fp,

            "alpn":
                alpn_value,
        }

    query = "&".join(
        (
            f"{key}="
            f"{quote(str(value))}"
        )

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
    link,
    uid,
    host,
):

    return generate_vless_link(
        uuid=uid,

        host=host,

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
            "alpn",
            "",
        ),

        port=link.get(
            "port",
            DEFAULT_PORT,
        ),
    )


# ============================================================
# CONNECTION HELPERS
# ============================================================

def unique_ips_for_uuid(
    uuid,
):

    return {
        value.get("ip")

        for value
        in connections.values()

        if value.get("uuid")
        == uuid

        and value.get("ip")
    }


def active_connections_for_uuid(
    uuid,
):

    return sum(
        1

        for value
        in connections.values()

        if value.get(
            "uuid"
        )
        == uuid
    )


def can_accept_connection(
    uuid,
    ip,
):

    link = LINKS.get(
        uuid
    )

    if not link:

        return (
            False,
            "not_found"
        )

    if not is_link_allowed(
        link
    ):

        return (
            False,
            "inactive"
        )

    concurrent_limit = safe_int(
        link.get(
            "concurrent_limit",
            0,
        )
    )

    if (
        concurrent_limit > 0
        and
        active_connections_for_uuid(
            uuid
        )
        >= concurrent_limit
    ):

        return (
            False,
            "concurrent_limit"
        )

    ip_limit = safe_int(
        link.get(
            "ip_limit",
            0,
        )
    )

    if ip_limit > 0:

        ips = unique_ips_for_uuid(
            uuid
        )

        if (
            ip not in ips
            and
            len(ips)
            >= ip_limit
        ):

            return (
                False,
                "ip_limit"
            )

    return (
        True,
        "ok"
    )


# ============================================================
# DEFAULT
# ============================================================

async def ensure_default_link():

    if any(
        item.get(
            "is_default"
        )
        for item
        in LINKS.values()
    ):
        return

    digest = hashlib.sha256(
        (
            "pixon-default-"
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
            now_iso(),

        "updated_at":
            now_iso(),

        "active":
            True,

        "expires_at":
            None,

        "note":
            "Default PixonPanel link",

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
            443,

        "ip_limit":
            0,

        "concurrent_limit":
            0,

        "speed_limit_bytes":
            0,

        "fragment":
            None,

        "fragment_profile":
            "off",
    }

    await save_state()


# ============================================================
# STARTUP
# ============================================================

@app.on_event(
    "startup"
)
async def startup():

    global http_client

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            30.0,
            connect=10.0,
        ),
        follow_redirects=True,
    )

    await load_state()
    await ensure_default_link()

    log_activity(
        "system",
        (
            f"{APP_NAME} "
            f"{APP_VERSION} "
            "started"
        ),
        "ok",
    )

    logger.info(
        "%s %s started on %s",
        APP_NAME,
        APP_VERSION,
        PORT,
    )


@app.on_event(
    "shutdown"
)
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

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>
PixonPanel 12.0.1 Beta
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

    color:#fff;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 15% 10%,
            rgba(99,102,241,.22),
            transparent 30%
        ),

        radial-gradient(
            circle at 90% 90%,
            rgba(168,85,247,.15),
            transparent 30%
        ),

        #07070a;
}

.card{

    width:100%;
    max-width:560px;

    padding:32px;

    border:
        1px solid
        rgba(255,255,255,.09);

    border-radius:30px;

    background:
        rgba(255,255,255,.045);

    backdrop-filter:
        blur(30px);

    box-shadow:
        0 40px 100px
        rgba(0,0,0,.48);
}

.logo{

    width:52px;
    height:52px;

    display:flex;

    align-items:center;
    justify-content:center;

    border-radius:17px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.version{

    display:inline-flex;

    margin-top:17px;

    padding:
        6px 9px;

    border-radius:999px;

    color:#c4b5fd;

    background:
        rgba(139,92,246,.08);

    border:
        1px solid
        rgba(139,92,246,.15);

    font-size:9px;
}

.status{

    margin-top:12px;

    color:#86efac;

    font-size:10px;
}

h1{

    margin:10px 0 0;

    font-size:29px;

    line-height:1.55;

    font-weight:900;
}

p{

    color:
        rgba(255,255,255,.53);

    line-height:2;

    font-size:12px;
}

.command{

    margin-top:20px;

    padding:14px;

    border-radius:14px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(0,0,0,.18);

    direction:ltr;

    text-align:left;

    font-family:
        Consolas,
        monospace;

    color:#c4b5fd;
}

.actions{

    display:flex;

    gap:8px;

    margin-top:18px;
}

.button{

    flex:1;

    padding:13px;

    border-radius:13px;

    text-decoration:none;

    text-align:center;

    font-size:11px;

    font-weight:800;
}

.primary{

    color:#fff;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.secondary{

    color:
        rgba(255,255,255,.75);

    background:
        rgba(255,255,255,.035);

    border:
        1px solid
        rgba(255,255,255,.08);
}

.footer{

    display:flex;

    justify-content:
        space-between;

    margin-top:19px;

    padding-top:16px;

    border-top:
        1px solid
        rgba(255,255,255,.07);

    color:
        rgba(255,255,255,.28);

    font-size:9px;
}

a{
    color:inherit;
}

.support{
    color:#a78bfa;
    text-decoration:none;
}

@media(max-width:600px){

    .card{
        padding:24px;
        border-radius:23px;
    }

    h1{
        font-size:24px;
    }

    .actions{
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

<div class="version">
12.0.1 Beta
</div>

<div class="status">
● سیستم آنلاین و فعال است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<p>
به PixonPanel خوش آمدید.
برای مدیریت کانفیگ‌ها و سرویس‌ها وارد پنل شوید.
</p>

<div class="command">
/login
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
PixonPanel · 12.0.1 Beta
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
/>

<title>
Login · PixonPanel
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

    color:#fff;

    font-family:
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.20),
            transparent 32%
        ),
        #07070a;
}

.card{

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
        0 35px 90px
        rgba(0,0,0,.45);
}

.logo{

    width:49px;
    height:49px;

    display:flex;

    align-items:center;
    justify-content:center;

    margin-bottom:20px;

    border-radius:16px;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight:900;
}

.version{

    color:#a78bfa;

    font-size:9px;

    margin-bottom:7px;
}

h1{

    margin:0;

    font-size:24px;
}

.desc{

    margin-top:7px;

    color:
        rgba(255,255,255,.43);

    line-height:1.9;

    font-size:11px;
}

form{

    margin-top:22px;
}

label{

    display:block;

    margin-bottom:7px;

    color:
        rgba(255,255,255,.50);

    font-size:10px;
}

.input{

    width:100%;

    padding:13px;

    border-radius:13px;

    border:
        1px solid
        rgba(255,255,255,.08);

    outline:none;

    color:#fff;

    background:
        rgba(0,0,0,.18);

    direction:ltr;

    font-family:
        "Vazirmatn",
        sans-serif;
}

.input:focus{

    border-color:
        rgba(129,140,248,.55);
}

button{

    width:100%;

    margin-top:12px;

    padding:13px;

    border:0;

    border-radius:13px;

    color:#fff;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-family:
        "Vazirmatn",
        sans-serif;

    font-weight:800;

    cursor:pointer;
}

.error{

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

.support{

    display:block;

    margin-top:17px;

    text-align:center;

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

<div class="version">
PixonPanel · 12.0.1 Beta
</div>

<h1>
ورود به پنل
</h1>

<div class="desc">
رمز عبور مدیریت را وارد کنید.
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
ورود
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


@app.post(
    "/login"
)
async def login(
    request: Request
):

    try:

        raw = await request.body()

        form = parse_qs(
            raw.decode(
                "utf-8",
                errors="ignore"
            )
        )

        password = (
            form
            .get(
                "password",
                [""]
            )[0]
            .strip()
        )

    except Exception:

        return HTMLResponse(
            LOGIN_HTML.replace(
                "</form>",
                """
                <div class="error">
                    خطا در پردازش فرم.
                </div>
                </form>
                """
            ),
            status_code=400
        )

    if (
        hash_password(password)
        != AUTH[
            "password_hash"
        ]
    ):

        log_activity(
            "auth",
            (
                "تلاش ناموفق "
                "برای ورود"
            ),
            "warn"
        )

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
        samesite="lax",
        secure=True,
        path="/"
    )

    log_activity(
        "auth",
        "ورود موفق به پنل",
        "ok"
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
# CREATE MANUAL
# ============================================================

@app.post(
    "/api/links"
)
async def create_link_api(
    request: Request,
    _=Depends(require_auth)
):

    body = await request.json()

    label = str(
        body.get(
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

    volume = safe_float(
        body.get(
            "volume_value",
            0
        )
    )

    volume_unit = str(
        body.get(
            "volume_unit",
            "GB"
        )
    )

    limit_bytes = (
        parse_size_to_bytes(
            volume,
            volume_unit
        )
    )

    days = max(
        0,
        safe_int(
            body.get(
                "duration_days",
                0
            )
        )
    )

    expires_at = (
        (
            datetime.now()
            + timedelta(
                days=days
            )
        ).isoformat()
        if days > 0
        else None
    )

    concurrent = max(
        0,
        safe_int(
            body.get(
                "concurrent_limit",
                0
            )
        )
    )

    ip_limit = max(
        0,
        safe_int(
            body.get(
                "ip_limit",
                0
            )
        )
    )

    speed = parse_speed_to_bytes(
        body.get(
            "speed_limit_value",
            0
        ),
        body.get(
            "speed_limit_unit",
            "MBIT"
        )
    )

    protocol = str(
        body.get(
            "protocol",
            DEFAULT_PROTOCOL
        )
    )

    if protocol not in PROTOCOLS:

        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT
        )
    ).lower()

    if fingerprint not in FINGERPRINTS:

        fingerprint = DEFAULT_FINGERPRINT

    fragment_profile = str(
        body.get(
            "fragment",
            "off"
        )
    )

    if fragment_profile not in FRAGMENT_PROFILES:

        fragment_profile = "off"

    fragment = FRAGMENT_PROFILES[
        fragment_profile
    ]

    port = safe_int(
        body.get(
            "port",
            DEFAULT_PORT
        ),
        DEFAULT_PORT
    )

    if not (
        MIN_PORT
        <= port
        <= MAX_PORT
    ):

        port = DEFAULT_PORT

    uid = generate_uuid()

    link = {

        "label":
            label[:80],

        "limit_bytes":
            limit_bytes,

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
            fragment,

        "fragment_profile":
            fragment_profile,

        "alpn":
            str(
                body.get(
                    "alpn",
                    ""
                )
            )[:100],

        "port":
            port,

        "ip_limit":
            ip_limit,

        "concurrent_limit":
            concurrent,

        "speed_limit_bytes":
            speed,

        "note":
            str(
                body.get(
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

        "sub_id":
            None,
    }

    async with LINKS_LOCK:

        LINKS[
            uid
        ] = link

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» ساخته شد"
        ),
        "ok"
    )

    host = get_host(
        request
    )

    return {

        "ok":
            True,

        "uuid":
            uid,

        **link,

        "vless_link":
            vless_link_for_link(
                link,
                uid,
                host
            ),

        "sub_url":
            f"https://{host}/sub/{uid}",

        "info_url":
            f"https://{host}/info/{uid}",
    }


# ============================================================
# AUTO CREATE
# ============================================================

@app.post(
    "/api/links/auto"
)
async def auto_create(
    request: Request,
    _=Depends(require_auth)
):

    uid = generate_uuid()

    link = {

        # ----------------------------------------------------
        # AUTO NAME
        # ----------------------------------------------------

        "label":
            generate_auto_name(),

        # ----------------------------------------------------
        # EVERYTHING UNLIMITED
        # ----------------------------------------------------

        "limit_bytes":
            0,

        "used_bytes":
            0,

        "duration_days":
            0,

        "expires_at":
            None,

        "concurrent_limit":
            0,

        "ip_limit":
            0,

        "speed_limit_bytes":
            0,

        # ----------------------------------------------------
        # Stable configuration
        # ----------------------------------------------------

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

        "note":
            "Auto generated by PixonPanel",

        "created_at":
            now_iso(),

        "updated_at":
            now_iso(),

        "is_default":
            False,

        "sub_id":
            None,
    }

    async with LINKS_LOCK:

        LINKS[
            uid
        ] = link

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ خودکار "
            f"«{link['label']}» "
            "ساخته شد"
        ),
        "ok"
    )

    host = get_host(
        request
    )

    return {

        "ok":
            True,

        "uuid":
            uid,

        **link,

        "vless_link":
            vless_link_for_link(
                link,
                uid,
                host
            ),

        "sub_url":
            f"https://{host}/sub/{uid}",

        "info_url":
            f"https://{host}/info/{uid}",
    }


# ============================================================
# LIST
# ============================================================

@app.get(
    "/api/links"
)
async def list_links(
    request: Request,
    _=Depends(require_auth)
):

    host = get_host(
        request
    )

    result = []

    async with LINKS_LOCK:

        snapshot = dict(
            LINKS
        )

    for uid, link in snapshot.items():

        result.append({

            "uuid":
                uid,

            **link,

            "expired":
                is_link_expired(
                    link
                ),

            "active":
                bool(
                    link.get(
                        "active",
                        True
                    )
                ),

            "online":
                is_link_allowed(
                    link
                ),

            "connections":
                active_connections_for_uuid(
                    uid
                ),

            "connected_ips":
                len(
                    unique_ips_for_uuid(
                        uid
                    )
                ),

            "used_fmt":
                fmt_bytes(
                    link.get(
                        "used_bytes",
                        0
                    )
                ),

            "limit_fmt":
                (
                    "نامحدود"

                    if not link.get(
                        "limit_bytes",
                        0
                    )

                    else fmt_bytes(
                        link[
                            "limit_bytes"
                        ]
                    )
                ),

            "vless_link":
                vless_link_for_link(
                    link,
                    uid,
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
        })

    result.sort(
        key=lambda x:
            x.get(
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
# EDIT
# ============================================================

@app.patch(
    "/api/links/{uid}"
)
async def update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth)
):

    body = await request.json()

    async with LINKS_LOCK:

        link = LINKS.get(
            uid
        )

        if not link:

            raise HTTPException(
                status_code=404,
                detail=
                    "کانفیگ پیدا نشد."
            )

        if "label" in body:

            value = str(
                body.get(
                    "label",
                    ""
                )
            ).strip()

            if value:

                link[
                    "label"
                ] = value[:80]

        if "active" in body:

            link[
                "active"
            ] = bool(
                body[
                    "active"
                ]
            )

        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol"
                )
            )

            if protocol in PROTOCOLS:

                link[
                    "protocol"
                ] = protocol

        if "fingerprint" in body:

            fp = str(
                body.get(
                    "fingerprint"
                )
            ).lower()

            if fp in FINGERPRINTS:

                link[
                    "fingerprint"
                ] = fp

        if "fragment" in body:

            profile = str(
                body.get(
                    "fragment",
                    "off"
                )
            )

            if profile in FRAGMENT_PROFILES:

                link[
                    "fragment_profile"
                ] = profile

                link[
                    "fragment"
                ] = FRAGMENT_PROFILES[
                    profile
                ]

        if "volume_value" in body:

            link[
                "limit_bytes"
            ] = parse_size_to_bytes(
                body.get(
                    "volume_value",
                    0
                ),
                body.get(
                    "volume_unit",
                    "GB"
                )
            )

        if "duration_days" in body:

            days = max(
                0,
                safe_int(
                    body.get(
                        "duration_days",
                        0
                    )
                )
            )

            link[
                "duration_days"
            ] = days

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

        if "concurrent_limit" in body:

            link[
                "concurrent_limit"
            ] = max(
                0,
                safe_int(
                    body.get(
                        "concurrent_limit",
                        0
                    )
                )
            )

        if "ip_limit" in body:

            link[
                "ip_limit"
            ] = max(
                0,
                safe_int(
                    body.get(
                        "ip_limit",
                        0
                    )
                )
            )

        if "speed_limit_value" in body:

            link[
                "speed_limit_bytes"
            ] = parse_speed_to_bytes(
                body.get(
                    "speed_limit_value",
                    0
                ),
                body.get(
                    "speed_limit_unit",
                    "MBIT"
                )
            )

        if "port" in body:

            port = safe_int(
                body.get(
                    "port",
                    443
                ),
                443
            )

            if (
                MIN_PORT
                <= port
                <= MAX_PORT
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
                    ""
                )
            )[:100]

        if "note" in body:

            link[
                "note"
            ] = str(
                body.get(
                    "note",
                    ""
                )
            )[:300]

        link[
            "updated_at"
        ] = now_iso()

        snapshot = dict(
            link
        )

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{snapshot['label']}» "
            "ویرایش شد"
        ),
        "info"
    )

    host = get_host(
        request
    )

    return {

        "ok":
            True,

        **snapshot,

        "vless_link":
            vless_link_for_link(
                snapshot,
                uid,
                host
            ),

        "sub_url":
            f"https://{host}/sub/{uid}",

        "info_url":
            f"https://{host}/info/{uid}",
    }


# ============================================================
# DELETE
# ============================================================

@app.delete(
    "/api/links/{uid}"
)
async def delete_link(
    uid: str,
    _=Depends(require_auth)
):

    async with LINKS_LOCK:

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
                    "کانفیگ پیش‌فرض قابل حذف نیست."
            )

        label = link.get(
            "label",
            uid
        )

        LINKS.pop(
            uid,
            None
        )

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» حذف شد"
        ),
        "warn"
    )

    return {
        "ok":
            True
    }


# ============================================================
# RESET TRAFFIC
# ============================================================

@app.post(
    "/api/links/{uid}/reset"
)
async def reset_usage(
    uid: str,
    _=Depends(require_auth)
):

    async with LINKS_LOCK:

        link = LINKS.get(
            uid
        )

        if not link:

            raise HTTPException(
                status_code=404,
                detail=
                    "کانفیگ پیدا نشد."
            )

        link[
            "used_bytes"
        ] = 0

        link[
            "updated_at"
        ] = now_iso()

    await save_state()

    log_activity(
        "traffic",
        (
            f"مصرف "
            f"«{link['label']}» "
            "ریست شد"
        ),
        "info"
    )

    return {
        "ok":
            True
    }


# ============================================================
# PASSWORD CHANGE
# ============================================================

@app.post(
    "/api/change-password"
)
async def change_password(
    request: Request,
    token=Depends(require_auth)
):

    body = await request.json()

    current = str(
        body.get(
            "current_password",
            ""
        )
    )

    new_password = str(
        body.get(
            "new_password",
            ""
        )
    )

    confirm = str(
        body.get(
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

    if not new_password:

        raise HTTPException(
            status_code=400,
            detail=
                "رمز جدید را وارد کنید."
        )

    if new_password != confirm:

        raise HTTPException(
            status_code=400,
            detail=
                "تکرار رمز جدید مطابقت ندارد."
        )

    if len(new_password) < 8:

        raise HTTPException(
            status_code=400,
            detail=
                "رمز جدید حداقل ۸ کاراکتر باشد."
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
            detail=
                "رمز فعلی اشتباه است."
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )

    await save_state()

    async with SESSIONS_LOCK:

        SESSIONS.clear()

        SESSIONS[
            token
        ] = (
            time.time()
            + SESSION_TTL
        )

    log_activity(
        "security",
        "رمز عبور تغییر کرد",
        "ok"
    )

    return {
        "ok":
            True
    }


# ============================================================
# SUBSCRIPTION
# ============================================================

@app.get(
    "/sub/{uuid}"
)
async def subscription(
    uuid: str,
    request: Request
):

    async with LINKS_LOCK:

        link = LINKS.get(
            uuid
        )

    if not link:

        raise HTTPException(
            status_code=404,
            detail="not found"
        )

    if not is_link_allowed(
        link
    ):

        raise HTTPException(
            status_code=404,
            detail="inactive"
        )

    host = get_host(
        request
    )

    vless = (
        vless_link_for_link(
            link,
            uuid,
            host
        )
    )

    encoded = (
        base64.b64encode(
            vless.encode(
                "utf-8"
            )
        )
        .decode(
            "ascii"
        )
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

        media_type=
            "text/plain",

        headers={

            "profile-title":
                quote(
                    link.get(
                        "label",
                        APP_NAME
                    )
                ),

            "support-url":
                SUPPORT_URL,

            "profile-update-interval":
                "1",

            "subscription-userinfo":
                (
                    "upload=0;"
                    f"download={used};"
                    f"total={total}"
                ),

            "x-pixonpanel-version":
                APP_VERSION,
        }
    )


# ============================================================
# INFO PAGE
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
            <body
                style="
                    background:#07070a;
                    color:white;
                    font-family:Tahoma;
                    padding:40px
                "
            >
                کانفیگ پیدا نشد.
            </body>
            """,
            status_code=404
        )

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

    active_conn = (
        active_connections_for_uuid(
            uid
        )
    )

    conn_limit = safe_int(
        link.get(
            "concurrent_limit",
            0
        )
    )

    return HTMLResponse(
        f"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>
{escape_html(link.get("label"))}
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

*{{box-sizing:border-box;}}

body{{

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
            transparent 30%
        ),
        #07070a;
}}

.container{{

    width:100%;
    max-width:760px;

    margin:auto;
}}

.card{{

    padding:25px;

    border-radius:27px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.045);

    backdrop-filter:
        blur(28px);
}}

.logo{{

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

.badge{{

    display:inline-flex;

    margin-top:12px;

    padding:6px 9px;

    border-radius:999px;

    color:#c4b5fd;

    background:
        rgba(139,92,246,.08);

    font-size:9px;
}}

h1{{

    margin:13px 0 0;

    font-size:23px;
}}

.meta{{

    margin-top:4px;

    color:
        rgba(255,255,255,.35);

    font-size:9px;
}}

.grid{{

    display:grid;

    grid-template-columns:
        repeat(
            2,
            1fr
        );

    gap:9px;

    margin-top:18px;
}}

.item{{

    padding:13px;

    border-radius:15px;

    background:
        rgba(255,255,255,.03);

    border:
        1px solid
        rgba(255,255,255,.06);
}}

.label{{

    color:
        rgba(255,255,255,.34);

    font-size:8px;
}}

.value{{

    margin-top:4px;

    font-size:11px;

    font-weight:800;

    word-break:break-word;
}}

.progress{{

    margin-top:18px;

    height:8px;

    border-radius:999px;

    overflow:hidden;

    background:
        rgba(255,255,255,.07);
}}

.fill{{

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

.section{{

    margin-top:18px;

    padding-top:16px;

    border-top:
        1px solid
        rgba(255,255,255,.07);
}}

.title{{

    font-size:11px;

    font-weight:800;

    margin-bottom:8px;
}}

.link{{

    display:block;

    padding:11px;

    border-radius:11px;

    color:#c4b5fd;

    background:
        rgba(0,0,0,.18);

    border:
        1px solid
        rgba(255,255,255,.07);

    direction:ltr;

    text-align:left;

    word-break:break-all;

    font-family:
        Consolas,
        monospace;

    font-size:8px;

    text-decoration:none;
}}

.notice{{

    padding:14px;

    border-radius:15px;

    background:
        rgba(255,255,255,.03);

    border:
        1px solid
        rgba(255,255,255,.06);

    color:
        rgba(255,255,255,.58);

    line-height:2;

    font-size:9px;
}}

.apps{{

    display:grid;

    grid-template-columns:
        repeat(
            2,
            1fr
        );

    gap:6px;

    margin-top:9px;
}}

.app{{

    padding:9px;

    border-radius:10px;

    color:
        rgba(255,255,255,.72);

    text-decoration:none;

    background:
        rgba(255,255,255,.035);

    border:
        1px solid
        rgba(255,255,255,.06);

    font-size:8px;
}}

.support{{

    margin-top:18px;

    padding-top:16px;

    border-top:
        1px solid
        rgba(255,255,255,.07);

    text-align:center;

    color:
        rgba(255,255,255,.35);

    font-size:9px;
}}

.support a{{

    color:#a78bfa;

    text-decoration:none;
}}

@media(max-width:600px){{

    .grid{{
        grid-template-columns:1fr;
    }}

    .apps{{
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

<div class="badge">
PixonPanel · 12.0.1 Beta
</div>

<h1>
{escape_html(link.get("label"))}
</h1>

<div class="meta">
اطلاعات سرویس و اشتراک
</div>

<div class="grid">

<div class="item">

<div class="label">
Protocol
</div>

<div class="value">
{escape_html(
    link.get(
        "protocol",
        "-"
    )
)}
</div>

</div>


<div class="item">

<div class="label">
Fingerprint
</div>

<div class="value">
{escape_html(
    link.get(
        "fingerprint",
        "-"
    )
)}
</div>

</div>


<div class="item">

<div class="label">
Fragment
</div>

<div class="value">
{escape_html(
    link.get(
        "fragment_profile",
        "off"
    )
)}
</div>

</div>


<div class="item">

<div class="label">
اتصالات فعال
</div>

<div class="value">
{active_conn}
/
{conn_limit or "∞"}
</div>

</div>


<div class="item">

<div class="label">
محدودیت IP
</div>

<div class="value">
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

<div class="label">
انقضا
</div>

<div class="value">
{
    escape_html(
        link.get(
            "expires_at"
        )
        or "بدون انقضا"
    )
}
</div>

</div>

</div>


<div class="progress">

<div class="fill"></div>

</div>


<div
    style="
        margin-top:7px;
        color:rgba(255,255,255,.36);
        font-size:8px;
    "
>
مصرف:
{fmt_bytes(used)}
/
{
    "نامحدود"
    if limit <= 0
    else fmt_bytes(limit)
}
</div>


<div class="section">

<div class="title">
Subscription
</div>

<a
    class="link"
    href="/sub/{uid}"
    target="_blank"
>
https://{get_public_host_placeholder()}/sub/{uid}
</a>

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
Happ · Google Play
</a>

<a
    class="app"
    href="https://dl.v2rayng.org/releases/latest/v2rayNG_2.2.6_arm64-v8a.apk"
    target="_blank"
>
v2rayNG · APK
</a>

<a
    class="app"
    href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box"
    target="_blank"
>
V2Box · Google Play
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
حتماً قبل از استفاده از کانفیگ‌های جدید،
برنامه را به آخرین نسخه آپدیت کنید.

<br><br>

🚀 کانفیگ‌های جدید با نسخه‌های جدید برنامه‌ها
سازگاری و عملکرد بهتری دارند.

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
    )


# ============================================================
# Placeholder helper for INFO
# ============================================================

def get_public_host_placeholder():

    railway = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway:
        return railway

    return "YOUR-DOMAIN"


# ============================================================
# STATS
# ============================================================

@app.get(
    "/stats"
)
async def get_stats(
    _=Depends(require_auth)
):

    total_used = sum(
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

        "version":
            APP_VERSION,

        "links_count":
            len(
                LINKS
            ),

        "active_links":
            sum(
                1
                for link
                in LINKS.values()
                if is_link_allowed(
                    link
                )
            ),

        "expired_links":
            sum(
                1
                for link
                in LINKS.values()
                if is_link_expired(
                    link
                )
            ),

        "active_connections":
            len(
                connections
            ),

        "total_bytes":
            stats[
                "total_bytes"
            ],

        "total_traffic":
            fmt_bytes(
                stats[
                    "total_bytes"
                ]
            ),

        "total_requests":
            stats[
                "total_requests"
            ],

        "total_errors":
            stats[
                "total_errors"
            ],

        "usage":
            total_used,

        "usage_fmt":
            fmt_bytes(
                total_used
            ),

        "uptime":
            uptime(),

        "uptime_seconds":
            int(
                time.time()
                -
                stats[
                    "start_time"
                ]
            ),

        "server_time":
            now_iso(),
    }


@app.get(
    "/api/activity"
)
async def get_activity(
    _=Depends(require_auth)
):

    return {
        "logs":
            list(
                activity_logs
            )[-150:]
    }


# ============================================================
# HEALTH
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
            uptime(),

        "port":
            PORT,

        "links":
            len(
                LINKS
            ),
    }


# ============================================================
# REAL WORKING RELAY
# ============================================================
#
# IMPORTANT:
# این بخش نسخه‌ی سالم قبلی را نگه می‌دارد.
# مسیر /ws/{uuid} همان چیزی است که VLESS قبلی استفاده می‌کرد.
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
        "Working VLESS relay loaded."
    )

except Exception as exc:

    logger.warning(
        "VLESS relay unavailable: %s",
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


@app.on_event(
    "startup"
)
async def telegram_start():

    try:

        await _tg_start_bot()

    except Exception as exc:

        logger.warning(
            "Telegram disabled: %s",
            exc,
        )


# ============================================================
# ERROR
# ============================================================

@app.exception_handler(
    Exception
)
async def global_exception(
    request: Request,
    exc: Exception
):

    stats[
        "total_errors"
    ] += 1

    error_logs.append(
        {
            "time":
                now_iso(),

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
        },
        status_code=500
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

<title>
PixonPanel · 12.0.1 Beta
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
        "Vazirmatn",
        sans-serif;

    background:
        radial-gradient(
            circle at 5% 0%,
            rgba(99,102,241,.13),
            transparent 25%
        ),
        radial-gradient(
            circle at 100% 100%,
            rgba(139,92,246,.09),
            transparent 25%
        ),
        #07070a;
}

button,
input,
select,
textarea{

    font-family:
        "Vazirmatn",
        sans-serif;
}

button{
    cursor:pointer;
}

.app{

    width:
        min(
            1250px,
            calc(100% - 22px)
        );

    margin:auto;

    padding:
        19px 0 40px;
}

.topbar{

    display:flex;

    align-items:center;

    justify-content:
        space-between;

    gap:10px;

    margin-bottom:13px;
}

.brand{

    display:flex;

    align-items:center;

    gap:11px;
}

.logo{

    width:45px;
    height:45px;

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

.brand-name{

    font-size:15px;
    font-weight:900;
}

.brand-version{

    margin-top:3px;

    color:
        rgba(255,255,255,.35);

    font-size:8px;
}

.toolbar{

    display:flex;

    flex-wrap:wrap;

    align-items:center;

    justify-content:flex-end;

    gap:5px;
}

.toolbar button,
.toolbar a{

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.03);

    color:
        rgba(255,255,255,.73);

    border-radius:10px;

    padding:
        8px 10px;

    font-size:8px;

    text-decoration:none;
}

.toolbar .auto{

    border:0;

    color:#fff;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.stats{

    display:grid;

    grid-template-columns:
        repeat(
            4,
            1fr
        );

    gap:8px;
}

.stat{

    padding:14px;

    border-radius:17px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);
}

.stat-title{

    color:
        rgba(255,255,255,.34);

    font-size:8px;
}

.stat-value{

    margin-top:5px;

    font-size:21px;

    font-weight:900;
}

.stat-sub{

    margin-top:3px;

    color:
        rgba(255,255,255,.22);

    font-size:7px;
}

.panel{

    margin-top:9px;

    overflow:hidden;

    border-radius:19px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);
}

.panel-head{

    display:flex;

    justify-content:
        space-between;

    align-items:center;

    gap:10px;

    padding:
        14px 15px;

    border-bottom:
        1px solid
        rgba(255,255,255,.06);
}

.panel-title{

    font-size:11px;

    font-weight:800;
}

.panel-sub{

    margin-top:3px;

    color:
        rgba(255,255,255,.25);

    font-size:7px;
}

.primary{

    padding:
        8px 11px;

    border:0;

    border-radius:10px;

    color:#fff;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-size:8px;

    font-weight:800;
}

.table-scroll{

    overflow-x:auto;
}

table{

    width:100%;

    min-width:1100px;

    border-collapse:
        collapse;
}

th,
td{

    padding:
        10px 12px;

    text-align:right;

    border-bottom:
        1px solid
        rgba(255,255,255,.045);

    font-size:8px;
}

th{

    color:
        rgba(255,255,255,.25);

    font-weight:500;
}

.name{

    font-size:9px;

    font-weight:800;
}

.uuid{

    margin-top:3px;

    direction:ltr;

    color:
        rgba(255,255,255,.20);

    font-family:
        Consolas,
        monospace;

    font-size:6px;
}

.badge{

    display:inline-flex;

    padding:
        4px 7px;

    border-radius:999px;

    font-size:7px;
}

.good{

    color:#86efac;

    background:
        rgba(34,197,94,.07);
}

.bad{

    color:#fca5a5;

    background:
        rgba(239,68,68,.07);
}

.usage{

    min-width:110px;
}

.usage-bar{

    height:5px;

    margin-top:5px;

    overflow:hidden;

    border-radius:99px;

    background:
        rgba(255,255,255,.06);
}

.usage-fill{

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

.actions{

    display:flex;

    flex-wrap:wrap;

    gap:3px;
}

.action{

    padding:
        5px 6px;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:7px;

    color:
        rgba(255,255,255,.76);

    background:
        rgba(255,255,255,.03);

    font-size:6px;
}

.action.danger{

    color:#fca5a5;
}

.action.success{

    color:#86efac;
}

.logs{

    max-height:240px;

    overflow:auto;

    padding:13px;
}

.log{

    display:flex;

    gap:8px;

    padding:7px 0;

    border-bottom:
        1px solid
        rgba(255,255,255,.04);
}

.log-time{

    color:
        rgba(255,255,255,.21);

    white-space:nowrap;

    font-size:6px;
}

.log-text{

    color:
        rgba(255,255,255,.53);

    font-size:7px;
}

/* =========================================================
   MODAL
========================================================= */

.modal{

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
        blur(15px);
}

.modal.show{

    display:flex;
}

.modal-card{

    width:100%;

    max-width:700px;

    max-height:
        calc(100vh - 20px);

    overflow:auto;

    border-radius:23px;

    border:
        1px solid
        rgba(255,255,255,.10);

    background:
        linear-gradient(
            145deg,
            rgba(24,24,31,.99),
            rgba(8,8,11,.99)
        );

    box-shadow:
        0 50px 120px
        rgba(0,0,0,.65);
}

.modal-head{

    display:flex;

    justify-content:
        space-between;

    align-items:center;

    gap:10px;

    padding:
        15px 17px;

    border-bottom:
        1px solid
        rgba(255,255,255,.06);
}

.modal-title{

    font-size:12px;

    font-weight:900;
}

.modal-desc{

    margin-top:3px;

    color:
        rgba(255,255,255,.27);

    font-size:7px;
}

.close{

    width:31px;
    height:31px;

    border:0;

    border-radius:9px;

    color:
        rgba(255,255,255,.65);

    background:
        rgba(255,255,255,.05);

    font-size:17px;
}

.form{

    display:grid;

    grid-template-columns:
        repeat(
            2,
            minmax(
                0,
                1fr
            )
        );

    gap:11px;

    padding:17px;
}

.field.full{

    grid-column:
        1 / -1;
}

.field label{

    display:block;

    margin-bottom:5px;

    color:
        rgba(255,255,255,.46);

    font-size:8px;
}

.input,
.select,
.textarea{

    width:100%;

    min-height:40px;

    padding:
        9px 10px;

    border:
        1px solid
        rgba(255,255,255,.08);

    border-radius:10px;

    outline:none;

    color:#fff;

    background:
        rgba(255,255,255,.04);

    font-size:8px;
}

.input:focus,
.select:focus,
.textarea:focus{

    border-color:
        rgba(129,140,248,.55);
}

.textarea{

    resize:vertical;

    min-height:72px;
}

.inline{

    display:flex;

    gap:5px;
}

.inline > *:first-child{

    flex:1;
}

.inline .select{

    width:85px;
}

.hint{

    margin-top:3px;

    color:
        rgba(255,255,255,.22);

    font-size:6px;
}

.modal-footer{

    display:flex;

    gap:6px;

    padding:
        13px 17px;

    border-top:
        1px solid
        rgba(255,255,255,.06);
}

.modal-btn{

    flex:1;

    min-height:40px;

    border:0;

    border-radius:11px;

    font-size:8px;

    font-weight:800;
}

.modal-btn.cancel{

    color:
        rgba(255,255,255,.65);

    background:
        rgba(255,255,255,.05);
}

.modal-btn.save{

    color:#fff;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.result{

    padding:17px;
}

.result-group{

    margin-bottom:11px;
}

.result-label{

    margin-bottom:5px;

    color:
        rgba(255,255,255,.30);

    font-size:7px;
}

.result-row{

    display:flex;

    gap:4px;
}

.result-input{

    flex:1;

    min-width:0;

    padding:
        9px;

    direction:ltr;

    text-align:left;

    border:
        1px solid
        rgba(255,255,255,.07);

    border-radius:9px;

    outline:none;

    color:#c4b5fd;

    background:
        rgba(0,0,0,.20);

    font-family:
        Consolas,
        monospace;

    font-size:7px;
}

.copy{

    border:0;

    padding:
        0 10px;

    border-radius:9px;

    color:#fff;

    background:
        rgba(255,255,255,.07);

    font-size:7px;
}

.toast-wrap{

    position:fixed;

    left:14px;
    bottom:14px;

    z-index:10000;

    display:flex;

    flex-direction:column;

    gap:5px;
}

.toast{

    min-width:190px;

    padding:
        9px 11px;

    border-radius:10px;

    border:
        1px solid
        rgba(255,255,255,.08);

    color:#fff;

    background:
        rgba(17,24,39,.96);

    box-shadow:
        0 20px 40px
        rgba(0,0,0,.38);

    font-size:7px;
}

@media(max-width:800px){

    .stats{
        grid-template-columns:
            repeat(
                2,
                1fr
            );
    }
}

@media(max-width:600px){

    .app{
        width:
            calc(100% - 12px);
    }

    .stats{
        grid-template-columns:1fr;
    }

    .form{
        grid-template-columns:1fr;
    }

    .field.full{
        grid-column:auto;
    }

    .topbar{
        align-items:flex-start;
    }

}

</style>

</head>

<body>

<div class="app">

<!-- ======================================================
     HEADER
====================================================== -->

<div class="topbar">

<div class="brand">

<div class="logo">
P
</div>

<div>

<div class="brand-name">
PixonPanel
</div>

<div class="brand-version">
12.0.1 Beta · @Pixonal
</div>

</div>

</div>


<div class="toolbar">

<button
    class="auto"
    onclick="autoCreate()"
>
ساخت خودکار
</button>

<button
    onclick="openManualModal()"
>
ساخت دستی
</button>

<button
    onclick="openPasswordModal()"
>
تغییر رمز
</button>

<a
    href="/logout"
>
خروج
</a>

</div>

</div>


<!-- ======================================================
     STATS
====================================================== -->

<div class="stats">

<div class="stat">

<div class="stat-label">
کل کانفیگ‌ها
</div>

<div
    id="totalLinks"
    class="stat-value"
>
0
</div>

<div class="stat-sub">
Services
</div>

</div>


<div class="stat">

<div class="stat-label">
فعال
</div>

<div
    id="activeLinks"
    class="stat-value"
>
0
</div>

<div class="stat-sub">
Active
</div>

</div>


<div class="stat">

<div class="stat-label">
اتصالات
</div>

<div
    id="connections"
    class="stat-value"
>
0
</div>

<div class="stat-sub">
Live Connections
</div>

</div>


<div class="stat">

<div class="stat-label">
آپتایم
</div>

<div
    id="uptime"
    class="stat-value"
>
00:00:00
</div>

<div
    id="clock"
    class="stat-sub"
>
-
</div>

</div>

</div>


<!-- ======================================================
     CONFIGS
====================================================== -->

<section class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
کانفیگ‌ها
</div>

<div class="panel-sub">
ساخت · ویرایش · حذف · مدیریت
</div>

</div>

<button
    class="primary"
    onclick="autoCreate()"
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
Protocol
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
     ACTIVITY
====================================================== -->

<section class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
Activity
</div>

<div class="panel-sub">
رویدادهای اخیر
</div>

</div>

</div>

<div
    id="logs"
    class="logs"
>
</div>

</section>

</div>


<!-- ======================================================
     CONFIG MODAL
====================================================== -->

<div
    id="configModal"
    class="modal"
>

<div class="modal-card">

<div class="modal-head">

<div>

<div
    id="configModalTitle"
    class="modal-title"
>
ساخت کانفیگ دستی
</div>

<div class="modal-desc">
تمام تنظیمات سرویس
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
    placeholder="مثلاً VIP تهران"
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

<option value="TB">
TB
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
0 = نامحدود
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
    maxlength="300"
    placeholder="توضیحات..."
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
    id="saveConfigButton"
    class="modal-btn save"
    onclick="saveConfig()"
>
ساخت کانفیگ
</button>

</div>

</div>

</div>


<!-- ======================================================
     RESULT MODAL
====================================================== -->

<div
    id="resultModal"
    class="modal"
>

<div class="modal-card">

<div class="modal-head">

<div>

<div class="modal-title">
کانفیگ آماده شد
</div>

<div class="modal-desc">
VLESS · SUB · INFO
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
    class="copy"
    onclick="copyValue('resultVless')"
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
    class="copy"
    onclick="copyValue('resultSub')"
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
    class="copy"
    onclick="copyValue('resultInfo')"
>
کپی
</button>

</div>

</div>


</div>

</div>

</div>


<!-- ======================================================
     DELETE MODAL
====================================================== -->

<div
    id="deleteModal"
    class="modal"
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
        padding:17px;
    "
>

<div
    style="
        color:
            rgba(255,255,255,.48);
        font-size:9px;
        line-height:2;
    "
>
آیا مطمئن هستید؟
</div>

<div
    id="deleteTarget"
    style="
        margin-top:9px;
        padding:10px;
        border-radius:10px;
        color:#fca5a5;
        background:
            rgba(239,68,68,.07);
        border:
            1px solid
            rgba(239,68,68,.13);
        font-size:8px;
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
    id="deleteButton"
    class="modal-btn"
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
     PASSWORD MODAL
====================================================== -->

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
    id="toastWrap"
    class="toast-wrap"
></div>


<script>

/* ==========================================================
   STATE
========================================================== */

let editingUuid = null;
let deletingUuid = null;
let uptimeBase = null;


/* ==========================================================
   API
========================================================== */

async function api(
    url,
    options = {}
){

    const response =
        await fetch(
            url,
            options
        );

    if(
        response.status === 401
    ){

        location.href =
            "/login";

        return null;
    }

    let data = {};

    try{

        data =
            await response.json();

    }catch{

        data = {};
    }

    if(!response.ok){

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
   TOAST
========================================================== */

function toast(
    message,
    isError = false
){

    const element =
        document.createElement(
            "div"
        );

    element.className =
        "toast";

    if(
        isError
    ){

        element.style.borderColor =
            "rgba(239,68,68,.25)";
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

            setTimeout(
                () => element.remove(),
                180
            );

        },
        2500
    );
}


/* ==========================================================
   ESCAPE
========================================================== */

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


/* ==========================================================
   FORMAT
========================================================== */

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
            value
            + " B"
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
            + " KB"
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
            + " MB"
        );
    }

    return (
        (
            value /
            1024 ** 3
        ).toFixed(2)
        + " GB"
    );
}


/* ==========================================================
   MODAL
========================================================== */

function openManualModal(){

    editingUuid =
        null;

    document.getElementById(
        "configModalTitle"
    ).textContent =
        "ساخت کانفیگ دستی";

    document.getElementById(
        "saveConfigButton"
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
){

    editingUuid =
        link.uuid;

    document.getElementById(
        "configModalTitle"
    ).textContent =
        "ویرایش کانفیگ";

    document.getElementById(
        "saveConfigButton"
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
        link.duration_days || "";


    document.getElementById(
        "fieldConcurrent"
    ).value =
        link.concurrent_limit || "";


    document.getElementById(
        "fieldIp"
    ).value =
        link.ip_limit || "";


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
        link.port || 443;


    document.getElementById(
        "fieldAlpn"
    ).value =
        link.alpn || "";


    document.getElementById(
        "fieldNote"
    ).value =
        link.note || "";


    document.getElementById(
        "configModal"
    ).classList.add(
        "show"
    );
}


function closeConfigModal(){

    document.getElementById(
        "configModal"
    ).classList.remove(
        "show"
    );
}


function resetForm(){

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
    ).value =
        "";

    document.getElementById(
        "fieldNote"
    ).value =
        "";
}


/* ==========================================================
   AUTO
========================================================== */

async function autoCreate(){

    try{

        const result =
            await api(
                "/api/links/auto",
                {
                    method:
                        "POST"
                }
            );

        if(!result)
            return;

        showResult(
            result
        );

        toast(
            `${result.label} ساخته شد.`
        );

        await refreshAll();

    }catch(error){

        toast(
            error.message,
            true
        );
    }
}


/* ==========================================================
   SAVE CONFIG
========================================================== */

async function saveConfig(){

    const button =
        document.getElementById(
            "saveConfigButton"
        );

    const oldText =
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
                    "fieldIp"
                ).value
                || 0
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


    if(
        !payload.label
    ){

        toast(
            "نام کانفیگ را وارد کنید.",
            true
        );

        return;
    }


    button.disabled =
        true;

    button.textContent =
        "در حال ذخیره...";


    try{

        let result;


        if(
            editingUuid
        ){

            result =
                await api(
                    "/api/links/"
                    +
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
                                payload
                            )
                    }
                );

            closeConfigModal();

            toast(
                "تغییرات ذخیره شد."
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

    }catch(error){

        toast(
            error.message,
            true
        );

    }finally{

        button.disabled =
            false;

        button.textContent =
            oldText;
    }
}


/* ==========================================================
   RESULT
========================================================== */

function showResult(
    data
){

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


function closeResultModal(){

    document.getElementById(
        "resultModal"
    ).classList.remove(
        "show"
    );
}


async function copyValue(
    id
){

    const input =
        document.getElementById(
            id
        );

    try{

        await navigator.clipboard.writeText(
            input.value
        );

    }catch{

        input.select();

        document.execCommand(
            "copy"
        );
    }

    toast(
        "کپی شد."
    );
}


async function copyDirect(
    text
){

    try{

        await navigator.clipboard.writeText(
            text
        );

        toast(
            "کپی شد."
        );

    }catch{

        window.prompt(
            "لینک:",
            text
        );
    }
}


/* ==========================================================
   DELETE
========================================================== */

function openDeleteModal(
    uuid,
    label
){

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


function closeDeleteModal(){

    deletingUuid =
        null;

    document.getElementById(
        "deleteModal"
    ).classList.remove(
        "show"
    );
}


async function confirmDelete(){

    if(
        !deletingUuid
    )
        return;


    const button =
        document.getElementById(
            "deleteButton"
        );

    button.disabled =
        true;

    button.textContent =
        "در حال حذف...";


    try{

        await api(
            "/api/links/"
            +
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

    }catch(error){

        toast(
            error.message,
            true
        );

    }finally{

        button.disabled =
            false;

        button.textContent =
            "حذف";
    }
}


/* ==========================================================
   TOGGLE
========================================================== */

async function toggleLink(
    uuid,
    active
){

    try{

        await api(
            "/api/links/"
            +
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

    }catch(error){

        toast(
            error.message,
            true
        );
    }
}


/* ==========================================================
   RESET
========================================================== */

async function resetUsage(
    uuid
){

    try{

        await api(
            "/api/links/"
            +
            encodeURIComponent(
                uuid
            )
            +
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

    }catch(error){

        toast(
            error.message,
            true
        );
    }
}


/* ==========================================================
   PASSWORD
========================================================== */

function openPasswordModal(){

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


function closePasswordModal(){

    document.getElementById(
        "passwordModal"
    ).classList.remove(
        "show"
    );
}


async function changePassword(){

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


    if(
        !current
        ||
        !next
        ||
        !confirm
    ){

        toast(
            "هر سه فیلد را کامل کنید.",
            true
        );

        return;
    }


    if(
        next !== confirm
    ){

        toast(
            "تکرار رمز جدید درست نیست.",
            true
        );

        return;
    }


    if(
        next.length < 8
    ){

        toast(
            "رمز جدید حداقل ۸ کاراکتر باشد.",
            true
        );

        return;
    }


    try{

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
            "رمز عبور با موفقیت تغییر کرد."
        );

    }catch(error){

        toast(
            error.message,
            true
        );
    }
}


/* ==========================================================
   RENDER LINKS
========================================================== */

function renderLinks(
    links
){

    const table =
        document.getElementById(
            "linksTable"
        );


    if(
        !links.length
    ){

        table.innerHTML = `

        <tr>

        <td
            colspan="7"
            style="
                text-align:center;
                padding:35px;
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
            هنوز کانفیگی ساخته نشده است.
        </td>

        </tr>

        `;

        return;
    }


    table.innerHTML =
        "";


    links.forEach(
        link => {

            const tr =
                document.createElement(
                    "tr"
                );

            const usage =
                Number(
                    link.limit_bytes
                )
                > 0
                ? Math.min(
                    100,
                    (
                        Number(
                            link.used_bytes
                            || 0
                        )
                        /
                        Number(
                            link.limit_bytes
                        )
                    )
                    * 100
                )
                : 0;


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
        ? "good"
        : "bad"
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
        --usage:
        ${usage}%;
    "
>

<div
    class="usage-fill"
></div>

</div>

</div>

</td>


<td>

${
    Number(
        link.connections
        || 0
    )
}

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
    onclick='openEditModal(
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
    );
}


/* ==========================================================
   REFRESH LINKS
========================================================== */

async function refreshLinks(){

    try{

        const data =
            await api(
                "/api/links"
            );

        if(!data)
            return;

        renderLinks(
            data.links
        );

    }catch(error){

        console.error(
            error
        );
    }
}


/* ==========================================================
   REFRESH STATS
========================================================== */

async function refreshStats(){

    try{

        const data =
            await api(
                "/stats"
            );

        if(!data)
            return;


        document.getElementById(
            "totalLinks"
        ).textContent =
            data.links_count;


        document.getElementById(
            "activeLinks"
        ).textContent =
            data.active_links;


        document.getElementById(
            "connections"
        ).textContent =
            data.active_connections;


        document.getElementById(
            "uptime"
        ).textContent =
            data.uptime;


        document.getElementById(
            "clock"
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
                *
                1000
            );

    }catch(error){

        console.error(
            error
        );
    }
}


/* ==========================================================
   LOCAL UPTIME
========================================================== */

function tickUptime(){

    if(
        !uptimeBase
    )
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


    const days =
        Math.floor(
            seconds
            / 86400
        );


    const hours =
        Math.floor(
            (
                seconds
                % 86400
            )
            / 3600
        );


    const minutes =
        Math.floor(
            (
                seconds
                % 3600
            )
            / 60
        );


    const secs =
        seconds
        % 60;


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
        ].join(
            ":"
        );


    document.getElementById(
        "uptime"
    ).textContent =
        days
        ? `${days}d ${text}`
        : text;
}


/* ==========================================================
   ACTIVITY
========================================================== */

async function refreshActivity(){

    try{

        const data =
            await api(
                "/api/activity"
            );

        if(!data)
            return;

        const box =
            document.getElementById(
                "logs"
            );


        if(
            !data.logs.length
        ){

            box.innerHTML =
                `
                <div
                    style="
                        padding:8px 0;
                        color:
                            rgba(
                                255,
                                255,
                                255,
                                .22
                            );
                        font-size:7px;
                    "
                >
                    فعالیتی ثبت نشده است.
                </div>
                `;

            return;
        }


        box.innerHTML =
            data.logs
                .slice()
                .reverse()
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

    }catch(error){

        console.error(
            error
        );
    }
}


/* ==========================================================
   REFRESH ALL
========================================================== */

async function refreshAll(){

    await Promise.all([
        refreshStats(),
        refreshLinks(),
        refreshActivity()
    ]);
}


/* ==========================================================
   MODAL OUTSIDE
========================================================== */

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
            .addEventListener(
                "click",
                function(event){

                    if(
                        event.target
                        === this
                    ){

                        this.classList.remove(
                            "show"
                        );
                    }

                }
            );

    }
);


/* ==========================================================
   ESCAPE
========================================================== */

document.addEventListener(
    "keydown",
    event => {

        if(
            event.key !==
            "Escape"
        )
            return;

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


/* ==========================================================
   START
========================================================== */

refreshAll();

/*
    Stats:
    every 1 second
*/

setInterval(
    refreshStats,
    1000
);

/*
    Config table:
    every 1 second
*/

setInterval(
    refreshLinks,
    1000
);

/*
    Activity:
    every 1 second
*/

setInterval(
    refreshActivity,
    1000
);

/*
    Local uptime:
    every 1 second
*/

setInterval(
    tickUptime,
    1000
);

</script>

</body>

</html>
"""


# ============================================================
# DASHBOARD ROUTE
# ============================================================

@app.get(
    "/dashboard",
    response_class=HTMLResponse
)
async def dashboard(
    request: Request
):

    if not await is_valid_session(
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

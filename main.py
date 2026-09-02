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
from urllib.parse import quote
from zoneinfo import ZoneInfo

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

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(
    title=APP_NAME,
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
# Configuration
# ============================================================

DATA_DIR = Path(
    os.environ.get(
        "DATA_DIR",
        "./data",
    )
)

DATA_FILE = DATA_DIR / "pixonpanel_state.json"
SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"

PORT = int(
    os.environ.get(
        "PORT",
        "8000",
    )
)

SESSION_TTL = 60 * 60 * 24 * 365

SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()

# ============================================================
# Secret
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")

    if env_secret:
        return env_secret

    try:
        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if SECRET_FILE.exists():
            value = SECRET_FILE.read_text(
                encoding="utf-8"
            ).strip()

            if value:
                return value

        value = secrets.token_urlsafe(32)

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

        return secrets.token_urlsafe(32)


SECRET_KEY = load_or_create_secret()

# ============================================================
# In-memory state
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
# Auth
# ============================================================

SESSION_COOKIE = "pixonpanel_session"


def hash_password(password: str) -> str:
    return hashlib.sha256(
        f"{password}{SECRET_KEY}".encode(
            "utf-8"
        )
    ).hexdigest()


AUTH = {
    "password_hash": hash_password(
        os.environ.get(
            "ADMIN_PASSWORD",
            "pxpanel2026",
        )
    )
}


async def create_session() -> str:
    token = secrets.token_urlsafe(48)

    async with SESSIONS_LOCK:
        SESSIONS[token] = (
            time.time() + SESSION_TTL
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

    if not await is_valid_session(token):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )

    return token

# ============================================================
# Persistence
# ============================================================

async def load_state():
    global LINKS
    global SUBS

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

        stored_password = data.get(
            "password_hash"
        )

        if stored_password:
            AUTH["password_hash"] = (
                stored_password
            )

        logger.info(
            "State loaded: %s links / %s subscriptions",
            len(LINKS),
            len(SUBS),
        )

    except Exception as exc:
        logger.warning(
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

            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "password_hash": AUTH[
                    "password_hash"
                ],
                "saved_at": datetime.now().isoformat(),
            }

            tmp_file = DATA_FILE.with_suffix(
                ".tmp"
            )

            async with aiofiles.open(
                tmp_file,
                "w",
                encoding="utf-8",
            ) as file:

                await file.write(
                    json.dumps(
                        data,
                        ensure_ascii=False,
                        indent=2,
                    )
                )

            tmp_file.replace(DATA_FILE)

        except Exception as exc:
            logger.warning(
                "Could not save state: %s",
                exc,
            )

# ============================================================
# Helpers
# ============================================================

def generate_uuid() -> str:
    value = secrets.token_hex(16)

    return (
        f"{value[:8]}-"
        f"{value[8:12]}-"
        f"{value[12:16]}-"
        f"{value[16:20]}-"
        f"{value[20:32]}"
    )


def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)


def uptime() -> str:
    seconds = int(
        time.time()
        - stats["start_time"]
    )

    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    secs = seconds % 60

    return (
        f"{hours:02d}:"
        f"{minutes:02d}:"
        f"{secs:02d}"
    )


def fmt_bytes(value: int) -> str:
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

    if value < 1024 ** 4:
        return (
            f"{value / 1024 ** 3:.2f} GB"
        )

    return (
        f"{value / 1024 ** 4:.2f} TB"
    )


def parse_size_to_bytes(
    value: float,
    unit: str,
) -> int:

    unit = (
        unit or "GB"
    ).upper()

    if value <= 0:
        return 0

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
) -> int:

    if value <= 0:
        return 0

    unit = (
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
            * 1024 ** 3
            / 8
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


def is_link_expired(
    link: dict,
) -> bool:

    expires_at = link.get(
        "expires_at"
    )

    if not expires_at:
        return False

    try:
        return (
            datetime.now()
            > datetime.fromisoformat(
                expires_at
            )
        )

    except Exception:
        return False


def is_link_allowed(
    link: dict | None,
) -> bool:

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


def get_host(
    request: Request | None = None,
) -> str:

    if request is not None:
        value = (
            request.headers.get(
                "x-forwarded-host"
            )
            or request.headers.get(
                "host"
            )
        )

        if value:
            return value.split(":")[0]

    return os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN",
        "localhost",
    )


def log_activity(
    kind: str,
    message: str,
    level: str = "info",
):
    activity_logs.append(
        {
            "kind": kind,
            "message": message,
            "level": level,
            "time": datetime.now().isoformat(),
        }
    )


# ============================================================
# VLESS
# ============================================================

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
)

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

DEFAULT_PROTOCOL = "vless-ws"
DEFAULT_FINGERPRINT = "chrome"
DEFAULT_PORT = 443


def generate_vless_link(
    uuid: str,
    host: str,
    remark: str = "PixonPanel",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
) -> str:

    fingerprint = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    port = port or DEFAULT_PORT

    if not 1 <= port <= 65535:
        port = DEFAULT_PORT

    if protocol == "vless-ws":

        path = f"/ws/{uuid}"

        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fingerprint,
            "alpn": (
                alpn
                or "http/1.1"
            ),
        }

    else:

        mode = protocol.replace(
            "xhttp-",
            "",
        )

        path = (
            f"/xhttp/"
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
            "fp": fingerprint,
            "alpn": (
                alpn
                or "h2,http/1.1"
            ),
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
        f"{port}?"
        f"{query}#"
        f"{quote(remark)}"
    )


def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
) -> str:

    return generate_vless_link(
        uuid=uid,
        host=host,
        remark=(
            "PixonPanel-"
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
# Link Management
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

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    if not 1 <= port <= 65535:
        port = DEFAULT_PORT

    uid = generate_uuid()

    link = {
        "label": (
            label
            or "لینک جدید"
        )[:60],
        "limit_bytes": max(
            0,
            limit_bytes,
        ),
        "used_bytes": 0,
        "created_at": datetime.now().isoformat(),
        "active": True,
        "expires_at": expires_at,
        "note": (
            note
            or ""
        )[:200],
        "is_default": False,
        "sub_id": sub_id,
        "protocol": protocol,
        "fingerprint": fingerprint,
        "alpn": (
            alpn
            or ""
        )[:100],
        "port": port,
        "ip_limit": max(
            0,
            ip_limit,
        ),
        "speed_limit_bytes": max(
            0,
            speed_limit_bytes,
        ),
    }

    async with LINKS_LOCK:
        LINKS[uid] = link

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

    asyncio.create_task(
        save_state()
    )

    log_activity(
        "link",
        f"کانفیگ «{link['label']}» ساخته شد",
        "ok",
    )

    return uid, link


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
        ].get("sub_id")

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

    asyncio.create_task(
        save_state()
    )

    log_activity(
        "link",
        f"کانفیگ «{label}» حذف شد",
        "warn",
    )

    return label


# ============================================================
# Default Link
# ============================================================

_default_link_created = False


async def ensure_default_link():

    global _default_link_created

    if _default_link_created:
        return

    async with LINKS_LOCK:

        exists = any(
            item.get(
                "is_default"
            )
            for item in LINKS.values()
        )

        if not exists:

            digest = hashlib.sha256(
                (
                    "default"
                    + SECRET_KEY
                ).encode()
            ).hexdigest()

            uid = (
                f"{digest[:8]}-"
                f"{digest[8:12]}-"
                f"{digest[12:16]}-"
                f"{digest[16:20]}-"
                f"{digest[20:32]}"
            )

            LINKS[uid] = {
                "label": "لینک پیش‌فرض",
                "limit_bytes": 0,
                "used_bytes": 0,
                "created_at": datetime.now().isoformat(),
                "active": True,
                "expires_at": None,
                "note": "",
                "is_default": True,
                "sub_id": None,
                "protocol": DEFAULT_PROTOCOL,
                "fingerprint": DEFAULT_FINGERPRINT,
                "alpn": "",
                "port": DEFAULT_PORT,
                "ip_limit": 0,
                "speed_limit_bytes": 0,
            }

            asyncio.create_task(
                save_state()
            )

    _default_link_created = True


# ============================================================
# Startup
# ============================================================

@app.on_event("startup")
async def startup():

    global http_client

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(
            30.0,
            connect=10.0,
        ),
        limits=httpx.Limits(
            max_connections=300,
            max_keepalive_connections=80,
        ),
        follow_redirects=True,
    )

    await load_state()

    log_activity(
        "system",
        "PixonPanel راه‌اندازی شد",
        "ok",
    )

    logger.info(
        "%s v%s started on port %s",
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
# Landing Page
# ============================================================

LANDING_HTML = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
/>

<title>PixonPanel</title>

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

    justify-content: center;

    align-items: center;

    padding: 24px;

    overflow: hidden;

    font-family:
        Vazirmatn,
        IRANSans,
        Tahoma,
        Arial,
        sans-serif;

    color: white;

    background:
        radial-gradient(
            circle at 15% 20%,
            rgba(99,102,241,.20),
            transparent 32%
        ),
        radial-gradient(
            circle at 85% 80%,
            rgba(168,85,247,.17),
            transparent 32%
        ),
        #06070b;
}

.glow {

    position: fixed;

    width: 280px;
    height: 280px;

    border-radius: 50%;

    filter: blur(110px);

    opacity: .18;

    pointer-events: none;
}

.glow-one {

    top: -120px;
    right: -80px;

    background: #6366f1;
}

.glow-two {

    bottom: -120px;
    left: -100px;

    background: #a855f7;
}

.container {

    width: 100%;
    max-width: 560px;

    position: relative;

    z-index: 5;
}

.card {

    padding: 34px;

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
        blur(30px)
        saturate(150%);

    -webkit-backdrop-filter:
        blur(30px)
        saturate(150%);

    box-shadow:
        0 40px 100px
        rgba(0,0,0,.45),

        inset 0 1px 0
        rgba(255,255,255,.05);
}

.brand {

    display: flex;

    align-items: center;

    gap: 14px;

    margin-bottom: 32px;
}

.logo {

    width: 52px;
    height: 52px;

    border-radius: 17px;

    display: flex;

    justify-content: center;
    align-items: center;

    font-size: 19px;

    font-weight: 900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    box-shadow:
        0 14px 34px
        rgba(99,102,241,.30);
}

.brand-title {

    font-size: 17px;

    font-weight: 900;
}

.brand-subtitle {

    margin-top: 5px;

    font-size: 12px;

    color:
        rgba(255,255,255,.43);
}

.badge {

    width: fit-content;

    padding:
        7px 11px;

    border-radius: 999px;

    border:
        1px solid
        rgba(34,197,94,.16);

    background:
        rgba(34,197,94,.07);

    color:
        #86efac;

    font-size: 11px;

    margin-bottom: 18px;
}

h1 {

    margin: 0;

    font-size: 30px;

    line-height: 1.45;

    font-weight: 900;

    letter-spacing: -.7px;
}

.description {

    margin-top: 14px;

    color:
        rgba(255,255,255,.55);

    font-size: 14px;

    line-height: 2;
}

.command-box {

    margin-top: 25px;

    padding: 16px;

    border-radius: 18px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(0,0,0,.19);
}

.command-title {

    margin-bottom: 9px;

    font-size: 11px;

    color:
        rgba(255,255,255,.42);
}

.command {

    display: block;

    padding:
        13px 14px;

    direction: ltr;

    text-align: left;

    font-family:
        Consolas,
        monospace;

    border-radius: 13px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(255,255,255,.04);

    color:
        #c4b5fd;

    user-select: all;
}

.actions {

    display: flex;

    gap: 10px;

    margin-top: 22px;
}

.btn {

    flex: 1;

    padding: 14px;

    border-radius: 14px;

    text-align: center;

    text-decoration: none;

    font-size: 13px;

    font-weight: 800;

    transition:
        transform .2s ease,
        background .2s ease;
}

.btn:hover {

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

    box-shadow:
        0 14px 30px
        rgba(99,102,241,.20);
}

.secondary {

    color:
        rgba(255,255,255,.82);

    background:
        rgba(255,255,255,.035);

    border:
        1px solid
        rgba(255,255,255,.08);
}

.footer {

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    margin-top: 23px;

    padding-top: 18px;

    border-top:
        1px solid
        rgba(255,255,255,.07);

    color:
        rgba(255,255,255,.35);

    font-size: 11px;
}

.support {

    color:
        #a78bfa;

    text-decoration: none;
}

@media (max-width: 600px) {

    .card {
        padding: 25px;
        border-radius: 24px;
    }

    h1 {
        font-size: 25px;
    }

    .actions {
        flex-direction: column;
    }
}

</style>

</head>

<body>

<div class="glow glow-one"></div>
<div class="glow glow-two"></div>

<main class="container">

<section class="card">

<div class="brand">

<div class="logo">
P
</div>

<div>

<div class="brand-title">
PixonPanel
</div>

<div class="brand-subtitle">
مدیریت حرفه‌ای سرویس و کانفیگ
</div>

</div>

</div>

<div class="badge">
● سرویس فعال است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<p class="description">
این صفحه عمومی PixonPanel است.
برای دسترسی به بخش مدیریت، از مسیر
ورود استفاده کنید.
</p>

<div class="command-box">

<div class="command-title">
دستور ورود
</div>

<div class="command">
/login
</div>

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
    class="btn secondary"
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

</section>

</main>

</body>

</html>
"""


@app.get(
    "/",
    response_class=HTMLResponse,
)
async def root():

    return HTMLResponse(
        content=LANDING_HTML
    )


# ============================================================
# Health
# ============================================================

@app.get("/health")
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
# Login
# ============================================================

LOGIN_HTML = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>ورود | PixonPanel</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    display: flex;

    align-items: center;

    justify-content: center;

    padding: 20px;

    color: white;

    font-family:
        Vazirmatn,
        Tahoma,
        sans-serif;

    background:
        radial-gradient(
            circle at 20% 15%,
            rgba(99,102,241,.20),
            transparent 30%
        ),
        #07070a;
}

.card {

    width: 100%;

    max-width: 430px;

    padding: 30px;

    border-radius: 26px;

    border:
        1px solid
        rgba(255,255,255,.09);

    background:
        rgba(255,255,255,.045);

    backdrop-filter: blur(28px);

    box-shadow:
        0 35px 80px
        rgba(0,0,0,.40);
}

.logo {

    width: 48px;
    height: 48px;

    display: flex;

    justify-content: center;
    align-items: center;

    border-radius: 15px;

    font-weight: 900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    margin-bottom: 22px;
}

h1 {

    margin: 0;

    font-size: 25px;
}

p {

    color:
        rgba(255,255,255,.5);

    font-size: 13px;

    line-height: 2;

    margin-top: 9px;
}

label {

    display: block;

    margin:
        22px 0 8px;

    color:
        rgba(255,255,255,.55);

    font-size: 12px;
}

input {

    width: 100%;

    padding: 14px;

    border-radius: 14px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(0,0,0,.20);

    outline: none;

    color: white;

    font-size: 14px;

    direction: ltr;

    text-align: left;
}

input:focus {

    border-color:
        rgba(139,92,246,.55);
}

button {

    width: 100%;

    margin-top: 16px;

    border: 0;

    padding: 14px;

    border-radius: 14px;

    color: white;

    font-weight: 800;

    cursor: pointer;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.error {

    display: none;

    margin-top: 12px;

    padding: 11px;

    border-radius: 12px;

    background:
        rgba(239,68,68,.08);

    border:
        1px solid
        rgba(239,68,68,.16);

    color:
        #fca5a5;

    font-size: 12px;
}

.support {

    display: block;

    text-align: center;

    margin-top: 18px;

    color:
        #a78bfa;

    font-size: 11px;

    text-decoration: none;
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

<p>
برای دسترسی به داشبورد مدیریت،
رمز عبور خود را وارد کنید.
</p>

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
    placeholder="••••••••"
/>

<button type="submit">
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


@app.post(
    "/login",
)
async def login(
    request: Request,
):

    form = await request.form()

    password = str(
        form.get(
            "password",
            "",
        )
    )

    if hash_password(
        password
    ) != AUTH[
        "password_hash"
    ]:

        return HTMLResponse(
            LOGIN_HTML.replace(
                "</form>",
                """
                <div
                    class="error"
                    style="display:block"
                >
                    رمز عبور اشتباه است.
                </div>
                </form>
                """,
            ),
            status_code=401,
        )

    token = await create_session()

    response = RedirectResponse(
        "/dashboard",
        status_code=303,
    )

    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=False,
    )

    log_activity(
        "auth",
        "ورود موفق به پنل",
        "ok",
    )

    return response


@app.get(
    "/logout",
)
async def logout(
    request: Request,
):

    token = request.cookies.get(
        SESSION_COOKIE
    )

    await destroy_session(
        token
    )

    response = RedirectResponse(
        "/login"
    )

    response.delete_cookie(
        SESSION_COOKIE
    )

    return response


# ============================================================
# Link APIs
# ============================================================

@app.post(
    "/api/links"
)
async def create_link(
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
        )

    except Exception:

        limit_value = 0

    limit_unit = body.get(
        "limit_unit",
        "GB",
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
        )

    except Exception:

        port = DEFAULT_PORT

    try:

        ip_limit = int(
            body.get(
                "ip_limit",
                0,
            )
        )

    except Exception:

        ip_limit = 0

    try:

        speed_value = float(
            body.get(
                "speed_limit_value",
                0,
            )
        )

    except Exception:

        speed_value = 0

    speed_unit = body.get(
        "speed_limit_unit",
        "MBIT",
    )

    speed_limit = (
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
        speed_limit_bytes=speed_limit,
    )

    host = get_host(
        request
    )

    return {
        "uuid": uid,
        **link,
        "expired": False,
        "vless_link": (
            vless_link_for_link(
                link,
                uid,
                host,
            )
        ),
        "sub_url": (
            f"https://"
            f"{host}/sub/"
            f"{uid}"
        ),
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
                "uuid": uid,
                **link,
                "expired": is_link_expired(
                    link
                ),
                "vless_link": (
                    vless_link_for_link(
                        link,
                        uid,
                        host,
                    )
                ),
                "sub_url": (
                    f"https://"
                    f"{host}/sub/"
                    f"{uid}"
                ),
            }
        )

    result.sort(
        key=lambda item: item[
            "created_at"
        ],
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
                404,
                "link not found",
            )

        link = LINKS[
            uid
        ]

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
            "reset_usage"
        ):

            link[
                "used_bytes"
            ] = 0

        if "limit_value" in body:

            value = float(
                body.get(
                    "limit_value",
                    0,
                )
                or 0
            )

            unit = body.get(
                "limit_unit",
                "GB",
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

            days = int(
                body.get(
                    "expires_days",
                    0,
                )
                or 0
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

            fp = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).lower()

            link[
                "fingerprint"
            ] = (
                fp
                if fp in FINGERPRINTS
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

            port = int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                )
                or DEFAULT_PORT
            )

            link[
                "port"
            ] = (
                port
                if 1 <= port <= 65535
                else DEFAULT_PORT
            )

        if "ip_limit" in body:

            value = int(
                body.get(
                    "ip_limit",
                    0,
                )
                or 0
            )

            link[
                "ip_limit"
            ] = max(
                0,
                value,
            )

        if "speed_limit_value" in body:

            value = float(
                body.get(
                    "speed_limit_value",
                    0,
                )
                or 0
            )

            unit = body.get(
                "speed_limit_unit",
                "MBIT",
            )

            link[
                "speed_limit_bytes"
            ] = (
                0
                if value <= 0
                else parse_speed_to_bytes(
                    value,
                    unit,
                )
            )

    await save_state()

    log_activity(
        "link",
        f"کانفیگ «{link['label']}» ویرایش شد",
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
            404,
            "link not found",
        )

    return {
        "ok": True,
        "deleted": uid,
    }


# ============================================================
# Subscription APIs
# ============================================================

@app.get(
    "/sub/{uuid}"
)
async def subscription(
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
            404,
            "not found or inactive",
        )

    host = get_host(
        request
    )

    config = vless_link_for_link(
        link,
        uuid,
        host,
    )

    encoded = (
        base64.b64encode(
            config.encode()
        )
        .decode()
    )

    return Response(
        content=encoded,
        media_type="text/plain",
        headers={
            "profile-title": quote(
                link[
                    "label"
                ]
            ),
            "support-url": SUPPORT_URL,
        },
    )


@app.post(
    "/api/subs"
)
async def create_sub(
    request: Request,
    _=Depends(require_auth),
):

    body = await request.json()

    sub_id = generate_uuid()

    public_key = secrets.token_urlsafe(
        18
    )

    sub = {
        "name": str(
            body.get(
                "name",
                "گروه جدید",
            )
        )[:60],
        "desc": str(
            body.get(
                "desc",
                "",
            )
        )[:200],
        "password_hash": (
            hash_password(
                str(
                    body.get(
                        "password",
                        "",
                    )
                )
            )
            if body.get(
                "password"
            )
            else None
        ),
        "uuid_key": public_key,
        "created_at": datetime.now().isoformat(),
        "link_ids": [],
    }

    async with SUBS_LOCK:
        SUBS[
            sub_id
        ] = sub

    await save_state()

    log_activity(
        "sub",
        f"گروه «{sub['name']}» ساخته شد",
        "ok",
    )

    host = get_host(
        request
    )

    return {
        "sub_id": sub_id,
        **sub,
        "password_hash": None,
        "public_url": (
            f"https://"
            f"{host}/p/"
            f"{public_key}"
        ),
        "sub_url": (
            f"https://"
            f"{host}/sub-group/"
            f"{public_key}"
        ),
    }


@app.get(
    "/api/subs"
)
async def list_subs(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(
        request
    )

    async with SUBS_LOCK:
        subscriptions = dict(
            SUBS
        )

    result = []

    for sid, sub in subscriptions.items():

        result.append(
            {
                "sub_id": sid,
                **sub,
                "password_hash": None,
                "has_password": (
                    sub.get(
                        "password_hash"
                    )
                    is not None
                ),
                "links_count": len(
                    sub.get(
                        "link_ids",
                        [],
                    )
                ),
                "public_url": (
                    f"https://"
                    f"{host}/p/"
                    f"{sub['uuid_key']}"
                ),
                "sub_url": (
                    f"https://"
                    f"{host}/sub-group/"
                    f"{sub['uuid_key']}"
                ),
            }
        )

    return {
        "subs": result
    }


@app.patch(
    "/api/subs/{sub_id}"
)
async def update_sub(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    body = await request.json()

    async with SUBS_LOCK:

        if sub_id not in SUBS:

            raise HTTPException(
                404,
                "sub not found",
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
            )

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
async def delete_sub(
    sub_id: str,
    _=Depends(require_auth),
):

    async with SUBS_LOCK:

        if sub_id not in SUBS:

            raise HTTPException(
                404,
                "sub not found",
            )

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

            if link.get(
                "sub_id"
            ) == sub_id:

                link[
                    "sub_id"
                ] = None

    await save_state()

    log_activity(
        "sub",
        f"گروه «{name}» حذف شد",
        "warn",
    )

    return {
        "ok": True
    }


@app.post(
    "/api/subs/{sub_id}/links"
)
async def assign_link(
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

    async with SUBS_LOCK:

        if sub_id not in SUBS:

            raise HTTPException(
                404,
                "sub not found",
            )

        ids = SUBS[
            sub_id
        ].setdefault(
            "link_ids",
            [],
        )

        if action == "add":

            if link_id not in ids:
                ids.append(
                    link_id
                )

        else:

            if link_id in ids:
                ids.remove(
                    link_id
                )

    async with LINKS_LOCK:

        if link_id in LINKS:

            LINKS[
                link_id
            ][
                "sub_id"
            ] = (
                sub_id
                if action == "add"
                else None
            )

    await save_state()

    return {
        "ok": True
    }


# ============================================================
# Public Subscription Group
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
                for item in SUBS.values()
                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not sub:

        raise HTTPException(
            404,
            "not found",
        )

    password = (
        request.query_params.get(
            "pw"
        )
        or ""
    )

    stored_password = sub.get(
        "password_hash"
    )

    if (
        stored_password
        and hash_password(
            password
        )
        != stored_password
    ):

        raise HTTPException(
            401,
            "password required",
        )

    host = get_host(
        request
    )

    lines = []

    async with LINKS_LOCK:

        for uid in sub.get(
            "link_ids",
            [],
        ):

            link = LINKS.get(
                uid
            )

            if link and is_link_allowed(
                link
            ):

                lines.append(
                    vless_link_for_link(
                        link,
                        uid,
                        host,
                    )
                )

    encoded = base64.b64encode(
        "\n".join(
            lines
        ).encode()
    ).decode()

    return Response(
        content=encoded,
        media_type="text/plain",
        headers={
            "profile-title": quote(
                sub.get(
                    "name",
                    APP_NAME,
                )
            ),
            "support-url": SUPPORT_URL,
        },
    )


# ============================================================
# Statistics
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
        "service": APP_NAME,
        "version": APP_VERSION,
        "active_connections": len(
            connections
        ),
        "total_traffic_mb": round(
            stats[
                "total_bytes"
            ]
            / (
                1024 ** 2
            ),
            2,
        ),
        "total_requests": stats[
            "total_requests"
        ],
        "total_errors": stats[
            "total_errors"
        ],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(
            hourly_traffic
        ),
        "recent_errors": list(
            error_logs
        )[-10:],
        "links_count": len(
            snapshot
        ),
        "active_links": sum(
            1
            for link in snapshot.values()
            if is_link_allowed(
                link
            )
        ),
        "expired_links": sum(
            1
            for link in snapshot.values()
            if is_link_expired(
                link
            )
        ),
        "subs_count": len(
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
        "logs": list(
            activity_logs
        )[-150:]
    }


@app.get(
    "/api/connections"
)
async def get_connections(
    _=Depends(require_auth),
):

    grouped = {}

    async with LINKS_LOCK:
        snapshot = dict(
            LINKS
        )

    for conn_id, connection in connections.items():

        ip = connection.get(
            "ip",
            "unknown",
        )

        uid = connection.get(
            "uuid"
        )

        link = snapshot.get(
            uid
        )

        label = (
            link.get(
                "label"
            )
            if link
            else "unknown"
        )

        group = grouped.setdefault(
            ip,
            {
                "ip": ip,
                "sessions": 0,
                "bytes": 0,
                "labels": set(),
                "transports": set(),
            },
        )

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
                "vless-ws",
            )
        )

    result = []

    for group in grouped.values():

        result.append(
            {
                "ip": group[
                    "ip"
                ],
                "sessions": group[
                    "sessions"
                ],
                "bytes": group[
                    "bytes"
                ],
                "bytes_fmt": fmt_bytes(
                    group[
                        "bytes"
                    ]
                ),
                "labels": sorted(
                    group[
                        "labels"
                    ]
                ),
                "transports": sorted(
                    group[
                        "transports"
                    ]
                ),
            }
        )

    return {
        "connections": result,
        "count": len(result),
        "raw_count": len(
            connections
        ),
    }


# ============================================================
# Public Subscription Page
# ============================================================

PUBLIC_PAGE_HTML = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>PixonPanel Subscription</title>

<style>

body {

    margin: 0;

    min-height: 100vh;

    display: flex;

    align-items: center;

    justify-content: center;

    background: #07070a;

    color: white;

    font-family:
        Tahoma,
        sans-serif;

    padding: 20px;
}

.card {

    width: 100%;

    max-width: 540px;

    padding: 28px;

    border-radius: 25px;

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

.info {

    color:
        rgba(255,255,255,.50);

    line-height: 2;

    font-size: 13px;
}

code {

    display: block;

    margin-top: 18px;

    padding: 15px;

    border-radius: 14px;

    background:
        rgba(0,0,0,.25);

    color:
        #c4b5fd;

    direction: ltr;

    text-align: left;
}

a {

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

<p class="info">
اشتراک سرویس شما آماده است.
برای دریافت Subscription از لینک زیر استفاده کنید.
</p>

<code id="url"></code>

<a
    href="https://t.me/Pixonal"
    target="_blank"
>
پشتیبانی @Pixonal
</a>

</div>

<script>

document.getElementById("url").textContent =
    location.origin +
    location.pathname.replace(
        "/p/",
        "/sub-group/"
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

        found = any(
            item.get(
                "uuid_key"
            ) == uuid_key
            for item in SUBS.values()
        )

    if not found:

        return HTMLResponse(
            "<h2 style='font-family:sans-serif;padding:40px'>گروه پیدا نشد</h2>",
            status_code=404,
        )

    return HTMLResponse(
        PUBLIC_PAGE_HTML
    )


@app.get(
    "/api/public/sub/{uuid_key}"
)
async def public_sub_data(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        sub_entry = next(
            (
                pair
                for pair in SUBS.items()
                if pair[1].get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not sub_entry:

        raise HTTPException(
            404,
            "not found",
        )

    sub_id, sub = sub_entry

    stored_password = sub.get(
        "password_hash"
    )

    if stored_password:

        password = request.query_params.get(
            "pw",
            "",
        )

        if hash_password(
            password
        ) != stored_password:

            return JSONResponse(
                {
                    "locked": True,
                    "name": sub[
                        "name"
                    ],
                }
            )

    host = get_host(
        request
    )

    links_out = []

    active_connections = 0

    async with LINKS_LOCK:

        snapshot = dict(
            LINKS
        )

    for uid in sub.get(
        "link_ids",
        [],
    ):

        link = snapshot.get(
            uid
        )

        if not link:
            continue

        count = sum(
            1
            for connection
            in connections.values()
            if connection.get(
                "uuid"
            ) == uid
        )

        active_connections += count

        links_out.append(
            {
                "uuid": uid,
                "label": link[
                    "label"
                ],
                "active": is_link_allowed(
                    link
                ),
                "protocol": link.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                ),
                "used_bytes": link.get(
                    "used_bytes",
                    0,
                ),
                "used_fmt": fmt_bytes(
                    link.get(
                        "used_bytes",
                        0,
                    )
                ),
                "limit_bytes": link.get(
                    "limit_bytes",
                    0,
                ),
                "limit_fmt": (
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
                "expires_at": link.get(
                    "expires_at"
                ),
                "vless_link": (
                    vless_link_for_link(
                        link,
                        uid,
                        host,
                    )
                ),
                "sub_url": (
                    f"https://"
                    f"{host}/sub/"
                    f"{uid}"
                ),
                "connections": count,
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
        "name": sub[
            "name"
        ],
        "desc": sub.get(
            "desc",
            "",
        ),
        "sub_url": (
            f"https://"
            f"{host}/sub-group/"
            f"{uuid_key}"
        ),
        "active_connections": active_connections,
        "total_used_fmt": fmt_bytes(
            total_used
        ),
        "links": links_out,
    }


# ============================================================
# Dashboard
# ============================================================

DASHBOARD_HTML = """
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1"
/>

<title>PixonPanel Dashboard</title>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    min-height: 100vh;

    color: white;

    font-family:
        Vazirmatn,
        Tahoma,
        sans-serif;

    background:
        radial-gradient(
            circle at 10% 5%,
            rgba(99,102,241,.13),
            transparent 28%
        ),
        radial-gradient(
            circle at 90% 90%,
            rgba(168,85,247,.12),
            transparent 28%
        ),
        #07070a;
}

.wrapper {

    width: min(
        1200px,
        calc(100% - 32px)
    );

    margin: 0 auto;

    padding: 28px 0;
}

.topbar {

    display: flex;

    justify-content:
        space-between;

    align-items: center;

    gap: 15px;

    margin-bottom: 24px;
}

.brand {

    display: flex;

    align-items: center;

    gap: 12px;
}

.logo {

    width: 45px;
    height: 45px;

    border-radius: 14px;

    display: flex;

    justify-content: center;
    align-items: center;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );

    font-weight: 900;
}

.title {

    font-size: 16px;

    font-weight: 900;
}

.subtitle {

    margin-top: 3px;

    font-size: 11px;

    color:
        rgba(255,255,255,.40);
}

.logout {

    padding:
        10px 14px;

    border-radius: 12px;

    border:
        1px solid
        rgba(255,255,255,.08);

    color:
        #fca5a5;

    text-decoration: none;

    background:
        rgba(255,255,255,.03);
}

.grid {

    display: grid;

    grid-template-columns:
        repeat(
            4,
            1fr
        );

    gap: 12px;
}

.stat {

    padding: 18px;

    border-radius: 18px;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);

    backdrop-filter: blur(18px);
}

.stat-label {

    font-size: 11px;

    color:
        rgba(255,255,255,.40);
}

.stat-value {

    margin-top: 8px;

    font-size: 23px;

    font-weight: 900;
}

.panel {

    margin-top: 14px;

    border-radius: 22px;

    overflow: hidden;

    border:
        1px solid
        rgba(255,255,255,.08);

    background:
        rgba(255,255,255,.035);
}

.panel-head {

    padding: 18px 20px;

    border-bottom:
        1px solid
        rgba(255,255,255,.07);

    display: flex;

    justify-content:
        space-between;

    align-items: center;
}

.panel-title {

    font-weight: 800;

    font-size: 14px;
}

.table-wrap {

    overflow-x: auto;
}

table {

    width: 100%;

    border-collapse: collapse;

    min-width: 800px;
}

th,
td {

    padding:
        13px 15px;

    text-align: right;

    border-bottom:
        1px solid
        rgba(255,255,255,.05);

    font-size: 12px;
}

th {

    color:
        rgba(255,255,255,.37);

    font-weight: 600;
}

.badge {

    display: inline-flex;

    align-items: center;

    padding:
        5px 8px;

    border-radius: 999px;

    font-size: 10px;
}

.online {

    color: #86efac;

    background:
        rgba(34,197,94,.08);
}

.offline {

    color: #fca5a5;

    background:
        rgba(239,68,68,.08);
}

.actions {

    display: flex;

    gap: 8px;

    flex-wrap: wrap;
}

.btn {

    border: 0;

    cursor: pointer;

    padding:
        9px 11px;

    border-radius: 10px;

    color: white;

    background:
        rgba(255,255,255,.06);

    font-size: 11px;
}

.btn:hover {

    background:
        rgba(255,255,255,.09);
}

.primary {

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.danger {

    color: #fca5a5;
}

pre {

    white-space: pre-wrap;

    word-break: break-word;
}

@media(max-width:900px) {

    .grid {
        grid-template-columns:
            repeat(
                2,
                1fr
            );
    }
}

@media(max-width:600px) {

    .grid {
        grid-template-columns: 1fr;
    }

    .wrapper {
        width:
            calc(100% - 20px);
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

<div class="title">
PixonPanel
</div>

<div class="subtitle">
داشبورد مدیریت
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

<div
    class="grid"
    id="stats"
>

<div class="stat">
<div class="stat-label">
کانفیگ‌ها
</div>
<div
    class="stat-value"
    id="links"
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
    id="active"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
اتصالات
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
کانفیگ‌ها
</div>

<div class="actions">

<button
    class="btn primary"
    onclick="createLink()"
>
+ ساخت کانفیگ
</button>

</div>

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
عملیات
</th>

</tr>

</thead>

<tbody id="links-table">

</tbody>

</table>

</div>

</div>

<div class="panel">

<div class="panel-head">

<div class="panel-title">
گزارش فعالیت
</div>

</div>

<pre
    id="logs"
    style="
        padding:20px;
        margin:0;
        color:rgba(255,255,255,.55);
        font-size:11px;
    "
>
در حال بارگذاری...
</pre>

</div>

</div>

<script>

async function api(
    url,
    options = {}
) {

    const response = await fetch(
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


async function refresh() {

    const stats =
        await api("/stats");

    if (!stats)
        return;

    document.getElementById(
        "links"
    ).textContent =
        stats.links_count;

    document.getElementById(
        "active"
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

    const tbody =
        document.getElementById(
            "links-table"
        );

    tbody.innerHTML = "";

    for (
        const link
        of data.links
    ) {

        const tr =
            document.createElement(
                "tr"
            );

        tr.innerHTML = `

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
                    ? "online"
                    : "offline"
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

            <div class="actions">

                <button
                    class="btn"
                    onclick='copyText(
                        ${JSON.stringify(
                            link.vless_link
                        )}
                    )'
                >
                    کپی
                </button>

                <button
                    class="btn danger"
                    onclick='removeLink(
                        ${JSON.stringify(
                            link.uuid
                        )}
                    )'
                >
                    حذف
                </button>

            </div>

        </td>
        `;

        tbody.appendChild(
            tr
        );
    }

    const logs =
        await api(
            "/api/activity"
        );

    if (logs) {

        document.getElementById(
            "logs"
        ).textContent =
            logs.logs
                .slice()
                .reverse()
                .map(
                    item =>
                        `[${item.level}] ${item.message}`
                )
                .join("\\n")
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

    const response =
        await api(
            "/api/links",
            {
                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(
                        {
                            label,
                            protocol:
                                "vless-ws",
                            fingerprint:
                                "chrome",
                            port: 443
                        }
                    )
            }
        );

    if (response) {

        await copyText(
            response.vless_link
        );

        alert(
            "کانفیگ ساخته شد و کپی شد."
        );

        refresh();
    }
}


async function removeLink(
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
        encodeURIComponent(uuid),
        {
            method: "DELETE"
        }
    );

    refresh();
}


async function copyText(
    text
) {

    await navigator
        .clipboard
        .writeText(
            text
        );

    alert(
        "کپی شد."
    );
}


function formatBytes(
    value
) {

    if (!value)
        return "0 B";

    if (
        value <
        1024
    ) {

        return value +
            " B";
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
            + " KB"
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


function escapeHtml(
    text
) {

    return String(
        text ?? ""
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
# Error Handling
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
            "error": str(exc),
            "path": str(
                request.url
            ),
            "time": datetime.now().isoformat(),
        }
    )

    logger.exception(
        "Unhandled exception"
    )

    return JSONResponse(
        {
            "ok": False,
            "error": "internal server error",
        },
        status_code=500,
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

# ============================================================
# PixonPanel 12.0.1 Beta
# Railway Ready
# ============================================================

import asyncio
import base64
import hashlib
import html
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

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# APP CONFIG
# ============================================================

APP_NAME = "PixonPanel"
APP_VERSION = "12.0.1 Beta"
SUPPORT_USERNAME = "@Pixonal"
SUPPORT_URL = "https://t.me/Pixonal"
NEWS_URL = "https://raw.githubusercontent.com/pxir029/fuckyoo/refs/heads/main/news.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(APP_NAME)

try:
    from zoneinfo import ZoneInfo
    IRAN_TZ = ZoneInfo("Asia/Tehran")
except Exception:
    IRAN_TZ = None

PORT = int(os.environ.get("PORT", "8000"))
DATA_DIR = Path(os.environ.get("RAILWAY_VOLUME_MOUNT_PATH", os.environ.get("DATA_DIR", "./data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE = DATA_DIR / "pixonpanel_state.json"
SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"

app = FastAPI(title=APP_NAME, version=APP_VERSION, docs_url=None, redoc_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()
NEWS_LOCK = asyncio.Lock()

LINKS = {}
SUBS = {}
SESSIONS = {}
connections = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs = deque(maxlen=100)
activity_logs = deque(maxlen=250)
hourly_traffic = defaultdict(int)
http_client = None
NEWS_CACHE = {"data": None, "expires_at": 0}

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
)
DEFAULT_PROTOCOL = "vless-ws"
FINGERPRINTS = (
    "chrome", "firefox", "safari", "ios", "android", "edge",
    "360", "qq", "random", "randomized",
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

def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })


def safe_int(value, default=0, minimum=0, maximum=None):
    try:
        n = int(value)
    except Exception:
        n = default
    n = max(minimum, n)
    if maximum is not None:
        n = min(maximum, n)
    return n


def safe_float(value, default=0.0, minimum=0.0):
    try:
        n = float(value)
    except Exception:
        n = default
    return max(minimum, n)


def escape_html(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def hash_password(password: str):
    return hashlib.sha256((password + SECRET_KEY).encode("utf-8")).hexdigest()


def load_or_create_secret():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    try:
        if SECRET_FILE.exists():
            value = SECRET_FILE.read_text(encoding="utf-8").strip()
            if value:
                return value
        value = secrets.token_urlsafe(48)
        SECRET_FILE.write_text(value, encoding="utf-8")
        return value
    except Exception as exc:
        logger.warning("Could not persist SECRET_KEY: %s", exc)
        return secrets.token_urlsafe(48)


SECRET_KEY = load_or_create_secret()
CONFIG = {
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
    "port": PORT,
}

DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "pxpanel2026")
AUTH = {"password_hash": hash_password(DEFAULT_ADMIN_PASSWORD)}
SESSION_COOKIE = "pixonpanel_session"
SESSION_TTL = 60 * 60 * 24 * 365


def generate_uuid():
    value = secrets.token_hex(16)
    return f"{value[:8]}-{value[8:12]}-{value[12:16]}-{value[16:20]}-{value[20:32]}"


def auto_config_name():
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "pxpanel_" + "".join(secrets.choice(alphabet) for _ in range(8))


def now_ir():
    return datetime.now(IRAN_TZ) if IRAN_TZ else datetime.now()


def uptime():
    total = int(time.time() - stats["start_time"])
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def fmt_bytes(value):
    value = int(value or 0)
    if value < 1024:
        return f"{value} B"
    if value < 1024**2:
        return f"{value / 1024:.1f} KB"
    if value < 1024**3:
        return f"{value / 1024**2:.2f} MB"
    return f"{value / 1024**3:.2f} GB"


def parse_size_to_bytes(value, unit):
    value = safe_float(value)
    if value <= 0:
        return 0
    unit = str(unit or "GB").upper()
    mult = {"KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}.get(unit, 1)
    return int(value * mult)


def parse_speed_to_bytes(value, unit):
    value = safe_float(value)
    if value <= 0:
        return 0
    unit = str(unit or "MBIT").upper()
    if unit == "MBIT":
        return int(value * 1024 * 1024 / 8)
    if unit == "MB":
        return int(value * 1024 * 1024)
    if unit == "KB":
        return int(value * 1024)
    return int(value)


def is_link_expired(link):
    expiry = link.get("expires_at")
    if not expiry:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(expiry)
    except Exception:
        return False


def is_link_allowed(link):
    if not link or not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    limit = int(link.get("limit_bytes", 0) or 0)
    used = int(link.get("used_bytes", 0) or 0)
    return not (limit > 0 and used >= limit)


def unique_ips_for_uuid(uuid):
    return {
        c.get("ip")
        for c in connections.values()
        if c.get("uuid") == uuid and c.get("ip")
    }


def client_ip(request: Request):
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real = request.headers.get("x-real-ip")
    if real:
        return real.strip()
    return request.client.host if request.client else "unknown"


def is_ip_allowed(link, uuid, ip):
    if not link:
        return False
    limit = int(link.get("ip_limit", 0) or 0)
    if limit <= 0:
        return True
    ips = unique_ips_for_uuid(uuid)
    return ip in ips or len(ips) < limit


def get_host(request=None):
    if request is not None:
        host = request.headers.get("x-forwarded-host") or request.headers.get("host")
        if host:
            host = host.split(":")[0].strip()
            CONFIG["host"] = host
            return host
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN") or CONFIG["host"]


# ============================================================
# VLESS GENERATOR - KEEP WORKING CORE
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
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT
    alpn_value = (alpn or "").strip() or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    port_value = port or DEFAULT_PORT
    if not MIN_PORT <= port_value <= MAX_PORT:
        port_value = DEFAULT_PORT

    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
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
        mode = protocol.replace("xhttp-", "")
        path = f"/xhttp-siz10/{mode}/{uuid}"
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

    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:{port_value}?{query}#{quote(remark)}"


def vless_link_for_link(link, uid, host):
    return generate_vless_link(
        uid,
        host,
        remark=f"PixonPanel-{link.get('label', '')}",
        protocol=link.get("protocol", DEFAULT_PROTOCOL),
        fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT),
        alpn=link.get("alpn"),
        port=link.get("port", DEFAULT_PORT),
    )


def build_link_info(link, uid, host):
    return {
        "uuid": uid,
        "name": link.get("label", ""),
        "label": link.get("label", ""),
        "protocol": link.get("protocol", DEFAULT_PROTOCOL),
        "active": is_link_allowed(link),
        "used_bytes": int(link.get("used_bytes", 0) or 0),
        "limit_bytes": int(link.get("limit_bytes", 0) or 0),
        "expires_at": link.get("expires_at"),
        "ip_limit": int(link.get("ip_limit", 0) or 0),
        "speed_limit_bytes": int(link.get("speed_limit_bytes", 0) or 0),
        "connection_limit": int(link.get("connection_limit", 0) or 0),
        "fragment": link.get("fragment", "off"),
        "fingerprint": link.get("fingerprint", DEFAULT_FINGERPRINT),
        "alpn": link.get("alpn", "http/1.1"),
        "port": link.get("port", DEFAULT_PORT),
        "note": link.get("note", ""),
        "notice": link.get("notice", ""),
        "vless": vless_link_for_link(link, uid, host),
        "sub": f"https://{host}/sub/{uid}",
        "info": f"https://{host}/info/{uid}",
        "support": SUPPORT_USERNAME,
    }


# ============================================================
# PERSISTENCE
# ============================================================

async def load_state():
    if not DATA_FILE.exists():
        return
    try:
        async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
            raw = await f.read()
        data = json.loads(raw)
        LINKS.update(data.get("links", {}))
        SUBS.update(data.get("subs", {}))
        if data.get("password_hash"):
            AUTH["password_hash"] = data["password_hash"]

        for link in LINKS.values():
            link.setdefault("protocol", DEFAULT_PROTOCOL)
            link.setdefault("fingerprint", DEFAULT_FINGERPRINT)
            link.setdefault("alpn", "http/1.1")
            link.setdefault("port", DEFAULT_PORT)
            link.setdefault("ip_limit", 0)
            link.setdefault("speed_limit_bytes", 0)
            link.setdefault("connection_limit", 0)
            link.setdefault("fragment", "off")
            link.setdefault("notice", "")
            link.setdefault("used_bytes", 0)
    except Exception as exc:
        logger.exception("Could not load state: %s", exc)


async def save_state():
    async with SAVE_LOCK:
        try:
            payload = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "password_hash": AUTH["password_hash"],
                "saved_at": datetime.now().isoformat(),
            }
            temp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(temp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(payload, ensure_ascii=False, indent=2))
            temp.replace(DATA_FILE)
        except Exception as exc:
            logger.exception("Could not save state: %s", exc)


# ============================================================
# SESSIONS
# ============================================================

async def create_session():
    token = secrets.token_urlsafe(48)
    async with SESSIONS_LOCK:
        SESSIONS[token] = time.time() + SESSION_TTL
    return token


async def is_valid_session(token):
    if not token:
        return False
    async with SESSIONS_LOCK:
        expiry = SESSIONS.get(token)
        if expiry is None:
            return False
        if expiry < time.time():
            SESSIONS.pop(token, None)
            return False
        return True


async def destroy_session(token):
    if token:
        async with SESSIONS_LOCK:
            SESSIONS.pop(token, None)


async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not await is_valid_session(token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return token


def set_auth_cookie(response, request, token):
    forwarded = request.headers.get("x-forwarded-proto", "").lower()
    secure = forwarded == "https" or request.url.scheme == "https"
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        secure=secure,
        path="/",
    )


# ============================================================
# LINK MANAGEMENT
# ============================================================

async def make_link(
    label="لینک جدید",
    limit_bytes=0,
    expires_at=None,
    note="",
    notice="",
    sub_id=None,
    protocol=DEFAULT_PROTOCOL,
    fingerprint=DEFAULT_FINGERPRINT,
    alpn="http/1.1",
    port=DEFAULT_PORT,
    ip_limit=0,
    speed_limit_bytes=0,
    connection_limit=0,
    fragment="off",
):
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL
    fingerprint = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT
    if not MIN_PORT <= port <= MAX_PORT:
        port = DEFAULT_PORT
    if fragment not in {"off", "safe", "balanced", "aggressive"}:
        fragment = "off"

    uid = generate_uuid()
    record = {
        "label": (label or "لینک جدید").strip()[:60],
        "limit_bytes": max(0, int(limit_bytes)),
        "used_bytes": 0,
        "created_at": datetime.now().isoformat(),
        "active": True,
        "expires_at": expires_at,
        "note": (note or "").strip()[:500],
        "notice": (notice or "").strip()[:2000],
        "is_default": False,
        "sub_id": sub_id,
        "protocol": protocol,
        "fingerprint": fingerprint,
        "alpn": (alpn or "http/1.1").strip()[:100],
        "port": port,
        "ip_limit": max(0, int(ip_limit)),
        "speed_limit_bytes": max(0, int(speed_limit_bytes)),
        "connection_limit": max(0, int(connection_limit)),
        "fragment": fragment,
    }
    async with LINKS_LOCK:
        LINKS[uid] = record
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)
    await save_state()
    log_activity("link", f"کانفیگ «{record['label']}» ساخته شد", "ok")
    return uid, record


async def remove_link(uid):
    async with LINKS_LOCK:
        if uid not in LINKS:
            return None
        label = LINKS[uid].get("label", uid)
        sub_id = LINKS[uid].get("sub_id")
        del LINKS[uid]
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
    await save_state()
    log_activity("link", f"کانفیگ «{label}» حذف شد", "warn")
    return label


async def set_link_active(uid, active):
    async with LINKS_LOCK:
        if uid not in LINKS:
            return None
        LINKS[uid]["active"] = bool(active)
        record = dict(LINKS[uid])
    await save_state()
    log_activity("link", f"کانفیگ «{record['label']}» {'فعال' if active else 'غیرفعال'} شد", "ok")
    return record


# ============================================================
# DEFAULT LINK
# ============================================================

_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(x.get("is_default") for x in LINKS.values()):
            digest = hashlib.sha256(("default" + SECRET_KEY).encode()).hexdigest()
            uid = f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"
            LINKS[uid] = {
                "label": "لینک پیش‌فرض",
                "limit_bytes": 0,
                "used_bytes": 0,
                "created_at": datetime.now().isoformat(),
                "active": True,
                "expires_at": None,
                "note": "",
                "notice": "",
                "is_default": True,
                "sub_id": None,
                "protocol": DEFAULT_PROTOCOL,
                "fingerprint": DEFAULT_FINGERPRINT,
                "alpn": "http/1.1",
                "port": 443,
                "ip_limit": 0,
                "speed_limit_bytes": 0,
                "connection_limit": 0,
                "fragment": "off",
            }
    _default_link_created = True
    await save_state()


# ============================================================
# NEWS
# ============================================================

async def fetch_news():
    now = time.time()
    async with NEWS_LOCK:
        if NEWS_CACHE["data"] is not None and NEWS_CACHE["expires_at"] > now:
            return NEWS_CACHE["data"]
        fallback = {
            "enabled": False,
            "title": "اطلاعیه مهم",
            "message": "",
            "updated_at": None,
        }
        if http_client is None:
            return fallback
        try:
            response = await http_client.get(
                NEWS_URL,
                headers={"User-Agent": "PixonPanel/12.0.1", "Cache-Control": "no-cache"},
            )
            response.raise_for_status()
            raw = response.json()
            if isinstance(raw, list):
                raw = {"items": raw}
            if not isinstance(raw, dict):
                raw = {}
            enabled = raw.get("enabled", raw.get("active", raw.get("show", raw.get("visible", True))))
            title = raw.get("title") or raw.get("name") or "اطلاعیه مهم"
            message = raw.get("message") or raw.get("text") or raw.get("description") or raw.get("content") or ""
            nested = raw.get("news") or raw.get("notice")
            if isinstance(nested, dict):
                enabled = nested.get("enabled", enabled)
                title = nested.get("title") or title
                message = message or nested.get("message") or nested.get("text") or nested.get("description") or nested.get("content") or ""
            items = raw.get("items")
            if not message and isinstance(items, list) and items:
                first = items[0]
                if isinstance(first, dict):
                    enabled = first.get("enabled", enabled)
                    title = first.get("title") or title
                    message = first.get("message") or first.get("text") or first.get("description") or first.get("content") or ""
                elif isinstance(first, str):
                    message = first
            data = {
                "enabled": bool(enabled),
                "title": str(title),
                "message": str(message),
                "updated_at": raw.get("updated_at") or raw.get("updatedAt"),
            }
            NEWS_CACHE["data"] = data
            NEWS_CACHE["expires_at"] = now + 60
            return data
        except Exception as exc:
            logger.warning("News fetch failed: %s", exc)
            if NEWS_CACHE.get("data"):
                return NEWS_CACHE["data"]
            return fallback


@app.get("/api/news")
async def api_news():
    return await fetch_news()


# ============================================================
# STARTUP / SHUTDOWN
# ============================================================

@app.on_event("startup")
async def startup():
    global http_client
    http_client = httpx.AsyncClient(
        limits=httpx.Limits(max_connections=500, max_keepalive_connections=100),
        timeout=httpx.Timeout(20.0, connect=8.0),
        follow_redirects=True,
    )
    await load_state()
    await ensure_default_link()
    log_activity("system", f"{APP_NAME} v{APP_VERSION} راه‌اندازی شد", "ok")
    logger.info("%s v%s started on 0.0.0.0:%s", APP_NAME, APP_VERSION, PORT)


@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()


# ============================================================
# LOGIN
# ============================================================

LOGIN_HTML = r"""
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PixonPanel Login</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-[#07070a] text-white flex items-center justify-center p-4">
<div class="w-full max-w-md rounded-md border border-white/10 bg-white/[.045] backdrop-blur-2xl p-6">
<div class="w-11 h-11 rounded-md flex items-center justify-center bg-gradient-to-br from-indigo-500 to-violet-500 font-black">P</div>
<h1 class="mt-5 text-2xl font-black">ورود به PixonPanel</h1>
<div class="mt-1 text-[11px] text-violet-300">12.0.1 Beta</div>
<p class="mt-2 text-xs text-white/45 leading-7">رمز عبور پنل مدیریت را وارد کنید.</p>
<form method="post" action="/login" class="mt-5">
<label class="block text-[11px] text-white/45 mb-2">رمز عبور</label>
<input name="password" type="password" autofocus autocomplete="current-password" class="w-full rounded-md border border-white/10 bg-black/20 px-3 py-3 outline-none focus:border-indigo-400/60" placeholder="رمز عبور">
<button class="mt-3 w-full rounded-md py-3 bg-gradient-to-br from-indigo-500 to-violet-500 font-bold text-sm">ورود</button>
</form>
<a href="https://t.me/Pixonal" target="_blank" class="block text-center mt-4 text-violet-300 text-[10px]">پشتیبانی @Pixonal</a>
</div>
</body></html>
"""


def login_error_html(message):
    return LOGIN_HTML.replace(
        "</form>",
        f'<div class="mt-3 rounded-md border border-red-400/20 bg-red-500/10 text-red-300 text-[10px] p-3">{escape_html(message)}</div></form>',
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/dashboard")
    return HTMLResponse(LOGIN_HTML)


@app.post("/login")
async def login_form(request: Request):
    try:
        ct = request.headers.get("content-type", "").lower()
        if "application/json" in ct:
            body = await request.json()
            password = str(body.get("password", "")).strip()
        else:
            raw = await request.body()
            parsed = parse_qs(raw.decode("utf-8", errors="ignore"))
            password = parsed.get("password", [""])[0].strip()
    except Exception:
        return HTMLResponse(login_error_html("خطا در پردازش ورود."), status_code=400)

    if hash_password(password) != AUTH["password_hash"]:
        log_activity("auth", f"تلاش ورود ناموفق از {client_ip(request)}", "err")
        return HTMLResponse(login_error_html("رمز عبور اشتباه است."), status_code=401)

    token = await create_session()
    response = RedirectResponse("/dashboard", status_code=303)
    set_auth_cookie(response, request, token)
    log_activity("auth", f"ورود موفق از {client_ip(request)}", "ok")
    return response


@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    response = JSONResponse({"ok": True, "authenticated": True})
    set_auth_cookie(response, request, token)
    return response


@app.get("/logout")
async def logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse("/login")
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/api/me")
async def api_me(request: Request):
    return {"authenticated": await is_valid_session(request.cookies.get(SESSION_COOKIE))}


@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    response = JSONResponse({"ok": True})
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.post("/api/change-password")
async def change_password(request: Request, token=Depends(require_auth)):
    body = await request.json()
    current = str(body.get("current_password", ""))
    new = str(body.get("new_password", ""))
    repeat = str(body.get("repeat_password", ""))
    if hash_password(current) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    if len(new) < 6:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۶ کاراکتر باشد")
    if new != repeat:
        raise HTTPException(status_code=400, detail="تکرار رمز یکسان نیست")
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        SESSIONS.clear()
        SESSIONS[token] = time.time() + SESSION_TTL
    await save_state()
    return {"ok": True}


# ============================================================
# LINK API
# ============================================================

@app.post("/api/links")
async def create_link_api(request: Request, _=Depends(require_auth)):
    body = await request.json()
    limit = parse_size_to_bytes(body.get("limit_value", 0), body.get("limit_unit", "GB"))
    days = safe_int(body.get("expires_days", 0), minimum=0)
    expires = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    speed = parse_speed_to_bytes(body.get("speed_limit_value", 0), body.get("speed_limit_unit", "MBIT"))
    uid, link = await make_link(
        label=body.get("label") or auto_config_name(),
        limit_bytes=limit,
        expires_at=expires,
        note=body.get("note", ""),
        notice=body.get("notice", ""),
        sub_id=body.get("sub_id"),
        protocol=body.get("protocol", DEFAULT_PROTOCOL),
        fingerprint=body.get("fingerprint", DEFAULT_FINGERPRINT),
        alpn=body.get("alpn", "http/1.1"),
        port=safe_int(body.get("port", 443), 443, 1, 65535),
        ip_limit=safe_int(body.get("ip_limit", 0), 0, 0),
        speed_limit_bytes=speed,
        connection_limit=safe_int(body.get("connection_limit", 0), 0, 0),
        fragment=body.get("fragment", "off"),
    )
    host = get_host(request)
    return {"ok": True, **build_link_info(link, uid, host)}


@app.post("/api/links/auto")
async def create_auto_link(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    uid, link = await make_link(
        label=auto_config_name(),
        limit_bytes=0,
        expires_at=None,
        note="Auto generated by PixonPanel",
        notice="",
        protocol="vless-ws",
        fingerprint="chrome",
        alpn="http/1.1",
        port=443,
        ip_limit=0,
        speed_limit_bytes=0,
        connection_limit=0,
        fragment="off",
    )
    return {"ok": True, **build_link_info(link, uid, host)}


@app.get("/api/links")
async def list_links(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    async with LINKS_LOCK:
        snapshot = dict(LINKS)
    out = []
    for uid, link in snapshot.items():
        item = build_link_info(link, uid, host)
        item["created_at"] = link.get("created_at")
        item["expired"] = is_link_expired(link)
        item["connected_ips"] = len(unique_ips_for_uuid(uid))
        out.append(item)
    out.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return {"links": out}


@app.get("/api/links/{uid}/info")
async def link_info_api(uid: str, request: Request, _=Depends(require_auth)):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="link not found")
        snapshot = dict(link)
    return {"ok": True, **build_link_info(snapshot, uid, get_host(request))}


@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        old_sub = link.get("sub_id")
        if "label" in body and str(body.get("label", "")).strip():
            link["label"] = str(body["label"]).strip()[:60]
        if "active" in body:
            link["active"] = bool(body["active"])
        if "note" in body:
            link["note"] = str(body.get("note", ""))[:500]
        if "notice" in body:
            link["notice"] = str(body.get("notice", ""))[:2000]
        if "limit_value" in body:
            link["limit_bytes"] = parse_size_to_bytes(body.get("limit_value", 0), body.get("limit_unit", "GB"))
        if "expires_days" in body:
            days = safe_int(body.get("expires_days", 0), minimum=0)
            link["expires_at"] = (datetime.now() + timedelta(days=days)).isoformat() if days else None
        if "protocol" in body and body["protocol"] in PROTOCOLS:
            link["protocol"] = body["protocol"]
        if "fingerprint" in body and body["fingerprint"] in FINGERPRINTS:
            link["fingerprint"] = body["fingerprint"]
        if "alpn" in body:
            link["alpn"] = str(body.get("alpn", "http/1.1"))[:100]
        if "port" in body:
            link["port"] = safe_int(body.get("port", 443), 443, 1, 65535)
        if "ip_limit" in body:
            link["ip_limit"] = safe_int(body.get("ip_limit", 0), 0, 0)
        if "connection_limit" in body:
            link["connection_limit"] = safe_int(body.get("connection_limit", 0), 0, 0)
        if "speed_limit_value" in body:
            link["speed_limit_bytes"] = parse_speed_to_bytes(body.get("speed_limit_value", 0), body.get("speed_limit_unit", "MBIT"))
        if "fragment" in body and body["fragment"] in {"off", "safe", "balanced", "aggressive"}:
            link["fragment"] = body["fragment"]
        if body.get("reset_usage"):
            link["used_bytes"] = 0
        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None
    if new_sub != "UNCHANGED":
        await set_link_sub(uid, new_sub or None)
    await save_state()
    return {"ok": True}


@app.post("/api/links/{uid}/reset-usage")
async def reset_usage(uid: str, _=Depends(require_auth)):
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        LINKS[uid]["used_bytes"] = 0
    await save_state()
    return {"ok": True, "used_bytes": 0}


@app.delete("/api/links/{uid}")
async def delete_link(uid: str, _=Depends(require_auth)):
    deleted = await remove_link(uid)
    if deleted is None:
        raise HTTPException(status_code=404, detail="link not found")
    return {"ok": True, "deleted": uid}


# ============================================================
# SUB HELPERS/API
# ============================================================

async def set_link_sub(uid, sub_id):
    async with LINKS_LOCK:
        if uid not in LINKS:
            return False
        old_sub = LINKS[uid].get("sub_id")
    if sub_id is not None:
        async with SUBS_LOCK:
            if sub_id not in SUBS:
                return False
    async with SUBS_LOCK:
        if old_sub and old_sub in SUBS:
            ids = SUBS[old_sub].get("link_ids", [])
            if uid in ids:
                ids.remove(uid)
        if sub_id and sub_id in SUBS:
            ids = SUBS[sub_id].setdefault("link_ids", [])
            if uid not in ids:
                ids.append(uid)
    return True


@app.post("/api/subs")
async def create_sub_api(request: Request, _=Depends(require_auth)):
    body = await request.json()
    sid = generate_uuid()
    key = secrets.token_urlsafe(16)
    sub = {
        "name": str(body.get("name") or "گروه جدید")[:60],
        "desc": str(body.get("desc") or "")[:200],
        "password_hash": hash_password(str(body.get("password"))) if body.get("password") else None,
        "uuid_key": key,
        "created_at": datetime.now().isoformat(),
        "link_ids": [],
    }
    async with SUBS_LOCK:
        SUBS[sid] = sub
    await save_state()
    host = get_host(request)
    return {
        "sub_id": sid,
        "name": sub["name"],
        "desc": sub["desc"],
        "has_password": bool(sub["password_hash"]),
        "public_url": f"https://{host}/p/{key}",
        "sub_url": f"https://{host}/sub-group/{key}",
        "link_ids": [],
    }


@app.get("/api/subs")
async def list_subs_api(request: Request, _=Depends(require_auth)):
    host = get_host(request)
    async with SUBS_LOCK:
        subs = dict(SUBS)
    async with LINKS_LOCK:
        links = dict(LINKS)
    result = []
    for sid, sub in subs.items():
        ids = sub.get("link_ids", [])
        used = sum(int(links[x].get("used_bytes", 0) or 0) for x in ids if x in links)
        result.append({
            "sub_id": sid,
            "name": sub.get("name", sid),
            "desc": sub.get("desc", ""),
            "has_password": bool(sub.get("password_hash")),
            "link_ids": ids,
            "links_count": len(ids),
            "total_used_bytes": used,
            "total_used_fmt": fmt_bytes(used),
            "public_url": f"https://{host}/p/{sub.get('uuid_key')}",
            "sub_url": f"https://{host}/sub-group/{sub.get('uuid_key')}",
        })
    return {"subs": result}


@app.patch("/api/subs/{sub_id}")
async def update_sub_api(sub_id: str, request: Request, _=Depends(require_auth)):
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        sub = SUBS[sub_id]
        if "name" in body:
            sub["name"] = str(body.get("name", ""))[:60]
        if "desc" in body:
            sub["desc"] = str(body.get("desc", ""))[:200]
        if "password" in body:
            p = str(body.get("password", ""))
            sub["password_hash"] = hash_password(p) if p else None
        if "link_ids" in body:
            sub["link_ids"] = list(body.get("link_ids") or [])
    await save_state()
    return {"ok": True}


@app.delete("/api/subs/{sub_id}")
async def delete_sub_api(sub_id: str, _=Depends(require_auth)):
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    await save_state()
    return {"ok": True, "deleted": sub_id}


@app.get("/sub/{uuid}")
async def subscription_single(uuid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")
    host = get_host(request)
    line = vless_link_for_link(link, uuid, host)
    content = base64.b64encode(line.encode()).decode()
    return Response(content, media_type="text/plain", headers={
        "profile-title": quote(link.get("label", APP_NAME)),
        "support-url": SUPPORT_URL,
        "profile-update-interval": "12",
    })


@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    async with SUBS_LOCK:
        sub = next((x for x in SUBS.values() if x.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")
    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="wrong password")
    host = get_host(request)
    async with LINKS_LOCK:
        lines = [vless_link_for_link(LINKS[x], x, host) for x in sub.get("link_ids", []) if x in LINKS and is_link_allowed(LINKS[x])]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content, media_type="text/plain", headers={
        "profile-title": quote(sub.get("name", APP_NAME)),
        "support-url": SUPPORT_URL,
        "profile-update-interval": "12",
    })


# ============================================================
# INFO PAGE
# ============================================================

@app.get("/info/{uid}", response_class=HTMLResponse)
async def info_page(uid: str, request: Request):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            raise HTTPException(status_code=404, detail="not found")
        snapshot = dict(link)
    host = get_host(request)
    custom = snapshot.get("notice", "").strip()
    news = await fetch_news()
    custom_html = ""
    if custom:
        custom_html = f'''<div class="rounded-md border border-violet-400/15 bg-violet-500/[.06] p-3 mt-3"><div class="font-bold text-xs">اطلاعیه این کانفیگ</div><div class="mt-2 text-[11px] text-white/60 leading-7">{escape_html(custom).replace(chr(10), "<br>")}</div></div>'''
    system_html = ""
    if news.get("enabled") and news.get("message"):
        system_html = f'''<div class="rounded-md border border-indigo-400/15 bg-indigo-500/[.06] p-3 mt-3"><div class="font-bold text-xs">{escape_html(news.get("title", "اطلاعیه مهم"))}</div><div class="mt-2 text-[11px] text-white/60 leading-7">{escape_html(news.get("message", "")).replace(chr(10), "<br>")}</div></div>'''
    def row(label, value):
        return f'''<div class="rounded-md border border-white/5 bg-white/[.025] p-3 mt-2"><div class="text-[9px] text-white/30 mb-1">{label}</div><div class="text-[9px] font-mono break-all text-violet-200" dir="ltr">{escape_html(value)}</div></div>'''
    html_page = f'''<!doctype html><html lang="fa" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><script src="https://cdn.tailwindcss.com"></script><title>PixonPanel INFO</title></head><body class="min-h-screen bg-[#07070a] text-white flex items-center justify-center p-4"><main class="w-full max-w-2xl rounded-md border border-white/10 bg-white/[.045] backdrop-blur-2xl p-4"><div class="flex items-center gap-3"><div class="w-10 h-10 rounded-md flex items-center justify-center bg-gradient-to-br from-indigo-500 to-violet-500 font-black">P</div><div><div class="font-black">{escape_html(snapshot.get("label", APP_NAME))}</div><div class="text-[9px] text-violet-300 mt-1">PixonPanel · {APP_VERSION}</div></div></div>{custom_html}{system_html}{row("UUID", uid)}{row("VLESS", vless_link_for_link(snapshot, uid, host))}{row("SUB", f"https://{host}/sub/{uid}")}{row("حجم", "Unlimited" if not snapshot.get("limit_bytes") else fmt_bytes(snapshot.get("limit_bytes")))}{row("زمان", "Unlimited" if not snapshot.get("expires_at") else snapshot.get("expires_at"))}{row("IP Limit", "Unlimited" if not snapshot.get("ip_limit") else snapshot.get("ip_limit"))}{row("Connection Limit", "Unlimited" if not snapshot.get("connection_limit") else snapshot.get("connection_limit"))}{row("Speed", "Unlimited" if not snapshot.get("speed_limit_bytes") else fmt_bytes(snapshot.get("speed_limit_bytes"))+"/s")}{row("Fingerprint", snapshot.get("fingerprint", "chrome"))}<div class="mt-3 text-[10px] text-violet-300">پشتیبانی {SUPPORT_USERNAME}</div></main></body></html>'''
    return HTMLResponse(html_page)


# ============================================================
# STATS / ACTIVITY
# ============================================================

@app.get("/stats")
async def stats_api(_=Depends(require_auth)):
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {
        "service": APP_NAME,
        "version": APP_VERSION,
        "active_connections": len(connections),
        "total_traffic_bytes": stats["total_bytes"],
        "total_traffic_mb": round(stats["total_bytes"] / 1024**2, 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "links_count": len(snap),
        "active_links": sum(1 for x in snap.values() if is_link_allowed(x)),
        "expired_links": sum(1 for x in snap.values() if is_link_expired(x)),
        "subs_count": len(SUBS),
    }


@app.get("/api/activity")
async def activity_api(_=Depends(require_auth)):
    return {"logs": list(activity_logs)[-150:]}


@app.get("/api/connections")
async def connections_api(_=Depends(require_auth)):
    return {"connections": list(connections.values()), "count": len(connections), "raw_count": len(connections)}


# ============================================================
# HTTP PROXY
# ============================================================

_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers", "transfer-encoding", "upgrade", "content-encoding", "content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    if http_client is None:
        raise HTTPException(status_code=503, detail="HTTP client not ready")
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        response = await http_client.request(request.method, target_url, headers=headers, content=body)
        stats["total_bytes"] += len(response.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(response.content)
        out = {k: v for k, v in response.headers.items() if k.lower() not in _HOP}
        return Response(response.content, status_code=response.status_code, headers=out)
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")


# ============================================================
# REAL VLESS RELAY - SAME IMPORT / SAME ROUTE
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
    app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)
    logger.info("VLESS relay loaded.")
except Exception as exc:
    logger.exception("VLESS relay module unavailable: %s", exc)


try:
    from xhttp_siz10 import router as xhttp_router
    app.include_router(xhttp_router)
    logger.info("XHTTP module loaded.")
except Exception as exc:
    logger.warning("XHTTP module unavailable: %s", exc)


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = r'''
<!doctype html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PixonPanel</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
body{font-family:Arial,sans-serif}.scrollbar::-webkit-scrollbar{height:5px;width:5px}.scrollbar::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:999px}
</style>
</head>
<body class="min-h-screen bg-[#07070a] text-white">
<div class="max-w-[1350px] mx-auto p-3 sm:p-5">

<header class="flex flex-col lg:flex-row gap-3 items-start lg:items-center justify-between mb-3">
<div class="flex items-center gap-3">
<div class="w-11 h-11 rounded-md bg-gradient-to-br from-indigo-500 to-violet-500 flex items-center justify-center font-black">P</div>
<div><div class="font-black">PixonPanel</div><div class="text-[9px] text-violet-300">12.0.1 Beta</div></div>
</div>
<div class="flex flex-wrap gap-2">
<button id="autoBtn" class="rounded-md px-3 py-2 text-[10px] bg-gradient-to-br from-indigo-500 to-violet-500">+ ساخت خودکار</button>
<button id="manualBtn" class="rounded-md px-3 py-2 text-[10px] border border-white/10 bg-white/[.035]">+ ساخت دستی</button>
<button id="newsBtn" class="rounded-md px-3 py-2 text-[10px] border border-white/10 bg-white/[.035]">اطلاعیه</button>
<button id="passBtn" class="rounded-md px-3 py-2 text-[10px] border border-white/10 bg-white/[.035]">تغییر رمز</button>
<a href="/logout" class="rounded-md px-3 py-2 text-[10px] border border-red-400/10 text-red-300 bg-white/[.035]">خروج</a>
</div>
</header>

<section class="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
<div class="rounded-md border border-white/5 bg-white/[.03] p-3"><div class="text-[8px] text-white/30">کانفیگ</div><div id="sLinks" class="mt-2 text-xl font-black">-</div></div>
<div class="rounded-md border border-white/5 bg-white/[.03] p-3"><div class="text-[8px] text-white/30">فعال</div><div id="sActive" class="mt-2 text-xl font-black">-</div></div>
<div class="rounded-md border border-white/5 bg-white/[.03] p-3"><div class="text-[8px] text-white/30">اتصال</div><div id="sConn" class="mt-2 text-xl font-black">-</div></div>
<div class="rounded-md border border-white/5 bg-white/[.03] p-3"><div class="text-[8px] text-white/30">Traffic</div><div id="sTraffic" class="mt-2 text-xl font-black">-</div></div>
<div class="rounded-md border border-white/5 bg-white/[.03] p-3"><div class="text-[8px] text-white/30">Requests</div><div id="sReq" class="mt-2 text-xl font-black">-</div></div>
<div class="rounded-md border border-white/5 bg-white/[.03] p-3"><div class="text-[8px] text-white/30">Uptime</div><div id="sUp" class="mt-2 text-xl font-black">-</div></div>
</section>

<section class="mt-2 rounded-md overflow-hidden border border-white/5 bg-white/[.03]">
<div class="p-3 flex items-center justify-between border-b border-white/5"><div><div class="font-bold text-xs">مدیریت کانفیگ‌ها</div><div class="text-[8px] text-white/25 mt-1">VLESS · SUB · INFO · EDIT · RESET</div></div><button id="refreshBtn" class="rounded-md px-2.5 py-2 text-[9px] border border-white/10 bg-white/[.035]">↻</button></div>
<div class="overflow-auto scrollbar"><table class="w-full min-w-[1200px] text-[8px]"><thead class="text-white/25"><tr class="border-b border-white/5"><th class="text-right p-2">نام</th><th class="text-right p-2">پروتکل</th><th class="text-right p-2">وضعیت</th><th class="text-right p-2">مصرف</th><th class="text-right p-2">زمان</th><th class="text-right p-2">IP</th><th class="text-right p-2">VLESS</th><th class="text-right p-2">عملیات</th></tr></thead><tbody id="rows"></tbody></table></div>
</section>

<section class="mt-2 rounded-md overflow-hidden border border-white/5 bg-white/[.03]">
<div class="p-3 border-b border-white/5 font-bold text-xs">آخرین فعالیت‌ها</div>
<pre id="logs" class="m-0 p-3 min-h-24 max-h-64 overflow-auto text-[8px] text-white/40 whitespace-pre-wrap"></pre>
</section>

<section class="mt-2 rounded-md overflow-hidden border border-white/5 bg-white/[.03]">
<div class="p-3 border-b border-white/5"><div class="font-bold text-xs">برنامه‌های اتصال</div><div class="text-[8px] text-white/25 mt-1">Android · iPhone · iPad · Windows</div></div>
<div class="grid grid-cols-2 md:grid-cols-3 gap-2 p-3">
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://play.google.com/store/apps/details?id=com.happproxy" target="_blank">Happ Android</a>
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://dl.v2rayng.org/releases/latest/v2rayNG_2.2.6_arm64-v8a.apk" target="_blank">v2rayNG</a>
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box" target="_blank">V2Box Android</a>
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://apps.apple.com/app/happ-proxy-utility/id6504287215" target="_blank">Happ iPhone / iPad</a>
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://apps.apple.com/app/v2box-v2ray-client/id6446814690" target="_blank">V2Box iPhone / iPad</a>
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://apps.apple.com/app/streisand/id6450534064" target="_blank">Streisand</a>
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://apps.apple.com/app/foxray/id6448898396" target="_blank">FoXray</a>
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://github.com/2dust/v2rayN/releases/latest" target="_blank">v2rayN Windows</a>
<a class="rounded-md border border-white/5 bg-white/[.025] p-3 text-[9px]" href="https://happ-proxy.com/" target="_blank">Happ Windows</a>
</div>
<div class="mx-3 mb-3 rounded-md border border-indigo-400/10 bg-indigo-500/[.05] p-3 text-[9px] leading-7 text-white/55"><b class="text-violet-200">آپدیت برنامه اتصال</b><br>برای بهترین سازگاری و پایداری، برنامه اتصال خود را همیشه به آخرین نسخه بروزرسانی کنید.</div>
</section>

<!-- Manual modal -->
<div id="manualModal" class="fixed inset-0 z-50 hidden items-center justify-center p-3 bg-black/70 backdrop-blur-md">
<div class="w-full max-w-3xl max-h-[92vh] overflow-auto rounded-md border border-white/10 bg-[#0e0e14] p-4">
<div class="flex items-center justify-between mb-3"><b id="modalTitle" class="text-xs">ساخت کانفیگ</b><button id="manualClose" class="rounded-md w-8 h-8 bg-white/5">×</button></div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
<div><label class="field-label">نام</label><input id="fName" class="field"></div>
<div><label class="field-label">پروتکل</label><select id="fProtocol" class="field"><option value="vless-ws">VLESS WebSocket</option><option value="xhttp-packet-up">XHTTP Packet Up</option><option value="xhttp-stream-up">XHTTP Stream Up</option><option value="xhttp-stream-one">XHTTP Stream One</option></select></div>
<div><label class="field-label">حجم</label><input id="fVolume" type="number" min="0" placeholder="0 = نامحدود" class="field"></div>
<div><label class="field-label">واحد</label><select id="fVolumeUnit" class="field"><option>GB</option><option>MB</option><option>TB</option></select></div>
<div><label class="field-label">روز</label><input id="fDays" type="number" min="0" placeholder="0 = نامحدود" class="field"></div>
<div><label class="field-label">IP Limit</label><input id="fIp" type="number" min="0" placeholder="0 = نامحدود" class="field"></div>
<div><label class="field-label">Connection Limit</label><input id="fConnLimit" type="number" min="0" placeholder="0 = نامحدود" class="field"></div>
<div><label class="field-label">Speed MBIT</label><input id="fSpeed" type="number" min="0" placeholder="0 = نامحدود" class="field"></div>
<div><label class="field-label">Fingerprint</label><select id="fFingerprint" class="field"><option>chrome</option><option>firefox</option><option>safari</option><option>ios</option><option>android</option><option>edge</option><option>360</option><option>qq</option><option>random</option><option>randomized</option></select></div>
<div><label class="field-label">Fragment</label><select id="fFragment" class="field"><option value="off">خاموش</option><option value="safe">Safe</option><option value="balanced">Balanced</option><option value="aggressive">Aggressive</option></select></div>
<div><label class="field-label">Port</label><input id="fPort" type="number" value="443" min="1" max="65535" class="field"></div>
<div><label class="field-label">ALPN</label><input id="fAlpn" value="http/1.1" class="field"></div>
<div class="sm:col-span-2"><label class="field-label">یادداشت</label><textarea id="fNote" class="field min-h-20"></textarea></div>
<div class="sm:col-span-2"><label class="field-label">اطلاعیه اختصاصی این کانفیگ</label><textarea id="fNotice" placeholder="این متن در صفحه INFO بالای اطلاعیه سیستم می‌آید." class="field min-h-24"></textarea></div>
</div>
<div class="flex gap-2 mt-3"><button id="manualCancel" class="flex-1 rounded-md py-2 bg-white/5 text-[9px]">انصراف</button><button id="manualSave" class="flex-1 rounded-md py-2 bg-gradient-to-br from-indigo-500 to-violet-500 text-[9px]">ذخیره</button></div>
</div></div>

<!-- News modal -->
<div id="newsModal" class="fixed inset-0 z-50 hidden items-center justify-center p-3 bg-black/70 backdrop-blur-md">
<div class="w-full max-w-lg rounded-md border border-white/10 bg-[#0e0e14] p-4">
<div class="flex items-center justify-between mb-3"><b class="text-xs">اطلاعیه مهم</b><button id="newsClose" class="rounded-md w-8 h-8 bg-white/5">×</button></div>
<div class="rounded-md border border-indigo-400/10 bg-indigo-500/[.05] p-4"><div id="newsTitle" class="font-black text-base"></div><div class="text-[8px] text-violet-300 mt-1">PixonPanel · 12.0.1 Beta</div><div id="newsText" class="mt-3 text-[10px] leading-8 text-white/60"></div></div>
<button id="newsOk" class="mt-3 w-full rounded-md py-2 bg-gradient-to-br from-indigo-500 to-violet-500 text-[9px]">متوجه شدم</button>
</div></div>

<!-- Password modal -->
<div id="passModal" class="fixed inset-0 z-50 hidden items-center justify-center p-3 bg-black/70 backdrop-blur-md">
<div class="w-full max-w-lg rounded-md border border-white/10 bg-[#0e0e14] p-4">
<div class="flex items-center justify-between mb-3"><b class="text-xs">تغییر رمز</b><button id="passClose" class="rounded-md w-8 h-8 bg-white/5">×</button></div>
<div class="space-y-2"><div><label class="field-label">رمز فعلی</label><input id="pCurrent" type="password" class="field"></div><div><label class="field-label">رمز جدید</label><input id="pNew" type="password" class="field"></div><div><label class="field-label">تکرار رمز جدید</label><input id="pRepeat" type="password" class="field"></div></div>
<div class="flex gap-2 mt-3"><button id="passCancel" class="flex-1 rounded-md py-2 bg-white/5 text-[9px]">انصراف</button><button id="passSave" class="flex-1 rounded-md py-2 bg-gradient-to-br from-indigo-500 to-violet-500 text-[9px]">ذخیره</button></div>
</div></div>

<div id="toast" class="fixed left-3 bottom-3 z-[100] hidden rounded-md border border-white/10 bg-[#14141c] px-3 py-2 text-[8px]"></div>

<script>
const $=id=>document.getElementById(id);
let editing=null;
let firstLoad=true;
const qs=s=>document.querySelector(s);
function toast(m){const t=$("toast");t.textContent=m;t.classList.remove("hidden");clearTimeout(window.tt);window.tt=setTimeout(()=>t.classList.add("hidden"),2200)}
function esc(v){return String(v??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;")}
function bytes(v){v=Number(v||0);if(v<1024)return v+" B";if(v<1024**2)return (v/1024).toFixed(1)+" KB";if(v<1024**3)return (v/1024**2).toFixed(2)+" MB";return (v/1024**3).toFixed(2)+" GB"}
async function api(url,opt={}){try{const r=await fetch(url,{credentials:"same-origin",cache:"no-store",...opt});if(r.status===401){location.href="/login";return null}let d;try{d=await r.json()}catch{d={ok:false,error:"پاسخ نامعتبر"}}if(!r.ok){toast(d.detail||d.error||"خطا");return null}return d}catch(e){console.error(e);toast("ارتباط با سرور برقرار نشد");return null}}
function open(id){$(id).classList.remove("hidden");$(id).classList.add("flex")}
function close(id){$(id).classList.add("hidden");$(id).classList.remove("flex")}
function resetForm(){["fName","fVolume","fDays","fIp","fConnLimit","fSpeed","fNote","fNotice"].forEach(id=>$(id).value="");$("fProtocol").value="vless-ws";$("fVolumeUnit").value="GB";$("fFingerprint").value="chrome";$("fFragment").value="off";$("fPort").value="443";$("fAlpn").value="http/1.1"}
function fillForm(x){$("fName").value=x.label||"";$("fProtocol").value=x.protocol||"vless-ws";$("fVolume").value=x.limit_bytes?(x.limit_bytes/1024**3).toFixed(2):"";$("fVolumeUnit").value="GB";$("fDays").value="";$("fIp").value=x.ip_limit||"";$("fConnLimit").value=x.connection_limit||"";$("fSpeed").value=x.speed_limit_bytes?(x.speed_limit_bytes*8/1024/1024).toFixed(2):"";$("fFingerprint").value=x.fingerprint||"chrome";$("fFragment").value=x.fragment||"off";$("fPort").value=x.port||443;$("fAlpn").value=x.alpn||"http/1.1";$("fNote").value=x.note||"";$("fNotice").value=x.notice||""}
async function loadNews(openIt=false){const d=await api("/api/news");if(!d)return;if(d.enabled&&d.message){$("newsTitle").textContent=d.title||"اطلاعیه مهم";$("newsText").innerHTML=esc(d.message).replaceAll("\n","<br>");if(openIt)open("newsModal")}else{$("newsTitle").textContent="اطلاعیه‌ای وجود ندارد";$ ("newsText")}}
async function refresh(){const [s,l,a]=await Promise.all([api("/stats"),api("/api/links"),api("/api/activity")]);if(s){$("sLinks").textContent=s.links_count;$("sActive").textContent=s.active_links;$("sConn").textContent=s.active_connections;$("sTraffic").textContent=bytes(s.total_traffic_bytes);$("sReq").textContent=s.total_requests;$("sUp").textContent=s.uptime}if(l)render(l.links||[]);if(a&&a.logs)$("logs").textContent=a.logs.slice().reverse().map(x=>`[${x.level}] ${x.message}`).join("\n")||"فعالیتی ثبت نشده است"}
function render(links){const tb=$("rows");tb.innerHTML="";if(!links.length){tb.innerHTML='<tr><td colspan="8" class="p-6 text-center text-white/20">کانفیگی وجود ندارد</td></tr>';return}for(const x of links){const tr=document.createElement("tr");tr.className="border-b border-white/5";tr.innerHTML=`<td class="p-2"><div class="font-bold">${esc(x.label)}</div><div class="text-[6px] text-white/20 mt-1">${esc(x.uuid)}</div></td><td class="p-2">${esc(x.protocol)}</td><td class="p-2"><span class="rounded-md px-1.5 py-1 ${x.active?'text-green-300 bg-green-500/10':'text-red-300 bg-red-500/10'}">${x.active?'فعال':'غیرفعال'}</span></td><td class="p-2">${bytes(x.used_bytes)} / ${x.limit_bytes?bytes(x.limit_bytes):'∞'}</td><td class="p-2">${x.expires_at?esc(x.expires_at):'∞'}</td><td class="p-2">${Number(x.connected_ips||0)}</td><td class="p-2"><div class="max-w-[220px] truncate font-mono text-violet-200" dir="ltr" title="${esc(x.vless)}">${esc(x.vless)}</div></td><td class="p-2"><div class="flex flex-wrap gap-1" data-actions></div></td>`;const box=tr.querySelector("[data-actions]");const btn=(text,cls,fn)=>{const b=document.createElement("button");b.className=`rounded-md px-2 py-1 text-[7px] ${cls}`;b.textContent=text;b.addEventListener("click",fn);box.appendChild(b)};btn("VLESS","bg-indigo-500/15",()=>copy(x.vless));btn("SUB","bg-white/5",()=>copy(x.sub));btn("INFO","bg-white/5",()=>window.open(x.info,"_blank","noopener,noreferrer"));btn("ویرایش","bg-white/5",()=>edit(x.uuid));btn("ریست","bg-white/5",()=>reset(x.uuid));btn(x.active?"خاموش":"فعال",x.active?"text-red-300":"text-green-300",()=>toggle(x.uuid,x.active));btn("حذف","text-red-300 bg-red-500/5",()=>remove(x.uuid));tb.appendChild(tr)}}
async function copy(text){try{await navigator.clipboard.writeText(text);toast("کپی شد")}catch{const a=document.createElement("textarea");a.value=text;document.body.appendChild(a);a.select();document.execCommand("copy");a.remove();toast("کپی شد")}}
async function edit(uuid){const d=await api(`/api/links/${encodeURIComponent(uuid)}/info`);if(!d)return;editing=uuid;fillForm(d);$("modalTitle").textContent="ویرایش کانفیگ";open("manualModal")}
async function toggle(uuid,active){if(await api(`/api/links/${encodeURIComponent(uuid)}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify({active:!active})}))refresh()}
async function reset(uuid){if(await api(`/api/links/${encodeURIComponent(uuid)}/reset-usage`,{method:"POST"})){toast("مصرف ریست شد");refresh()}}
async function remove(uuid){if(!confirm("این کانفیگ حذف شود؟"))return;if(await api(`/api/links/${encodeURIComponent(uuid)}`,{method:"DELETE"})){toast("حذف شد");refresh()}}
$("manualBtn").addEventListener("click",()=>{editing=null;resetForm();$("modalTitle").textContent="ساخت کانفیگ";open("manualModal")});$("manualClose").addEventListener("click",()=>close("manualModal"));$("manualCancel").addEventListener("click",()=>close("manualModal"));
$("manualSave").addEventListener("click",async()=>{const body={label:$("fName").value.trim()||"کانفیگ جدید",protocol:$("fProtocol").value,limit_value:Number($("fVolume").value||0),limit_unit:$("fVolumeUnit").value,expires_days:Number($("fDays").value||0),ip_limit:Number($("fIp").value||0),connection_limit:Number($("fConnLimit").value||0),speed_limit_value:Number($("fSpeed").value||0),speed_limit_unit:"MBIT",fingerprint:$("fFingerprint").value,fragment:$("fFragment").value,port:Number($("fPort").value||443),alpn:$("fAlpn").value,note:$("fNote").value,notice:$("fNotice").value};let d;if(editing){d=await api(`/api/links/${encodeURIComponent(editing)}`,{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})}else{d=await api("/api/links",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)})}if(d){close("manualModal");toast(editing?"ویرایش شد":"ساخته شد");if(d.vless)await copy(d.vless);editing=null;refresh()}});
$("autoBtn").addEventListener("click",async()=>{const d=await api("/api/links/auto",{method:"POST"});if(d){await copy(d.vless);toast("کانفیگ خودکار ساخته شد");refresh()}});
$("refreshBtn").addEventListener("click",refresh);$("newsBtn").addEventListener("click",()=>loadNews(true));$("newsClose").addEventListener("click",()=>close("newsModal"));$("newsOk").addEventListener("click",()=>close("newsModal"));
$("passBtn").addEventListener("click",()=>open("passModal"));$("passClose").addEventListener("click",()=>close("passModal"));$("passCancel").addEventListener("click",()=>close("passModal"));$("passSave").addEventListener("click",async()=>{const d=await api("/api/change-password",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({current_password:$("pCurrent").value,new_password:$("pNew").value,repeat_password:$("pRepeat").value})});if(d){close("passModal");toast("رمز تغییر کرد");$("pCurrent").value=$("pNew").value=$("pRepeat").value=""}});
refresh();setInterval(refresh,1000);loadNews(true);
</script>
</body>
</html>
'''

# Utility classes for the Tailwind form fields.
DASHBOARD_HTML = DASHBOARD_HTML.replace(
    '<style>',
    '<style>\n.field{width:100%;border-radius:.375rem;border:1px solid rgba(255,255,255,.08);background:rgba(255,255,255,.03);color:#fff;padding:.6rem;outline:none}.field-label{display:block;color:rgba(255,255,255,.35);font-size:8px;margin-bottom:4px}'
)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    if not await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse("/login")
    await ensure_default_link()
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/health")
async def health():
    return {"status": "ok", "service": APP_NAME, "version": APP_VERSION, "connections": len(connections), "uptime": uptime()}


# ============================================================
# GLOBAL ERROR HANDLER
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    stats["total_errors"] += 1
    error_logs.append({"error": str(exc), "path": str(request.url), "method": request.method, "time": datetime.now().isoformat()})
    logger.exception("Unhandled exception")
    if request.url.path.startswith("/api/") or request.url.path == "/stats":
        return JSONResponse({"ok": False, "error": str(exc) or "internal server error"}, status_code=500)
    return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>Internal server error</h2>", status_code=500)


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, log_level="info", workers=1)




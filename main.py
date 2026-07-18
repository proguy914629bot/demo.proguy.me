"""Authenticated local-site guard.

Put sites below ``sites/<hostname>/`` and start this application with Uvicorn.
The files on disk remain ordinary HTML, CSS, and JavaScript; protected/encoded
representations are generated only for authenticated HTTP responses.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import html
import json
import mimetypes
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qs, quote

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, RedirectResponse, Response

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
SITES_DIR = (BASE_DIR / os.getenv("SITE_GUARD_SITES_DIR", "sites")).resolve()
USERNAME = os.getenv("SITE_GUARD_USERNAME", "admin")
PASSWORD = os.getenv("SITE_GUARD_PASSWORD", "change-me")
PASSWORD_HASH = os.getenv("SITE_GUARD_PASSWORD_HASH", "")
SESSION_TTL = int(os.getenv("SITE_GUARD_SESSION_TTL", "28800"))
MAX_TEXT_BYTES = int(os.getenv("SITE_GUARD_MAX_TEXT_BYTES", str(5 * 1024 * 1024)))
COOKIE_SECURE = os.getenv("SITE_GUARD_COOKIE_SECURE", "0").lower() in {"1", "true", "yes"}
AGGRESSIVE_PROTECTION = os.getenv("SITE_GUARD_AGGRESSIVE", "0").lower() in {"1", "true", "yes"}
DEVTOOLS_THRESHOLD = int(os.getenv("SITE_GUARD_DEVTOOLS_THRESHOLD", "170"))
SECRET = os.getenv("SITE_GUARD_SECRET", "").encode() or secrets.token_bytes(32)

try:
    SITE_CREDENTIALS = json.loads(os.getenv("SITE_GUARD_CREDENTIALS_JSON", "{}"))
    if not isinstance(SITE_CREDENTIALS, dict):
        raise ValueError("SITE_GUARD_CREDENTIALS_JSON must contain a JSON object")
except json.JSONDecodeError as exc:
    raise ValueError("SITE_GUARD_CREDENTIALS_JSON is not valid JSON") from exc

SITE_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
URL_ATTRIBUTE_RE = re.compile(
    r"""(?P<prefix>(?<![\w:-])(?:href|src|action|poster)\s*=\s*)
        (?:(?P<quote>["'])(?P<quoted>.*?)(?P=quote)|(?P<bare>[^\s"'=<>`]+))""",
    flags=re.IGNORECASE | re.VERBOSE,
)
BARE_DOMAIN_PATH_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]*\.)+[A-Za-z]{2,}(?::\d+)?(?:[/?#].*)?$"
)
SAFE_ASSET_SUFFIXES = {
    ".avif", ".bmp", ".css", ".csv", ".eot", ".gif", ".ico", ".jpeg", ".jpg",
    ".js", ".json", ".m4a", ".m4v", ".map-disabled", ".mjs", ".mov", ".mp3",
    ".mp4", ".ogg", ".otf", ".pdf", ".png", ".svg", ".ttf", ".txt", ".wasm",
    ".wav", ".webm", ".webmanifest", ".webp", ".woff", ".woff2", ".xml",
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


def _security_headers(content_type: str | None = None) -> dict[str, str]:
    headers = {
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0, private",
        "Pragma": "no-cache",
        "Expires": "0",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
        "Content-Security-Policy": "frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
        "X-Robots-Tag": "noindex, nofollow, noarchive, nosnippet",
    }
    if COOKIE_SECURE:
        headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if content_type:
        headers["Content-Type"] = content_type
    return headers


@app.middleware("http")
async def add_guard_headers(request: Request, call_next):
    response = await call_next(request)
    for key, value in _security_headers().items():
        response.headers.setdefault(key, value)
    return response


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _cookie_name(site: str) -> str:
    return "site_guard_" + hashlib.sha256(site.encode()).hexdigest()[:12]


def _csrf_cookie_name(site: str) -> str:
    return "site_guard_csrf_" + hashlib.sha256(site.encode()).hexdigest()[:12]


def _site_credentials_file(site: str) -> Path | None:
    site_dir = _site_directory(site)
    if site_dir is None:
        return None
    credentials_file = site_dir / ".guard.json"
    try:
        if not credentials_file.is_file() or credentials_file.stat().st_size > 64 * 1024:
            return None
    except OSError:
        return None
    try:
        credentials_file.resolve().relative_to(site_dir)
    except ValueError:
        return None
    return credentials_file


def _credentials_for(site: str) -> tuple[str, str, str]:
    configured = SITE_CREDENTIALS.get(site, {})
    if not isinstance(configured, dict):
        configured = {}

    credentials_file = _site_credentials_file(site)
    if credentials_file is not None:
        try:
            file_configured = json.loads(credentials_file.read_text(encoding="utf-8"))
            if not isinstance(file_configured, dict):
                raise ValueError("credential file must contain a JSON object")
            configured = file_configured
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            # A present but malformed credential file fails closed instead of
            # silently falling back to a less-specific global credential.
            return "", "", "invalid-credential-file"

    username = str(configured.get("username", USERNAME))
    password_value = configured.get("password", PASSWORD)
    password_hash_value = configured.get("password_hash", PASSWORD_HASH)
    password = "" if password_value is None else str(password_value)
    password_hash = "" if password_hash_value is None else str(password_hash_value)
    if credentials_file is not None and not username:
        return "", "", "invalid-credential-file"
    if credentials_file is not None and not password and not password_hash:
        return "", "", "invalid-credential-file"
    return username, password, password_hash


def _credential_version(site: str) -> str:
    username, password, password_hash = _credentials_for(site)
    material = f"{username}\0{password_hash or password}".encode()
    return _b64url(hmac.new(SECRET, b"credentials\0" + material, hashlib.sha256).digest()[:12])


def _browser_binding(request: Request) -> str:
    user_agent = request.headers.get("user-agent", "").encode("utf-8", errors="replace")
    return _b64url(hmac.new(SECRET, b"browser\0" + user_agent, hashlib.sha256).digest()[:12])


def _issue_token(site: str, request: Request) -> str:
    now = int(time.time())
    payload = json.dumps(
        {
            "v": 2,
            "site": site,
            "iat": now,
            "exp": now + SESSION_TTL,
            "browser": _browser_binding(request),
            "credentials": _credential_version(site),
            "nonce": secrets.token_hex(16),
        },
        separators=(",", ":"),
    ).encode()
    encoded = _b64url(payload)
    signature = _b64url(hmac.new(SECRET, encoded.encode(), hashlib.sha256).digest())
    return f"{encoded}.{signature}"


def _valid_token(token: str | None, site: str, request: Request) -> bool:
    if not token:
        return False
    try:
        encoded, supplied_signature = token.split(".", 1)
        expected_signature = _b64url(hmac.new(SECRET, encoded.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(supplied_signature, expected_signature):
            return False
        payload = json.loads(_b64url_decode(encoded))
        if not isinstance(payload, dict):
            return False
        now = int(time.time())
        issued_at = int(payload.get("iat", 0))
        expires_at = int(payload.get("exp", 0))
        return (
            payload.get("v") == 2
            and hmac.compare_digest(str(payload.get("site", "")), site)
            and hmac.compare_digest(str(payload.get("browser", "")), _browser_binding(request))
            and hmac.compare_digest(str(payload.get("credentials", "")), _credential_version(site))
            and now - SESSION_TTL <= issued_at <= now + 30
            and issued_at < expires_at <= issued_at + SESSION_TTL
            and expires_at >= now
        )
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def _hash_password(password: str, iterations: int = 600_000) -> str:
    salt = secrets.token_bytes(18)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${_b64url(salt)}${_b64url(digest)}"


def _verify_password(supplied: str, plain_password: str, password_hash: str) -> bool:
    if not password_hash:
        return hmac.compare_digest(supplied, plain_password)
    try:
        algorithm, iterations_text, salt_text, digest_text = password_hash.split("$", 3)
        iterations = int(iterations_text)
        if algorithm != "pbkdf2_sha256" or not 100_000 <= iterations <= 2_000_000:
            return False
        expected = _b64url_decode(digest_text)
        actual = hashlib.pbkdf2_hmac("sha256", supplied.encode(), _b64url_decode(salt_text), iterations)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def _credentials_valid(site: str, username: str, password: str) -> bool:
    expected_username, plain_password, password_hash = _credentials_for(site)
    # Always perform both comparisons so an invalid username does not skip the
    # intentionally expensive password verification.
    username_valid = hmac.compare_digest(username, expected_username)
    password_valid = _verify_password(password, plain_password, password_hash)
    return username_valid & password_valid


def _site_directory(site: str) -> Path | None:
    if not SITE_RE.fullmatch(site) or ".." in site:
        return None
    candidate = (SITES_DIR / site).resolve()
    try:
        candidate.relative_to(SITES_DIR)
    except ValueError:
        return None
    return candidate if candidate.is_dir() else None


def _resolve_resource(site_dir: Path, resource_path: str) -> tuple[Path | None, bool]:
    """Resolve a URL path and indicate whether it is an HTML page."""
    raw = resource_path.strip("/")
    if "\\" in raw or "\x00" in raw:
        return None, False

    parts = PurePosixPath(raw).parts if raw else ()
    if any(part in {".", ".."} or part.startswith(".") for part in parts):
        return None, False

    relative = PurePosixPath(*parts) if parts else PurePosixPath("index.html")
    suffix = relative.suffix.lower()
    is_page = suffix in {"", ".html", ".htm"}
    if not suffix:
        relative = relative.with_suffix(".html")
    elif suffix == ".map" or (not is_page and suffix not in SAFE_ASSET_SUFFIXES):
        return None, False

    candidate = (site_dir / Path(*relative.parts)).resolve()
    try:
        candidate.relative_to(site_dir)
    except ValueError:
        return None, False
    if not candidate.is_file():
        return None, is_page
    return candidate, is_page


def _xor_payload(source: str) -> tuple[str, list[int]]:
    raw = source.encode("utf-8")
    key = secrets.token_bytes(24)
    encoded = bytes(value ^ key[index % len(key)] for index, value in enumerate(raw))
    return base64.b64encode(encoded).decode("ascii"), list(key)


def _decoder_expression(payload: str, key: list[int]) -> str:
    return (
        "(()=>{const p='" + payload + "',k=[" + ",".join(map(str, key)) + "];"
        "const b=Uint8Array.from(atob(p),c=>c.charCodeAt(0));"
        "for(let i=0;i<b.length;i++)b[i]^=k[i%k.length];"
        "return new TextDecoder().decode(b)})()"
    )


def _runtime_script(marker: str) -> str:
    # DevTools detection is deliberately a deterrent. It is never treated as an
    # authorization boundary; the server-side session remains the real boundary.
    aggressive = "true" if AGGRESSIVE_PROTECTION else "false"
    return f"""(()=>{{
const threshold={DEVTOOLS_THRESHOLD},aggressive={aggressive},marker='{marker}',safeLog=console.log.bind(console),safeClear=console.clear.bind(console);let blocked=false,getterHits=0,getterSignals=0;
document.documentElement.style.visibility='hidden';
const deny=()=>{{if(blocked)return;blocked=true;document.documentElement.style.visibility='visible';document.documentElement.innerHTML='<head><title>Inspection blocked</title></head><body style="margin:0;background:#09090b;color:#fafafa;font:16px system-ui;display:grid;place-items:center;min-height:100vh"><main style="text-align:center"><h1>Inspection blocked</h1><p>Close developer tools and reload this page.</p></main></body>';if(aggressive){{let n=0;const trap=setInterval(()=>{{debugger;if(++n>80)clearInterval(trap)}},125);}}}};
const dimensions=()=>{{const open=Math.max(window.outerWidth-window.innerWidth,window.outerHeight-window.innerHeight)>threshold;if(open)deny();return open;}};
const pauseStart=performance.now();debugger;const debuggerOpen=performance.now()-pauseStart>100;if(debuggerOpen)deny();
const probe=new Image();Object.defineProperty(probe,'id',{{configurable:false,get(){{getterHits++;return'guard';}}}});
setInterval(()=>{{dimensions();const before=getterHits;safeLog(probe);setTimeout(()=>{{getterSignals=getterHits>before?getterSignals+1:0;if(getterSignals>=3)deny();}},0);safeClear();}},100);
window.addEventListener('resize',dimensions,{{passive:true}});dimensions();
document.addEventListener('contextmenu',event=>event.preventDefault());
document.addEventListener('keydown',event=>{{const key=event.key.toLowerCase();if(key==='f12'||(event.ctrlKey&&event.shiftKey&&['i','j','c'].includes(key))||(event.ctrlKey&&key==='u')){{event.preventDefault();deny();}}}},true);
window.addEventListener('beforeprint',deny);
new MutationObserver(()=>{{if(!document.querySelector('meta[data-site-guard="'+marker+'"]'))deny();}}).observe(document.documentElement,{{childList:true,subtree:true}});
if(!dimensions()&&!debuggerOpen)document.documentElement.style.visibility='visible';
}})();"""


def _inject_runtime(source: str) -> str:
    marker = secrets.token_hex(16)
    script = f'<meta data-site-guard="{marker}"><script>' + _runtime_script(marker) + "</script>"
    head = re.search(r"<head(?:\s[^>]*)?>", source, flags=re.IGNORECASE)
    if head:
        return source[: head.end()] + script + source[head.end() :]
    return script + source


def _rewrite_tag_urls(raw_tag: str, site_prefix: str, site_name: str | None = None) -> str:
    site_prefix = "/" + site_prefix.strip("/")
    site_name_prefix = "/" + site_prefix.rsplit("/", 1)[-1]
    mount_prefix = site_prefix[: -len(site_name_prefix)]
    legacy_prefix = f"/{site_name}.com" if site_name and "." not in site_name else ""

    def replace(match: re.Match[str]) -> str:
        url = match.group("quoted") if match.group("quote") else match.group("bare")
        if not url.startswith("/"):
            if BARE_DOMAIN_PATH_RE.fullmatch(url):
                route_site = site_prefix.rsplit("/", 1)[-1]
                # If the link already starts with the guarded route's domain
                # name, append only its remaining path. Otherwise retain the
                # complete domain-shaped path beneath this guard route.
                if url == route_site or url.startswith(route_site + "/"):
                    rewritten = site_prefix + url[len(route_site):]
                else:
                    rewritten = site_prefix + "/" + url
                quote_char = match.group("quote") or ""
                return f"{match.group('prefix')}{quote_char}{rewritten}{quote_char}"
            return match.group(0)
        if url.startswith("//"):
            return match.group(0)

        if url == site_prefix or url.startswith(tuple(site_prefix + suffix for suffix in ("/", "?", "#"))):
            return match.group(0)
        # Preserve a site-prefixed URL written in the source while adding only
        # the external mount prefix (for example /example.com/x ->
        # /example/example.com/x).
        if url == site_name_prefix or url.startswith(tuple(site_name_prefix + suffix for suffix in ("/", "?", "#"))):
            rewritten = mount_prefix + url
        elif legacy_prefix and (url == legacy_prefix or url.startswith(tuple(legacy_prefix + suffix for suffix in ("/", "?", "#")))):
            rewritten = site_prefix + url[len(legacy_prefix):]
        else:
            rewritten = site_prefix + url
        quote_char = match.group("quote") or ""
        return f"{match.group('prefix')}{quote_char}{rewritten}{quote_char}"

    return URL_ATTRIBUTE_RE.sub(replace, raw_tag)


class _SiteUrlRewriter(HTMLParser):
    """Preserve document content while rewriting attributes on actual HTML tags."""

    def __init__(self, site_prefix: str, site_name: str | None = None):
        super().__init__(convert_charrefs=False)
        self.site_prefix = site_prefix
        self.site_name = site_name
        self.output: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.output.append(_rewrite_tag_urls(self.get_starttag_text(), self.site_prefix, self.site_name))

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.output.append(_rewrite_tag_urls(self.get_starttag_text(), self.site_prefix, self.site_name))

    def handle_endtag(self, tag: str) -> None:
        self.output.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        self.output.append(data)

    def handle_entityref(self, name: str) -> None:
        self.output.append(f"&{name};")

    def handle_charref(self, name: str) -> None:
        self.output.append(f"&#{name};")

    def handle_comment(self, data: str) -> None:
        self.output.append(f"<!--{data}-->")

    def handle_decl(self, decl: str) -> None:
        self.output.append(f"<!{decl}>")

    def handle_pi(self, data: str) -> None:
        self.output.append(f"<?{data}>")

    def unknown_decl(self, data: str) -> None:
        self.output.append(f"<![{data}]>")


def _rewrite_site_urls(source: str, site_prefix: str, site_name: str | None = None) -> str:
    rewriter = _SiteUrlRewriter(site_prefix, site_name)
    rewriter.feed(source)
    rewriter.close()
    return "".join(rewriter.output)


def _protect_html(source: str, site: str, route_prefix: str | None = None) -> str:
    rewritten_source = _rewrite_site_urls(source, route_prefix or f"/{site}", site)
    payload, key = _xor_payload(_inject_runtime(rewritten_source))
    decoder = _decoder_expression(payload, key)
    blocked_markup = (
        "<head><title>Inspection blocked</title></head><body style=\"margin:0;background:#09090b;"
        "color:#fafafa;font:16px system-ui;display:grid;place-items:center;min-height:100vh\">"
        "<main style=\"text-align:center\"><h1>Inspection blocked</h1>"
        "<p>Close developer tools and reload this page.</p></main></body>"
    )
    return (
        "<!doctype html><html><head><meta charset=utf-8><meta name=robots content=noindex,nofollow>"
        "<title>Loading…</title><style>html{visibility:hidden}</style></head><body>"
        "<noscript>JavaScript is required.</noscript><script>"
        "const blockedMarkup='" + blocked_markup.replace("'", "\\'") + "';"
        "const pauseStart=performance.now();debugger;const debuggerOpen=performance.now()-pauseStart>100;"
        "const devtoolsOpen=Math.max(window.outerWidth-window.innerWidth,window.outerHeight-window.innerHeight)>" + str(DEVTOOLS_THRESHOLD) + ";"
        "if(devtoolsOpen||debuggerOpen){document.documentElement.style.visibility='visible';document.documentElement.innerHTML=blockedMarkup;}"
        "else{const d=" + decoder + ";document.open();document.write(d);document.close();}"
        "</script></body></html>"
    )


def _compact_css(source: str) -> str:
    # Conservative compaction: strings remain untouched, while comments and
    # whitespace outside strings are reduced.
    output: list[str] = []
    index = 0
    quote_char: str | None = None
    while index < len(source):
        char = source[index]
        if quote_char:
            output.append(char)
            if char == "\\" and index + 1 < len(source):
                index += 1
                output.append(source[index])
            elif char == quote_char:
                quote_char = None
        elif char in {"'", '"'}:
            quote_char = char
            output.append(char)
        elif source.startswith("/*", index):
            end = source.find("*/", index + 2)
            index = len(source) if end < 0 else end + 1
        elif char.isspace():
            if output and output[-1] not in "{}:;,>+~ " and index + 1 < len(source):
                output.append(" ")
        else:
            if char in "{}:;,>+~" and output and output[-1] == " ":
                output.pop()
            output.append(char)
        index += 1
    return "".join(output).strip()


def _protect_javascript(source: str) -> str:
    # Modules must retain their import/export grammar and URL base. Ordinary
    # classic scripts can be delivered through an encoded indirect-eval wrapper.
    if re.search(r"(^|\n)\s*(?:import\s|export\s)", source):
        return source
    payload, key = _xor_payload(source)
    decoder = _decoder_expression(payload, key)
    return f"(()=>{{const s={decoder};(0,eval)(s);}})();"


def _login_page(
    site: str,
    next_path: str,
    error: str = "",
    status_code: int | None = None,
    route_prefix: str | None = None,
) -> HTMLResponse:
    safe_site = html.escape(site)
    safe_next = html.escape(next_path, quote=True)
    route_prefix = route_prefix or f"/{site}"
    safe_route_prefix = html.escape(route_prefix, quote=True)
    csrf_token = secrets.token_urlsafe(32)
    error_markup = f'<p class="error" role="alert">{html.escape(error)}</p>' if error else ""
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>Sign in · {safe_site}</title>
<style>*{{box-sizing:border-box}}body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#09090b;color:#fafafa;font:16px system-ui}}main{{width:min(92vw,390px);padding:30px;border:1px solid #27272a;border-radius:16px;background:#18181b;box-shadow:0 24px 80px #0008}}h1{{margin:0 0 8px;font-size:1.6rem}}p{{color:#a1a1aa}}label{{display:block;margin:18px 0 7px}}input{{width:100%;padding:12px;border:1px solid #3f3f46;border-radius:9px;background:#09090b;color:#fff;font:inherit}}button{{width:100%;margin-top:22px;padding:12px;border:0;border-radius:9px;background:#fafafa;color:#09090b;font-weight:700;cursor:pointer}}.error{{color:#fda4af}}</style></head>
<body><main><h1>Protected site</h1><p>Sign in to continue to {safe_site}.</p>{error_markup}
<form method="post" action="/__guard/login" autocomplete="on"><input type="hidden" name="site" value="{safe_site}"><input type="hidden" name="next" value="{safe_next}"><input type="hidden" name="route_prefix" value="{safe_route_prefix}"><input type="hidden" name="csrf" value="{csrf_token}">
<label for="username">Username</label><input id="username" name="username" autocomplete="username" required autofocus>
<label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required>
<button type="submit">Sign in</button></form></main></body></html>"""
    response = HTMLResponse(
        document,
        status_code=status_code if status_code is not None else (401 if error else 200),
        headers=_security_headers(),
    )
    response.set_cookie(
        _csrf_cookie_name(site),
        csrf_token,
        max_age=600,
        path="/__guard",
        secure=COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )
    return response


class AttemptLimiter:
    def __init__(self, limit: int = 5, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self.attempts: defaultdict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self.lock:
            attempts = self.attempts[key]
            while attempts and attempts[0] <= now - self.window:
                attempts.popleft()
            if len(attempts) >= self.limit:
                return False
            attempts.append(now)
            return True

    def clear(self, key: str) -> None:
        with self.lock:
            self.attempts.pop(key, None)


attempt_limiter = AttemptLimiter()


@app.get("/", response_class=PlainTextResponse)
async def root() -> PlainTextResponse:
    return PlainTextResponse("Site guard is running. Open /<site-name>/ to continue.")


@app.post("/__guard/login")
async def login(request: Request) -> Response:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        return PlainTextResponse("Unsupported content type", status_code=415)
    raw_body = await request.body()
    if len(raw_body) > 16_384:
        return PlainTextResponse("Request too large", status_code=413)
    try:
        fields = parse_qs(raw_body.decode("utf-8"), keep_blank_values=True)
    except UnicodeDecodeError:
        return PlainTextResponse("Invalid form", status_code=400)

    field = lambda name: fields.get(name, [""])[0]
    site, username, password, next_path, route_prefix, csrf_token = (
        field("site"), field("username"), field("password"), field("next"), field("route_prefix"), field("csrf")
    )
    site_dir = _site_directory(site)
    if site_dir is None:
        return PlainTextResponse("Site not found", status_code=404)

    prefix_parts = route_prefix.strip("/").split("/") if route_prefix.strip("/") else []
    valid_prefix = bool(prefix_parts) and prefix_parts[-1] == site and all(SITE_RE.fullmatch(part) for part in prefix_parts)
    if not valid_prefix:
        route_prefix = f"/{site}"
    safe_prefix = route_prefix
    if not (
        next_path == safe_prefix
        or next_path.startswith(safe_prefix + "/")
        or next_path.startswith(safe_prefix + "?")
        or next_path.startswith(safe_prefix + "#")
    ):
        next_path = safe_prefix
    csrf_cookie = request.cookies.get(_csrf_cookie_name(site), "")
    if not csrf_token or not csrf_cookie or not hmac.compare_digest(csrf_token, csrf_cookie):
        return _login_page(
            site,
            next_path,
            "The sign-in form expired. Please try again.",
            status_code=400,
            route_prefix=route_prefix,
        )

    remote = request.client.host if request.client else "unknown"
    limiter_key = f"{remote}:{site}"
    if not attempt_limiter.allow(limiter_key):
        return _login_page(
            site,
            next_path,
            "Too many attempts. Try again in one minute.",
            status_code=429,
            route_prefix=route_prefix,
        )

    valid = await asyncio.to_thread(_credentials_valid, site, username, password)
    if not valid:
        return _login_page(site, next_path, "Incorrect username or password.", route_prefix=route_prefix)

    attempt_limiter.clear(limiter_key)
    response = RedirectResponse(next_path, status_code=303, headers=_security_headers())
    response.delete_cookie(_csrf_cookie_name(site), path="/__guard")
    response.set_cookie(
        _cookie_name(site),
        _issue_token(site, request),
        max_age=SESSION_TTL,
        path=route_prefix,
        secure=COOKIE_SECURE,
        httponly=True,
        samesite="strict",
    )
    return response


@app.post("/__guard/logout")
async def logout(request: Request) -> Response:
    raw_body = await request.body()
    fields = parse_qs(raw_body.decode("utf-8", errors="ignore"), keep_blank_values=True)
    site = fields.get("site", [""])[0]
    if _site_directory(site) is None:
        return PlainTextResponse("Site not found", status_code=404)
    response = RedirectResponse(f"/{quote(site)}", status_code=303, headers=_security_headers())
    response.delete_cookie(_cookie_name(site), path=f"/{site}")
    return response


def _site_route_context(site_segment: str, resource_path: str) -> tuple[str, str, Path, str] | None:
    """Resolve both direct routes and deployments mounted below a URL prefix.

    For example, ``/example.com/assets/site.css`` is direct, while
    ``/example/example.com/assets/site.css`` has ``/example`` as a mount prefix.
    """
    direct_dir = _site_directory(site_segment)
    if direct_dir is not None:
        legacy_segment = f"{site_segment}.com"
        if resource_path == legacy_segment:
            return site_segment, "", direct_dir, f"/{site_segment}"
        if resource_path.startswith(legacy_segment + "/"):
            return site_segment, resource_path[len(legacy_segment) + 1 :], direct_dir, f"/{site_segment}"
        return site_segment, resource_path, direct_dir, f"/{site_segment}"

    if not resource_path:
        return None
    nested_site, separator, nested_resource = resource_path.partition("/")
    nested_dir = _site_directory(nested_site)
    if nested_dir is None:
        return None
    return nested_site, nested_resource if separator else "", nested_dir, f"/{site_segment}/{nested_site}"


@app.get("/{site}")
@app.get("/{site}/{resource_path:path}")
async def guarded_site(request: Request, site: str, resource_path: str = "") -> Response:
    context = _site_route_context(site, resource_path)
    if context is None:
        return PlainTextResponse("Site not found", status_code=404)
    site, resource_path, site_dir, route_prefix = context

    requested_path = request.url.path
    if request.url.query:
        requested_path += "?" + request.url.query
    if not _valid_token(request.cookies.get(_cookie_name(site)), site, request):
        return _login_page(site, requested_path, route_prefix=route_prefix)

    resource, is_page = _resolve_resource(site_dir, resource_path)
    if resource is None:
        return PlainTextResponse("Page not found" if is_page else "Asset not found", status_code=404)

    suffix = resource.suffix.lower()
    if is_page:
        if resource.stat().st_size > MAX_TEXT_BYTES:
            return PlainTextResponse("HTML file is too large", status_code=413)
        try:
            source = resource.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return PlainTextResponse("HTML must be UTF-8", status_code=500)
        return HTMLResponse(
            _protect_html(source, site, route_prefix),
            headers=_security_headers("text/html; charset=utf-8"),
        )
    if suffix == ".css":
        if resource.stat().st_size > MAX_TEXT_BYTES:
            return PlainTextResponse("CSS file is too large", status_code=413)
        source = resource.read_text(encoding="utf-8")
        return Response(_compact_css(source), media_type="text/css", headers=_security_headers())
    if suffix in {".js", ".mjs"}:
        if resource.stat().st_size > MAX_TEXT_BYTES:
            return PlainTextResponse("JavaScript file is too large", status_code=413)
        source = resource.read_text(encoding="utf-8")
        return Response(_protect_javascript(source), media_type="text/javascript", headers=_security_headers())

    media_type = mimetypes.guess_type(resource.name)[0] or "application/octet-stream"
    return FileResponse(resource, media_type=media_type, headers=_security_headers())


if __name__ == "__main__":
    import getpass
    import sys

    if sys.argv[1:] != ["--hash-password"]:
        raise SystemExit("Usage: python main.py --hash-password")
    entered_password = getpass.getpass("Password to hash: ")
    confirmed_password = getpass.getpass("Confirm password: ")
    if not entered_password or not hmac.compare_digest(entered_password, confirmed_password):
        raise SystemExit("Passwords did not match or were empty")
    print(_hash_password(entered_password))

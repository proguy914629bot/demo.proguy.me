# FastAPI site guard

This app serves ordinary local files from `sites/<site-name>/` behind a username/password login. Extensionless URLs map to HTML files:

| URL | Local file |
| --- | --- |
| `/mywebsite.com` | `sites/mywebsite.com/index.html` |
| `/mywebsite.com/abc` | `sites/mywebsite.com/abc.html` |
| `/mywebsite.com/abc/def` | `sites/mywebsite.com/abc/def.html` |
| `/mywebsite.com/assets/app.js` | `sites/mywebsite.com/assets/app.js` |

## Run it

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export SITE_GUARD_USERNAME='your-user'
python main.py --hash-password
export SITE_GUARD_PASSWORD_HASH='paste-the-generated-pbkdf2-value-here'
export SITE_GUARD_SECRET="$(openssl rand -hex 32)"
export SITE_GUARD_COOKIE_SECURE=0  # use 1 behind HTTPS in production
uvicorn main:app --host 127.0.0.1 --port 8000
```

Then open <http://127.0.0.1:8000/example.com>. The development defaults are `admin` / `change-me`; do not use those defaults on a public deployment. `SITE_GUARD_PASSWORD` remains supported for local development, but the PBKDF2 hash is preferred.

## Run with systemd

The repository includes [demo-proguy-me.service](demo-proguy-me.service). On the Linux host, update its `User`, `WorkingDirectory`, and `ExecStart` paths if needed, then install and enable it:

```bash
sudo install -d -m 0750 /etc/demo.proguy.me
sudo install -m 0644 demo-proguy-me.service /etc/systemd/system/demo-proguy-me.service
sudo systemctl daemon-reload
sudo systemctl enable --now demo-proguy-me.service
sudo systemctl status demo-proguy-me.service
```

Put production secrets in `/etc/demo.proguy.me/site-guard.env` (for example `SITE_GUARD_SECRET`, `SITE_GUARD_USERNAME`, and `SITE_GUARD_PASSWORD_HASH`) and restrict it with `sudo chmod 0600 /etc/demo.proguy.me/site-guard.env`.

Each site can have its own credentials in `sites/<site-name>/.guard.json`. The file is read only by the server, is blocked from URL serving, and is ignored by Git:

```json
{
  "username": "alice",
  "password_hash": "pbkdf2_sha256$..."
}
```

For local development, a plain password is also accepted:

```json
{
  "username": "alice",
  "password": "development-only-password"
}
```

Generate a hash with `python main.py --hash-password`. A site file takes precedence over the environment variables. If no site file exists, the global credentials are used. Alternatively, different sites can use credentials through one JSON environment variable:

```bash
export SITE_GUARD_CREDENTIALS_JSON='{"example.com":{"username":"alice","password_hash":"pbkdf2_sha256$..."},"client.test":{"username":"bob","password":"development-only"}}'
```

For production, terminate HTTPS at a reverse proxy, set `SITE_GUARD_COOKIE_SECURE=1`, and keep the secret and credentials in environment variables or a secret manager. Set `SITE_GUARD_AGGRESSIVE=1` only if you accept the usability risk of the bounded debugger trap. Size, shortcut, and repeated object-getter detection plus 100 ms console clearing are enabled without it.

## What the protection does

- Validates a signed, expiring, per-site HTTP-only session cookie bound to the browser user agent and current credential version.
- Supports PBKDF2-SHA256 password hashes and per-site credentials, rate-limits failed sign-ins, and performs password verification outside the async event loop.
- Protects login forms with short-lived, HTTP-only, same-site CSRF cookies and validates redirect destinations strictly.
- Rejects traversal, symlink escapes, dotfiles, source maps, and unapproved asset types.
- Prefixes root-relative `href`, `src`, `action`, and `poster` attributes with the current site name. Explicit external, protocol-relative, fragment, and ordinary relative URLs are preserved.
- Converts bare domain-shaped paths such as `example.com/abc` into guarded paths such as `/example/example.com/abc`. Explicit `https://...` and `//...` URLs remain external.
- Also supports deployments mounted below a URL prefix, such as `/example/example.com/...`; generated asset links and cookie paths retain that prefix.
- Encodes each HTML response with a new random XOR key and injects it through a generated JavaScript loader.
- Encodes classic JavaScript inside an execution wrapper; ES modules stay unobfuscated so their import/export semantics are not broken.
- Conservatively compacts CSS while leaving the source files on disk untouched.
- Detects common DevTools window-size changes, repeated object-getter probes, and inspection shortcuts; wipes the document on detection; clears the console every 100 ms; and optionally enables a bounded debugger trap.
- Uses browser-compatible width/height thresholds so vertical-tab sidebars do not look like docked DevTools; Firefox/Zen also skip the two browser-specific probes that otherwise produce false positives there.
- Watches its injected guard marker for DOM tampering and blocks printing while the guarded page is active.
- Sends no-cache, no-index, anti-framing, object-blocking, same-origin resource, and optional HSTS headers.
- Refuses oversized HTML, CSS, and JavaScript transformation requests; configure the limit with `SITE_GUARD_MAX_TEXT_BYTES`.

## Important limitation

Anything a browser can render or execute can ultimately be recovered by the person controlling that browser. Encoding, minification, DevTools detection, console clearing, and debugger traps only discourage casual inspection. They are not a secrecy boundary. Keep confidential business logic and secrets on the server and return only the data the authenticated user is allowed to receive.

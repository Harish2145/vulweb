"""
INTENTIONALLY VULNERABLE APPLICATION - FOR LOCAL PENTEST LAB USE ONLY.
Every bug below is labeled VULN-NN and documented with a PoC in CHEATSHEET.md.
Do NOT expose this to the internet. Do NOT reuse this code anywhere real.
"""
import base64
import hashlib
import json
import os
import pickle
import sqlite3
import subprocess
import time

import jwt
import requests
from flask import (Flask, request, redirect, render_template, render_template_string,
                    session, jsonify, make_response, send_from_directory)
from lxml import etree

app = Flask(__name__)

# VULN-01 (SECRET-01): Hardcoded secret key / signing key committed to source.
app.secret_key = "s3cr3t_dev_key_2023"
JWT_SECRET = "s3cr3t_dev_key_2023"

# VULN-02 (DEBUG-01): Debug mode enabled -> Werkzeug interactive debugger /
# verbose stack traces leak source, env vars, and allow RCE via console if reached.
app.config["DEBUG"] = True

DB_PATH = "/app/lab.db"
UPLOAD_DIR = "/app/static/uploads"
FILES_DIR = "/app/files"
os.makedirs(FILES_DIR, exist_ok=True)
with open(os.path.join(FILES_DIR, "report.txt"), "w") as f:
    f.write("Q3 report: nothing interesting here.\n")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def md5(s):
    # VULN-03 (CRYPTO-01): Weak, unsalted MD5 password hashing.
    return hashlib.md5(s.encode()).hexdigest()


def init_db():
    conn = db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT,
        email TEXT, is_admin INTEGER DEFAULT 0, secret_note TEXT
    );
    CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, author TEXT, body TEXT);
    CREATE TABLE IF NOT EXISTS coupons(code TEXT PRIMARY KEY, uses_left INTEGER);
    """)
    conn.execute("INSERT OR IGNORE INTO users(id,username,password,email,is_admin,secret_note) "
                 "VALUES (1,'alice',?,'alice@lab.local',0,'alice fav color: blue')", (md5("password123"),))
    conn.execute("INSERT OR IGNORE INTO users(id,username,password,email,is_admin,secret_note) "
                 "VALUES (2,'admin',?,'admin@lab.local',1,'root flag: FLAG{idor_or_bust}')", (md5("S3cureAdminPW!"),))
    conn.execute("INSERT OR IGNORE INTO comments(id,author,body) VALUES (1,'bob','Welcome to the lab!')")
    conn.execute("INSERT OR IGNORE INTO coupons(code,uses_left) VALUES ('LAB10',1)")
    conn.commit()
    conn.close()


init_db()


# ---------- VULN-04 (CORS-01): Overly permissive CORS on API routes ----------
@app.after_request
def add_headers(resp):
    if request.path.startswith("/api/"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Headers"] = "*"
    # VULN-05 (INFO-01): Leaking internal stack/version info via headers.
    resp.headers["X-Powered-By"] = "LabApp/0.1 (Flask 3.0, debug=on)"
    return resp


@app.route("/")
def index():
    return render_template("index.html", user=session.get("user"))


# ---------- VULN-06 (AUTH-01): SQLi in login (string concatenation) ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        conn = db()
        # Classic SQLi: ' OR '1'='1' -- as username logs in as the first user.
        query = f"SELECT * FROM users WHERE username = '{u}' AND password = '{md5(p)}'"
        try:
            row = conn.execute(query).fetchone()
        except sqlite3.Error as e:
            return f"<pre>SQL error: {e}\nQuery: {query}</pre>", 500  # VULN-05 error leakage
        conn.close()
        if row:
            session["user"] = row["username"]
            session["uid"] = row["id"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect("/")
        error = "Invalid credentials"
        # VULN-07 (AUTH-02): No rate limiting / lockout on login -> brute-forceable.
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


# ---------- VULN-08: Reflected XSS + VULN-09: 2nd-order SQLi via search ----------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    conn = db()
    query = f"SELECT * FROM comments WHERE body LIKE '%{q}%'"
    try:
        results = conn.execute(query).fetchall()
    except sqlite3.Error as e:
        return f"<pre>SQL error: {e}</pre>", 500
    conn.close()
    # q is reflected without escaping -> reflected XSS (render_template_string
    # with |safe-equivalent string building).
    html = f"<h2>Results for: {q}</h2><ul>"
    for r in results:
        html += f"<li><b>{r['author']}</b>: {r['body']}</li>"
    html += "</ul><a href='/'>home</a>"
    return html


# ---------- VULN-10: Stored XSS via comments ----------
@app.route("/comments", methods=["GET", "POST"])
def comments():
    conn = db()
    if request.method == "POST":
        author = request.form.get("author", "anon")
        body = request.form.get("body", "")
        conn.execute("INSERT INTO comments(author, body) VALUES (?, ?)", (author, body))
        conn.commit()
    rows = conn.execute("SELECT * FROM comments").fetchall()
    conn.close()
    return render_template("comments.html", comments=rows)


# ---------- VULN-11: Server-Side Template Injection (SSTI) ----------
@app.route("/greet")
def greet():
    name = request.args.get("name", "world")
    # Directly building a Jinja2 template string from user input -> SSTI/RCE.
    template = "<h2>Hello " + name + "!</h2><a href='/'>home</a>"
    return render_template_string(template)


# ---------- VULN-12: Insecure deserialization (pickle) -> RCE ----------
@app.route("/profile/import", methods=["GET", "POST"])
def profile_import():
    if request.method == "POST":
        blob = request.form.get("data", "")
        try:
            obj = pickle.loads(base64.b64decode(blob))  # VULN: untrusted pickle
        except Exception as e:
            return f"Import failed: {e}", 400
        return jsonify({"imported": str(obj)})
    return render_template("upload.html", mode="pickle")


# ---------- VULN-13: OS command injection ----------
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    cmd = "ping -c 1 " + host  # shell metacharacters not sanitized
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
    except Exception as e:
        out = str(e).encode()
    return f"<pre>{out.decode(errors='replace')}</pre>"


# ---------- VULN-14: Path traversal / LFI ----------
@app.route("/download")
def download():
    fname = request.args.get("file", "report.txt")
    path = os.path.join(FILES_DIR, fname)  # no sanitization of ../
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception as e:
        return str(e), 404
    return data, 200, {"Content-Type": "text/plain"}


# ---------- VULN-15: IDOR ----------
@app.route("/api/user/<int:uid>")
def api_user(uid):
    conn = db()
    row = conn.execute("SELECT id, username, email, secret_note FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    # No check that uid == session['uid'] -> any logged-in (or anonymous) user
    # can read anyone else's record, e.g. /api/user/2 for the admin's secret_note.
    return jsonify(dict(row))


# ---------- VULN-16: Mass assignment ----------
@app.route("/api/user/update", methods=["POST"])
def api_user_update():
    if "uid" not in session:
        return jsonify({"error": "login required"}), 401
    data = request.get_json(force=True, silent=True) or {}
    conn = db()
    row = conn.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    merged = dict(row)
    merged.update(data)  # blindly trusts client JSON, including "is_admin"
    conn.execute("UPDATE users SET email=?, is_admin=? WHERE id=?",
                 (merged["email"], int(bool(merged["is_admin"])), session["uid"]))
    conn.commit()
    conn.close()
    return jsonify({"status": "updated", "profile": merged})


# ---------- VULN-17: CSRF (state-changing POST, no token, cookie-based auth) ----------
@app.route("/api/change-email", methods=["POST"])
def change_email():
    if "uid" not in session:
        return jsonify({"error": "login required"}), 401
    new_email = request.form.get("email")
    conn = db()
    conn.execute("UPDATE users SET email=? WHERE id=?", (new_email, session["uid"]))
    conn.commit()
    conn.close()
    return jsonify({"status": "email updated", "email": new_email})


# ---------- VULN-18: JWT "alg=none" / algorithm confusion ----------
def b64url_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


@app.route("/api/token", methods=["POST"])
def api_token():
    u = request.form.get("username", "guest")
    token = jwt.encode({"user": u, "is_admin": False, "iat": int(time.time())}, JWT_SECRET, algorithm="HS256")
    return jsonify({"token": token})


@app.route("/api/admin")
def api_admin():
    auth = request.headers.get("Authorization", "")
    token = auth.replace("Bearer ", "")
    try:
        header = json.loads(b64url_decode(token.split(".")[0]))
        if header.get("alg", "").lower() == "none":
            # VULN: trusts the client-supplied 'alg' header and skips
            # signature verification entirely for alg=none tokens.
            payload = json.loads(b64url_decode(token.split(".")[1]))
        else:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except Exception as e:
        return jsonify({"error": f"invalid token: {e}"}), 401
    if not payload.get("is_admin"):
        return jsonify({"error": "forbidden"}), 403
    return jsonify({"flag": "FLAG{jwt_alg_none_or_weak_secret}", "payload": payload})


# ---------- VULN-19: Unrestricted file upload ----------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        if not f:
            return "no file", 400
        # No extension allow-list, no filename sanitization -> can overwrite
        # arbitrary files with '../' in filename, or drop .html/.svg for
        # stored XSS served from the same origin.
        dest = os.path.join(UPLOAD_DIR, f.filename)
        f.save(dest)
        return jsonify({"status": "saved", "path": f"/static/uploads/{f.filename}"})
    return render_template("upload.html", mode="file")


# ---------- VULN-20: XXE (XML External Entity injection) ----------
@app.route("/api/xml", methods=["POST"])
def api_xml():
    xml_data = request.data
    parser = etree.XMLParser(resolve_entities=True, no_network=False)  # unsafe
    try:
        tree = etree.fromstring(xml_data, parser=parser)
        result = etree.tostring(tree).decode()
    except Exception as e:
        return str(e), 400
    return f"<pre>{result}</pre>"


# ---------- VULN-21: SSRF (incl. cloud-metadata style target) ----------
@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    if not url:
        return "provide ?url=", 400
    try:
        r = requests.get(url, timeout=5)
        body = r.text[:2000]
    except Exception as e:
        body = str(e)
    return f"<pre>{body}</pre>"


# ---------- VULN-22: Open redirect ----------
@app.route("/redirect")
def open_redirect():
    nxt = request.args.get("next", "/")
    return redirect(nxt)  # no allow-list / same-origin check


# ---------- VULN-23: Race condition (TOCTOU) on coupon redemption ----------
@app.route("/api/redeem", methods=["POST"])
def redeem():
    code = request.form.get("code", "")
    conn = db()
    row = conn.execute("SELECT uses_left FROM coupons WHERE code=?", (code,)).fetchone()
    if not row or row["uses_left"] <= 0:
        conn.close()
        return jsonify({"status": "rejected"}), 400
    time.sleep(0.3)  # widen the race window to make it easy to demonstrate
    new_left = row["uses_left"] - 1
    conn.execute("UPDATE coupons SET uses_left=? WHERE code=?", (new_left, code))
    conn.commit()
    conn.close()
    return jsonify({"status": "redeemed", "uses_left": new_left})


# ---------- VULN-24: Web cache poisoning (paired with nginx layer) ----------
@app.route("/welcome")
def welcome():
    host_header = request.headers.get("X-Forwarded-Host", request.host)
    # Reflecting an attacker-controlled header into a cached page -> poisoning.
    return f"""<html><body><h2>Welcome!</h2>
    <p>Reset your password: <a href="https://{host_header}/reset">here</a></p>
    </body></html>"""


# ---------- VULN-25: Debug/info-disclosure endpoint left in "by mistake" ----------
@app.route("/debug")
def debug_info():
    return jsonify({
        "secret_key": app.secret_key,
        "jwt_secret": JWT_SECRET,
        "env": dict(os.environ),
        "note": "This endpoint should never exist in production.",
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

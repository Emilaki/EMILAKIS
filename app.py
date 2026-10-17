#!/usr/bin/env python3
"""EA EarnHub pilot web app. SQLite locally; PostgreSQL when DATABASE_URL is set."""
from flask import Flask, jsonify, make_response, request, send_from_directory
from pathlib import Path
import hashlib, hmac, json, os, re, secrets, sqlite3, time

ROOT = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("EA_ADMIN_TOKEN", "")
MIN_WITHDRAW = 50
DAILY_LIMIT = 500
COOKIE_SECURE = os.environ.get("EA_HTTPS", "0") == "1"
TASKS = [
    {"id":"quiz","title":"Money-smart mini quiz","description":"A short budgeting knowledge check.","reward":10,"minutes":3},
    {"id":"learn","title":"Learn something new","description":"Read a short saving guide and answer a question.","reward":20,"minutes":5},
    {"id":"safety","title":"Online safety basics","description":"Review practical account safety tips.","reward":30,"minutes":5},
]

try:
    import psycopg
    from psycopg.rows import dict_row
except ImportError:
    psycopg = None
    dict_row = None

class Database:
    def __init__(self):
        self.is_pg = bool(DATABASE_URL)
        if self.is_pg:
            if psycopg is None:
                raise RuntimeError("Install requirements.txt to use PostgreSQL.")
            dsn = DATABASE_URL.replace("postgres://", "postgresql://", 1)
            self.conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=True)
        else:
            self.conn = sqlite3.connect(ROOT / "earnhub.sqlite3", timeout=15, isolation_level=None)
            self.conn.row_factory = sqlite3.Row
            self.conn.execute("PRAGMA foreign_keys=ON")
    def execute(self, query, params=()):
        if self.is_pg:
            query = query.replace("?", "%s")
        return self.conn.execute(query, params)
    def close(self):
        self.conn.close()
    def __enter__(self):
        return self
    def __exit__(self, typ, value, traceback):
        self.close()

def db():
    return Database()

def init_db():
    idtype = "BIGSERIAL PRIMARY KEY" if DATABASE_URL else "INTEGER PRIMARY KEY AUTOINCREMENT"
    blobtype = "BYTEA" if DATABASE_URL else "BLOB"
    schema = [
        f"CREATE TABLE IF NOT EXISTS users(id {idtype}, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt {blobtype} NOT NULL, password_hash {blobtype} NOT NULL, refcode TEXT UNIQUE NOT NULL, referred_by BIGINT REFERENCES users(id), created BIGINT NOT NULL)",
        f"CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires BIGINT NOT NULL)",
        f"CREATE TABLE IF NOT EXISTS ledger(id {idtype}, user_id BIGINT NOT NULL REFERENCES users(id), amount INTEGER NOT NULL, kind TEXT NOT NULL, note TEXT NOT NULL, created BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS claims(user_id BIGINT NOT NULL REFERENCES users(id), task_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created BIGINT NOT NULL, updated BIGINT NOT NULL, PRIMARY KEY(user_id,task_id))",
        f"CREATE TABLE IF NOT EXISTS payouts(id {idtype}, user_id BIGINT NOT NULL REFERENCES users(id), amount INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'queued', created BIGINT NOT NULL, updated BIGINT NOT NULL)",
        "CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value BIGINT NOT NULL)",
        "INSERT INTO settings(key,value) VALUES('reward_pool',0) ON CONFLICT(key) DO NOTHING",
        "CREATE INDEX IF NOT EXISTS ledger_user_idx ON ledger(user_id,id)",
        "CREATE INDEX IF NOT EXISTS payouts_user_created_idx ON payouts(user_id,created)",
    ]
    with db() as c:
        for statement in schema:
            c.execute(statement)
        c.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))

def digest(token):
    return hashlib.sha256(token.encode()).hexdigest()

def balance(c, uid):
    row=c.execute("SELECT COALESCE(SUM(amount),0) AS b FROM ledger WHERE user_id=?",(uid,)).fetchone()
    return int(row["b"])

def reward_pool(c):
    return int(c.execute("SELECT value FROM settings WHERE key='reward_pool'").fetchone()["value"])

def add_ledger(c, uid, amount, kind, note):
    c.execute("INSERT INTO ledger(user_id,amount,kind,note,created) VALUES(?,?,?,?,?)",(uid,amount,kind,note,int(time.time())))

def current_user(c):
    raw=request.cookies.get("session","")
    if not re.fullmatch(r"[a-f0-9]{64}",raw):
        return None
    row=c.execute("SELECT u.id,u.name,u.email,u.refcode FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?",(digest(raw),int(time.time()))).fetchone()
    return dict(row) if row else None

def require_user(c):
    u=current_user(c)
    if not u: raise ValueError("Sign in to continue.")
    return u

def require_admin():
    if not ADMIN_TOKEN: raise PermissionError("Admin access is not configured. Set EA_ADMIN_TOKEN.")
    if not hmac.compare_digest(request.headers.get("X-Admin-Token",""),ADMIN_TOKEN):
        raise PermissionError("Admin key is not valid.")

def daily_withdrawn(c,uid):
    since=int(time.time())-86400
    row=c.execute("SELECT COALESCE(SUM(amount),0) AS n FROM payouts WHERE user_id=? AND created>=? AND status!='cancelled'",(uid,since)).fetchone()
    return int(row["n"])

def payload():
    return request.get_json(silent=True) or {}

app=Flask(__name__)

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="same-origin"
    response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"]="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response

@app.get("/")
@app.get("/index.html")
def home():
    return send_from_directory(ROOT,"index.html",max_age=0)

@app.get("/api/health")
def health():
    return jsonify(status="pilot",payments="disabled",adminConfigured=bool(ADMIN_TOKEN))

@app.get("/api/me")
def me():
    with db() as c:
        u=current_user(c)
        if not u: return jsonify(user=None)
        return jsonify(user=u,balance=balance(c,u["id"]),dailyWithdrawn=daily_withdrawn(c,u["id"]),minWithdraw=MIN_WITHDRAW,dailyLimit=DAILY_LIMIT)

@app.get("/api/tasks")
def tasks():
    with db() as c:
        u=current_user(c)
        claims={r["task_id"]:r["status"] for r in c.execute("SELECT task_id,status FROM claims WHERE user_id=?",(u["id"],)).fetchall()} if u else {}
        pool=reward_pool(c)
        return jsonify(tasks=[dict(t,completed=claims.get(t["id"])=="approved",pending=claims.get(t["id"])=="pending",funded=pool>=t["reward"]) for t in TASKS],paymentsEnabled=False)

@app.get("/api/activity")
def activity():
    with db() as c:
        u=require_user(c)
        rows=c.execute("SELECT note,amount,created,kind FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 8",(u["id"],)).fetchall()
        return jsonify(items=[dict(r) for r in rows])

@app.get("/api/admin/overview")
def admin_overview():
    require_admin()
    with db() as c:
        payouts=c.execute("SELECT p.id,p.amount,p.status,p.created,u.name,u.email FROM payouts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 50").fetchall()
        claims=c.execute("SELECT cl.user_id,cl.task_id,cl.created,u.name,u.email FROM claims cl JOIN users u ON u.id=cl.user_id WHERE cl.status='pending' ORDER BY cl.created LIMIT 50").fetchall()
        users=c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        return jsonify(rewardPool=reward_pool(c),users=users,payouts=[dict(r) for r in payouts],claims=[dict(r) for r in claims],tasks=TASKS,paymentsEnabled=False)

@app.post("/api/signup")
def signup():
    data=payload()
    name=str(data.get("name","")).strip()[:60]
    email=str(data.get("email","")).strip().lower()[:254]
    password=str(data.get("password",""))
    if len(name)<2 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+",email):
        return jsonify(error="Enter your name and a valid email address."),400
    if len(password)<10:
        return jsonify(error="Use a password with at least 10 characters."),400
    token=secrets.token_hex(32)
    try:
        with db() as c:
            c.execute("BEGIN")
            referral=str(data.get("referral","")).strip().upper()
            referrer=c.execute("SELECT id FROM users WHERE refcode=?",(referral,)).fetchone() if referral else None
            salt=secrets.token_bytes(16)
            ph=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,310000)
            refcode="EA"+secrets.token_hex(4).upper()
            cur=c.execute("INSERT INTO users(name,email,salt,password_hash,refcode,referred_by,created) VALUES(?,?,?,?,?,?,?) RETURNING id",(name,email,salt,ph,refcode,referrer["id"] if referrer else None,int(time.time())))
            uid=cur.fetchone()["id"]
            if reward_pool(c)>=10:
                c.execute("UPDATE settings SET value=value-10 WHERE key='reward_pool'")
                add_ledger(c,uid,10,"welcome","Welcome credit")
            c.execute("INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)",(digest(token),uid,int(time.time())+604800))
            c.execute("COMMIT")
            credited=balance(c,uid)>=10
        response=make_response(jsonify(user={"id":uid,"name":name,"email":email,"refcode":refcode},balance=balance_after(uid),welcomeFunded=credited),201)
        set_cookie(response,token)
        return response
    except Exception as exc:
        return db_error(exc)

def balance_after(uid):
    with db() as c: return balance(c,uid)

@app.post("/api/login")
def login():
    data=payload()
    email=str(data.get("email","")).strip().lower()
    with db() as c:
        row=c.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        salt=row["salt"] if row else b"\0"*16
        expected=row["password_hash"] if row else b"\0"*32
        candidate=hashlib.pbkdf2_hmac("sha256",str(data.get("password","")).encode(),salt,310000)
        if not row or not hmac.compare_digest(candidate,expected):
            return jsonify(error="Email or password is incorrect."),401
        token=secrets.token_hex(32)
        c.execute("INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)",(digest(token),row["id"],int(time.time())+604800))
        response=make_response(jsonify(user={"id":row["id"],"name":row["name"],"email":row["email"],"refcode":row["refcode"]},balance=balance(c,row["id"])))
        set_cookie(response,token)
        return response

@app.post("/api/logout")
def logout():
    raw=request.cookies.get("session","")
    if re.fullmatch(r"[a-f0-9]{64}",raw):
        with db() as c: c.execute("DELETE FROM sessions WHERE token_hash=?",(digest(raw),))
    response=make_response(jsonify(ok=True))
    response.set_cookie("session","",max_age=0,httponly=True,secure=COOKIE_SECURE,samesite="Strict",path="/")
    return response

def set_cookie(response,token):
    response.set_cookie("session",token,max_age=604800,httponly=True,secure=COOKIE_SECURE,samesite="Strict",path="/")

@app.post("/api/tasks/complete")
def complete_task():
    data=payload()
    tid=str(data.get("taskId",""))
    task=next((t for t in TASKS if t["id"]==tid),None)
    if not task: return jsonify(error="Activity not found."),404
    try:
        with db() as c:
            u=require_user(c)
            c.execute("BEGIN")
            if c.execute("SELECT 1 FROM claims WHERE user_id=? AND task_id=?",(u["id"],tid)).fetchone():
                c.execute("ROLLBACK")
                return jsonify(error="This activity already has a pending or final review."),400
            now=int(time.time())
            c.execute("INSERT INTO claims(user_id,task_id,status,created,updated) VALUES(?,?,'pending',?,?)",(u["id"],tid,now,now))
            c.execute("COMMIT")
            return jsonify(ok=True,status="pending",message="Activity submitted for review. Credits are added only after approval."),202
    except Exception as exc: return db_error(exc)

@app.post("/api/withdraw")
def withdraw():
    data=payload()
    amount=data.get("amount")
    if not isinstance(amount,int) or amount<MIN_WITHDRAW: return jsonify(error="Minimum withdrawal is KSh 50."),400
    if amount>DAILY_LIMIT: return jsonify(error="Maximum withdrawal is KSh 500 per day."),400
    try:
        with db() as c:
            u=require_user(c)
            c.execute("BEGIN")
            used=daily_withdrawn(c,u["id"])
            if used+amount>DAILY_LIMIT:
                c.execute("ROLLBACK")
                return jsonify(error="This request would exceed your KSh 500 daily limit."),400
            if balance(c,u["id"])<amount:
                c.execute("ROLLBACK")
                return jsonify(error="Your confirmed balance is too low."),400
            now=int(time.time())
            cur=c.execute("INSERT INTO payouts(user_id,amount,status,created,updated) VALUES(?,?,'queued',?,?) RETURNING id",(u["id"],amount,now,now))
            payout_id=cur.fetchone()["id"]
            add_ledger(c,u["id"],-amount,"withdrawal","Withdrawal request #"+str(payout_id))
            c.execute("COMMIT")
            return jsonify(ok=True,status="queued",message="Request queued for review. No money has been sent."),201
    except Exception as exc: return db_error(exc)

@app.post("/api/admin/fund")
def admin_fund():
    require_admin()
    amount=payload().get("amount")
    if not isinstance(amount,int) or amount<1 or amount>100000000:
        return jsonify(error="Enter a valid whole KSh funding amount."),400
    with db() as c:
        c.execute("UPDATE settings SET value=value+? WHERE key='reward_pool'",(amount,))
        return jsonify(ok=True,rewardPool=reward_pool(c))

@app.post("/api/admin/claim")
def admin_claim():
    require_admin()
    data=payload()
    uid=data.get("userId"); tid=str(data.get("taskId","")); status=data.get("status")
    if status not in ("approved","rejected"): return jsonify(error="Choose approved or rejected."),400
    task=next((t for t in TASKS if t["id"]==tid),None)
    if not task: return jsonify(error="Activity not found."),400
    try:
        with db() as c:
            c.execute("BEGIN")
            cl=c.execute("SELECT * FROM claims WHERE user_id=? AND task_id=?",(uid,tid)).fetchone()
            if not cl or cl["status"]!="pending":
                c.execute("ROLLBACK"); return jsonify(error="Pending activity claim not found."),400
            if status=="approved":
                if reward_pool(c)<task["reward"]:
                    c.execute("ROLLBACK"); return jsonify(error="Reward reserve is too low to approve this activity."),400
                c.execute("UPDATE settings SET value=value-? WHERE key='reward_pool'",(task["reward"],))
                add_ledger(c,uid,task["reward"],"activity",task["title"])
                referred=c.execute("SELECT referred_by FROM users WHERE id=?",(uid,)).fetchone()["referred_by"]
                prior=c.execute("SELECT COUNT(*) AS n FROM claims WHERE user_id=? AND status='approved'",(uid,)).fetchone()["n"]
                if referred and prior==0 and reward_pool(c)>=5:
                    c.execute("UPDATE settings SET value=value-5 WHERE key='reward_pool'")
                    add_ledger(c,referred,5,"referral","Verified referral activity")
            c.execute("UPDATE claims SET status=?,updated=? WHERE user_id=? AND task_id=?",(status,int(time.time()),uid,tid))
            c.execute("COMMIT")
            return jsonify(ok=True,status=status)
    except Exception as exc: return db_error(exc)

@app.post("/api/admin/payout")
def admin_payout():
    require_admin()
    data=payload(); pid=data.get("id"); status=data.get("status")
    if status not in ("paid","cancelled"): return jsonify(error="Choose paid or cancelled."),400
    try:
        with db() as c:
            c.execute("BEGIN")
            p=c.execute("SELECT * FROM payouts WHERE id=?",(pid,)).fetchone()
            if not p or p["status"]!="queued":
                c.execute("ROLLBACK"); return jsonify(error="Queued payout not found."),400
            c.execute("UPDATE payouts SET status=?,updated=? WHERE id=?",(status,int(time.time()),pid))
            if status=="cancelled": add_ledger(c,p["user_id"],p["amount"],"refund","Cancelled withdrawal request #"+str(pid))
            c.execute("COMMIT")
            return jsonify(ok=True,status=status)
    except Exception as exc: return db_error(exc)

@app.errorhandler(PermissionError)
def permission_error(exc):
    return jsonify(error=str(exc)),403

@app.errorhandler(ValueError)
def value_error(exc):
    return jsonify(error=str(exc)),401

@app.errorhandler(404)
def not_found(exc):
    if request.path.startswith("/api/"): return jsonify(error="Not found."),404
    return exc

def db_error(exc):
    try:
        with db() as c: c.execute("ROLLBACK")
    except Exception: pass
    try:
        from psycopg import IntegrityError
        if isinstance(exc,IntegrityError): return jsonify(error="That email is already registered or the request conflicts with existing data."),409
    except ImportError: pass
    if isinstance(exc,sqlite3.IntegrityError):
        return jsonify(error="That email is already registered or the request conflicts with existing data."),409
    app.logger.exception("Request failed")
    return jsonify(error="Request could not be completed."),500

if __name__ == "__main__":
    init_db()
    app.run(host=os.environ.get("EA_HOST","127.0.0.1"),port=int(os.environ.get("PORT",os.environ.get("EA_PORT","8000"))))


# Render starts this module through Gunicorn, which does not run the __main__ block.
# Initialize the persistent schema when a WSGI server imports this module.
if __name__ != "__main__":
    init_db()

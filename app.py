#!/usr/bin/env python3
"""EA EarnHub pilot web app. SQLite locally; PostgreSQL when DATABASE_URL is set."""
from flask import Flask, jsonify, make_response, request, send_from_directory
from pathlib import Path
import hashlib, hmac, json, os, re, secrets, sqlite3, time
from urllib.parse import urlparse
import requests

ROOT = Path(__file__).resolve().parent
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("EA_ADMIN_TOKEN", "")
MIN_WITHDRAW = 50
DAILY_LIMIT = 500
COOKIE_SECURE = os.environ.get("EA_HTTPS", "0") == "1"
MPESA_ENV = os.environ.get("MPESA_ENV", "sandbox").strip().lower()
MPESA_B2C_ENABLED = os.environ.get("MPESA_B2C_ENABLED", "false").strip().lower() == "true"
MPESA_CONSUMER_KEY = os.environ.get("MPESA_CONSUMER_KEY", "").strip()
MPESA_CONSUMER_SECRET = os.environ.get("MPESA_CONSUMER_SECRET", "").strip()
MPESA_B2C_SHORTCODE = os.environ.get("MPESA_B2C_SHORTCODE", "").strip()
MPESA_INITIATOR_NAME = os.environ.get("MPESA_INITIATOR_NAME", "").strip()
MPESA_SECURITY_CREDENTIAL = (os.environ.get("MPESA_SECURITY_CREDENTIAL") or os.environ.get("MPESA_B2C_SECURITY_CREDENTIAL") or "").strip()
# Deliberately fixed to Safaricom's sandbox: this starter cannot send live money.
MPESA_SANDBOX_URL = "https://sandbox.safaricom.co.ke"
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
        if c.is_pg:
            for column in ("msisdn", "originator_id", "conversation_id", "transaction_id", "result_code", "result_desc"):
                c.execute(f"ALTER TABLE payouts ADD COLUMN IF NOT EXISTS {column} TEXT")
        else:
            existing={r["name"] for r in c.execute("PRAGMA table_info(payouts)").fetchall()}
            for column in ("msisdn", "originator_id", "conversation_id", "transaction_id", "result_code", "result_desc"):
                if column not in existing:
                    c.execute(f"ALTER TABLE payouts ADD COLUMN {column} TEXT")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS payouts_originator_idx ON payouts(originator_id)")
        c.execute("DELETE FROM sessions WHERE expires < ?", (int(time.time()),))

def mpesa_sandbox_ready():
    base=os.environ.get("MPESA_PUBLIC_BASE_URL", os.environ.get("RENDER_EXTERNAL_URL", "")).strip().rstrip("/")
    parsed=urlparse(base)
    return bool(
        MPESA_B2C_ENABLED and MPESA_ENV == "sandbox" and MPESA_CONSUMER_KEY and
        MPESA_CONSUMER_SECRET and MPESA_B2C_SHORTCODE and MPESA_INITIATOR_NAME and
        MPESA_SECURITY_CREDENTIAL and parsed.scheme == "https" and parsed.netloc
    )

def normalize_msisdn(value):
    digits=re.sub(r"[\s()+-]", "", str(value or ""))
    if digits.startswith("0") and len(digits)==10:
        digits="254"+digits[1:]
    elif digits.startswith("7") or digits.startswith("1"):
        if len(digits)==9: digits="254"+digits
    if not re.fullmatch(r"254[17]\d{8}",digits):
        raise ValueError("Enter a valid Kenyan M-Pesa number, for example 07XXXXXXXX or 2547XXXXXXXX.")
    return digits

def mpesa_request(payout_id, msisdn, amount, originator_id):
    """Send one explicitly admin-triggered B2C request to sandbox only."""
    auth=requests.get(
        MPESA_SANDBOX_URL+"/oauth/v1/generate?grant_type=client_credentials",
        auth=(MPESA_CONSUMER_KEY,MPESA_CONSUMER_SECRET), timeout=(5,20), allow_redirects=False,
    )
    auth.raise_for_status()
    access_token=auth.json().get("access_token")
    if not access_token:
        raise RuntimeError("Daraja did not return an access token.")
    public_base=os.environ.get("MPESA_PUBLIC_BASE_URL",os.environ.get("RENDER_EXTERNAL_URL","")).strip().rstrip("/")
    if urlparse(public_base).scheme != "https":
        raise RuntimeError("Set MPESA_PUBLIC_BASE_URL to the public HTTPS website URL.")
    body={
        "InitiatorName":MPESA_INITIATOR_NAME,
        "SecurityCredential":MPESA_SECURITY_CREDENTIAL,
        "CommandID":"BusinessPayment",
        "Amount":int(amount),
        "PartyA":MPESA_B2C_SHORTCODE,
        "PartyB":msisdn,
        "Remarks":f"EA EarnHub payout {payout_id}",
        "QueueTimeOutURL":public_base+"/api/mpesa/b2c/timeout",
        "ResultURL":public_base+"/api/mpesa/b2c/result",
        "Occassion":"EA EarnHub sandbox",
        "OriginatorConversationID":originator_id,
    }
    return requests.post(
        MPESA_SANDBOX_URL+"/mpesa/b2c/v3/paymentrequest", json=body,
        headers={"Authorization":"Bearer "+access_token,"Content-Type":"application/json"},
        timeout=(5,25), allow_redirects=False,
    )

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
app.config["MAX_CONTENT_LENGTH"]=64*1024

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
    return jsonify(status="pilot",payments="sandbox-only" if mpesa_sandbox_ready() else "disabled",adminConfigured=bool(ADMIN_TOKEN))

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
        payouts=c.execute("SELECT p.id,p.amount,p.status,p.created,p.msisdn,p.transaction_id,p.result_desc,u.name,u.email FROM payouts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 50").fetchall()
        claims=c.execute("SELECT cl.user_id,cl.task_id,cl.created,u.name,u.email FROM claims cl JOIN users u ON u.id=cl.user_id WHERE cl.status='pending' ORDER BY cl.created LIMIT 50").fetchall()
        users=c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        return jsonify(rewardPool=reward_pool(c),users=users,payouts=[dict(r) for r in payouts],claims=[dict(r) for r in claims],tasks=TASKS,paymentsEnabled=mpesa_sandbox_ready(),mpesaMode="sandbox" if mpesa_sandbox_ready() else "disabled")

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
    try: msisdn=normalize_msisdn(data.get("phone"))
    except ValueError as exc: return jsonify(error=str(exc)),400
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
            cur=c.execute("INSERT INTO payouts(user_id,amount,status,created,updated,msisdn) VALUES(?,?,'queued',?,?,?) RETURNING id",(u["id"],amount,now,now,msisdn))
            payout_id=cur.fetchone()["id"]
            add_ledger(c,u["id"],-amount,"withdrawal","Withdrawal request #"+str(payout_id))
            c.execute("COMMIT")
            return jsonify(ok=True,status="queued",message="Request queued for operator review. A sandbox test, if enabled, does not move real money."),201
    except Exception as exc: return db_error(exc)

@app.post("/api/admin/payout/send-sandbox")
def admin_send_sandbox_payout():
    require_admin()
    if not mpesa_sandbox_ready():
        return jsonify(error="Sandbox payouts are disabled or incomplete. Check the Daraja sandbox settings and HTTPS callback URL."),503
    pid=payload().get("id")
    try: pid=int(pid)
    except (TypeError,ValueError): return jsonify(error="Invalid payout request."),400
    originator_id=secrets.token_urlsafe(24)
    try:
        with db() as c:
            c.execute("BEGIN")
            cur=c.execute("UPDATE payouts SET status='initiating',originator_id=?,updated=? WHERE id=? AND status='queued' AND msisdn IS NOT NULL",(originator_id,int(time.time()),pid))
            if cur.rowcount != 1:
                c.execute("ROLLBACK")
                return jsonify(error="Queued payout not found, phone number missing, or payout already submitted."),409
            payout=c.execute("SELECT amount,msisdn,user_id FROM payouts WHERE id=?",(pid,)).fetchone()
            c.execute("COMMIT")
        try:
            response=mpesa_request(pid,payout["msisdn"],payout["amount"],originator_id)
            try: result=response.json()
            except ValueError: result={}
            if response.status_code >= 500 or not isinstance(result,dict) or "ResponseCode" not in result:
                with db() as c: c.execute("UPDATE payouts SET status='unknown',updated=?,result_desc=? WHERE id=? AND status='initiating'",(int(time.time()),"Daraja response was inconclusive; reconcile in the Daraja simulator before retrying.",pid))
                return jsonify(ok=True,status="unknown",message="Daraja's response was inconclusive. Do not resend until you reconcile the request in the Daraja portal."),202
            if response.status_code >= 400 or str(result.get("ResponseCode")) != "0":
                desc=str(result.get("errorMessage") or result.get("ResponseDescription") or "Daraja rejected the sandbox request.")[:240]
                with db() as c:
                    c.execute("BEGIN")
                    cur=c.execute("UPDATE payouts SET status='failed',updated=?,result_desc=? WHERE id=? AND status='initiating'",(int(time.time()),desc,pid))
                    if cur.rowcount:
                        add_ledger(c, payout["user_id"], payout["amount"], "refund", "Sandbox payout request rejected")
                    c.execute("COMMIT")
                return jsonify(error="Daraja rejected the sandbox request. The reserved balance was refunded."),502
            conversation=str(result.get("ConversationID") or "")[:120]
            desc=str(result.get("ResponseDescription") or "Request accepted by Daraja sandbox; awaiting callback.")[:240]
            with db() as c:
                c.execute("UPDATE payouts SET status='pending',conversation_id=?,updated=?,result_desc=? WHERE id=? AND status='initiating'",(conversation,int(time.time()),desc,pid))
            return jsonify(ok=True,status="pending",message="Sandbox request accepted. Waiting for Safaricom's result callback; this is not a real payout."),202
        except requests.Timeout:
            with db() as c: c.execute("UPDATE payouts SET status='unknown',updated=?,result_desc=? WHERE id=? AND status='initiating'",(int(time.time()),"Network timeout after request; reconcile in the Daraja portal before retrying.",pid))
            return jsonify(ok=True,status="unknown",message="The request timed out and may have reached Daraja. Reconcile it in the portal before any retry."),202
        except requests.RequestException:
            with db() as c: c.execute("UPDATE payouts SET status='unknown',updated=?,result_desc=? WHERE id=? AND status='initiating'",(int(time.time()),"Network result was inconclusive; reconcile in the Daraja portal before retrying.",pid))
            return jsonify(ok=True,status="unknown",message="The network result is uncertain. Reconcile in the Daraja portal before retrying."),202
        except Exception as exc:
            app.logger.warning("Sandbox payout %s could not be processed: %s",pid,type(exc).__name__)
            with db() as c: c.execute("UPDATE payouts SET status='unknown',updated=?,result_desc=? WHERE id=? AND status='initiating'",(int(time.time()),"Processing result is uncertain; reconcile in the Daraja portal before retrying.",pid))
            return jsonify(ok=True,status="unknown",message="The request result is uncertain. Reconcile it in the Daraja portal before retrying."),202
    except Exception as exc: return db_error(exc)

def settle_mpesa_callback(data, timed_out=False):
    result=data.get("Result") if isinstance(data,dict) else None
    if not isinstance(result,dict): return False
    originator=str(result.get("OriginatorConversationID") or "")[:120]
    if not originator: return False
    now=int(time.time())
    with db() as c:
        c.execute("BEGIN")
        payout=c.execute("SELECT id,user_id,amount,status FROM payouts WHERE originator_id=?",(originator,)).fetchone()
        if not payout or payout["status"] not in ("initiating","pending","unknown"):
            c.execute("ROLLBACK")
            return False
        if timed_out:
            status="unknown"
            code="timeout"
            desc="Daraja reported a queue timeout. Reconcile before retrying."
        else:
            code=str(result.get("ResultCode", "unknown"))[:50]
            desc=str(result.get("ResultDesc") or "Daraja returned a transaction result.")[:240]
            status="paid" if code=="0" else "failed"
        transaction_id=""
        params=result.get("ResultParameters",{}).get("ResultParameter",[]) if isinstance(result.get("ResultParameters"),dict) else []
        if isinstance(params,list):
            transaction_id=next((str(item.get("Value"))[:120] for item in params if isinstance(item,dict) and item.get("Key")=="TransactionReceipt" and item.get("Value")),"")
        cur=c.execute("UPDATE payouts SET status=?,result_code=?,result_desc=?,transaction_id=?,conversation_id=COALESCE(NULLIF(?,''),conversation_id),updated=? WHERE id=? AND status IN ('initiating','pending','unknown')",(status,code,desc,transaction_id,str(result.get("ConversationID") or "")[:120],now,payout["id"]))
        if cur.rowcount and status=="failed":
            add_ledger(c,payout["user_id"],payout["amount"],"refund","M-Pesa payout failed; withdrawal refunded")
        c.execute("COMMIT")
        return bool(cur.rowcount)

@app.post("/api/mpesa/b2c/result")
def mpesa_b2c_result():
    accepted=settle_mpesa_callback(request.get_json(silent=True) or {})
    # Acknowledge callbacks even if they are duplicates or unmatched; no PII is returned.
    return jsonify(ok=accepted),200

@app.post("/api/mpesa/b2c/timeout")
def mpesa_b2c_timeout():
    accepted=settle_mpesa_callback(request.get_json(silent=True) or {},timed_out=True)
    return jsonify(ok=accepted),200

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
    if status != "cancelled": return jsonify(error="A payout can only be marked paid by a successful Daraja result callback."),400
    try:
        with db() as c:
            c.execute("BEGIN")
            p=c.execute("SELECT * FROM payouts WHERE id=?",(pid,)).fetchone()
            if not p or p["status"]!="queued":
                c.execute("ROLLBACK"); return jsonify(error="Queued payout not found."),400
            c.execute("UPDATE payouts SET status=?,updated=? WHERE id=?",(status,int(time.time()),pid))
            add_ledger(c,p["user_id"],p["amount"],"refund","Cancelled withdrawal request #"+str(pid))
            c.execute("COMMIT")
            return jsonify(ok=True,status=status)
    except Exception as exc: return db_error(exc)

@app.post("/api/admin/payout/reconcile")
def admin_reconcile_sandbox_payout():
    require_admin()
    data=payload(); pid=data.get("id"); outcome=data.get("outcome")
    if outcome not in ("paid","failed"):
        return jsonify(error="Choose the confirmed Daraja sandbox result: paid or failed."),400
    try:
        with db() as c:
            c.execute("BEGIN")
            p=c.execute("SELECT * FROM payouts WHERE id=?",(pid,)).fetchone()
            if not p or p["status"] not in ("unknown","pending"):
                c.execute("ROLLBACK"); return jsonify(error="Only an unresolved Daraja sandbox request can be reconciled."),409
            code="manual-confirmed-success" if outcome=="paid" else "manual-confirmed-failure"
            desc="Operator reconciled against the Daraja sandbox simulator."
            cur=c.execute("UPDATE payouts SET status=?,result_code=?,result_desc=?,updated=? WHERE id=? AND status IN ('unknown','pending')",(outcome,code,desc,int(time.time()),pid))
            if cur.rowcount and outcome=="failed":
                add_ledger(c,p["user_id"],p["amount"],"refund","Daraja sandbox failure confirmed; withdrawal refunded")
            c.execute("COMMIT")
            return jsonify(ok=True,status=outcome)
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

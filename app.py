import os, re, secrets, hashlib, sqlite3, random, time, hmac, requests
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = os.getenv("SECRET_KEY", "dev-only-change-this-secret-key-before-deploying")
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "false").lower() == "true"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "el_brusto.db")

BREVO_API_KEY = os.getenv("BREVO_API_KEY", "").strip()
BREVO_FROM = os.getenv("BREVO_FROM", "").strip()
BREVO_FROM_NAME = os.getenv("BREVO_FROM_NAME", "EL BRUSTO").strip()
TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM = os.getenv("TWILIO_FROM_NUMBER", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
print("Brevo API key configured:", bool(BREVO_API_KEY))
print("Brevo sender configured:", bool(BREVO_FROM))
OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
DEV_SHOW_OTP = os.getenv("DEV_SHOW_OTP", "false").lower() == "true"

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.teardown_appcontext
def close_db(exception=None):
    conn = g.pop("db", None)
    if conn:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        age INTEGER NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT NOT NULL UNIQUE,
        address TEXT NOT NULL,
        postal_code TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        email_verified INTEGER NOT NULL DEFAULT 0,
        phone_verified INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS registration_otps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        token TEXT NOT NULL UNIQUE,
        payload_json TEXT NOT NULL,
        email_hash TEXT NOT NULL,
        phone_hash TEXT NOT NULL,
        email_otp_hash TEXT NOT NULL,
        phone_otp_hash TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS cart_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        image TEXT NOT NULL,
        quantity INTEGER NOT NULL DEFAULT 1,
        UNIQUE(user_id, name),
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        address TEXT NOT NULL,
        postal_code TEXT NOT NULL,
        phone TEXT NOT NULL,
        note TEXT,
        total REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'Pending',
        created_at TEXT NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS order_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        quantity INTEGER NOT NULL,
        subtotal REAL NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        stock INTEGER NOT NULL DEFAULT 0,
        updated_at TEXT NOT NULL
    );
    """)
    # Add delivery-tracking columns to existing databases without deleting old orders.
    order_columns = {row[1] for row in conn.execute("PRAGMA table_info(orders)").fetchall()}
    for column, definition in (
        ("delivery_date", "TEXT"),
        ("delivery_time", "TEXT"),
        ("admin_note", "TEXT"),
        ("updated_at", "TEXT"),
        ("payment_method", "TEXT NOT NULL DEFAULT 'Cash on Delivery'"),
    ):
        if column not in order_columns:
            conn.execute(f"ALTER TABLE orders ADD COLUMN {column} {definition}")
    # Start stock at zero; the owner enters the real count in the admin inventory screen.
    for item_name in ("SILLA CHICKEN", "GOREO PORK", "JOSEON SPICY BEEF",
                      "STRAWBERRY 16oz", "STRAWBERRY 22oz", "BLUEBERRY 16oz",
                      "BLUEBERRY 22oz", "GREEN APPLE 16oz", "GREEN APPLE 22oz",
                      "SILLA CHICKEN COMBO", "GOREO PORK COMBO", "JOSEON SPICY BEEF COMBO"):
        conn.execute("INSERT OR IGNORE INTO inventory(name,stock,updated_at) VALUES(?,0,?)", (item_name, datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()

def now():
    return datetime.utcnow()

def normalize_phone(phone):
    p = re.sub(r"\D", "", str(phone or ""))
    if p.startswith("09") and len(p) == 11:
        return "+63" + p[1:]
    if p.startswith("63") and len(p) == 12:
        return "+" + p
    if p.startswith("+63") and len(p) == 13:
        return p
    return None

def hash_otp(code):
    return hashlib.sha256(code.encode()).hexdigest()

def make_otp():
    return f"{secrets.randbelow(1000000):06d}"

def mask_email(email):
    name, domain = email.split("@", 1)
    return (name[:2] + "***" if len(name) > 2 else "***") + "@" + domain

def mask_phone(phone):
    digits = re.sub(r"\D", "", phone)
    return digits[:2] + "******" + digits[-2:]


def send_email_otp(to_email, code):
    """Send an OTP email using the Brevo transactional email API."""
    if not BREVO_API_KEY:
        raise RuntimeError("Brevo is not configured. Set BREVO_API_KEY in the environment.")
    if not BREVO_FROM:
        raise RuntimeError("Brevo sender is not configured. Set BREVO_FROM in the environment.")

    response = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={
            "api-key": BREVO_API_KEY,
            "accept": "application/json",
            "content-type": "application/json",
        },
        json={
            "sender": {"name": BREVO_FROM_NAME, "email": BREVO_FROM},
            "to": [{"email": to_email}],
            "subject": "EL BRUSTO - Account Verification OTP",
            "textContent": (
                f"Your EL BRUSTO verification code is: {code}\n\n"
                f"This code expires in {OTP_EXPIRY_MINUTES} minutes. "
                "Do not share it with anyone."
            ),
        },
        timeout=20,
    )

    if not response.ok:
        # Log provider details on the server only; never expose API credentials to the client.
        app.logger.error("Brevo API failed (%s): %s", response.status_code, response.text[:1000])
        raise RuntimeError(f"Brevo API request failed with HTTP {response.status_code}.")


def send_sms_otp(to_phone, code):
    if not all([TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM]):
        raise RuntimeError("SMS OTP is not configured. Set Twilio credentials in .env.")
    from twilio.rest import Client
    Client(TWILIO_SID, TWILIO_TOKEN).messages.create(
        body=f"EL BRUSTO verification code: {code}. Expires in {OTP_EXPIRY_MINUTES} minutes.",
        from_=TWILIO_FROM,
        to=to_phone
    )

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return jsonify(error="LOGIN_REQUIRED"), 401
        return fn(*args, **kwargs)
    return wrapped

@app.route("/")
def index():
    return render_template("index.html")

@app.post("/api/register/start")
def register_start():
    data = request.get_json(force=True)
    required = ["first_name","last_name","age","email","phone","address","postal_code","password","confirm_password"]
    if any(not str(data.get(k, "")).strip() for k in required):
        return jsonify(error="Please complete all registration fields."), 400
    if data["password"] != data["confirm_password"]:
        return jsonify(error="Passwords do not match."), 400
    if len(data["password"]) < 8:
        return jsonify(error="Password must be at least 8 characters."), 400
    try:
        age = int(data["age"])
    except ValueError:
        return jsonify(error="Age must be a number."), 400
    if age < 1 or age > 120:
        return jsonify(error="Please enter a valid age."), 400

    email = str(data["email"]).strip().lower()
    phone = normalize_phone(data["phone"])
    if not phone:
        return jsonify(error="Enter a valid Philippine mobile number such as 09XXXXXXXXX."), 400

    conn = db()
    if conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
        return jsonify(error="An account with that email already exists."), 400
    if conn.execute("SELECT id FROM users WHERE phone=?", (phone,)).fetchone():
        return jsonify(error="An account with that phone number already exists."), 400

    email_otp, phone_otp = make_otp(), make_otp()
    token = secrets.token_urlsafe(32)
    payload = {
        "first_name": str(data["first_name"]).strip(),
        "last_name": str(data["last_name"]).strip(),
        "age": age,
        "email": email,
        "phone": phone,
        "address": str(data["address"]).strip(),
        "postal_code": str(data["postal_code"]).strip(),
        "password_hash": generate_password_hash(data["password"])
    }
    expires = now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    conn.execute("DELETE FROM registration_otps WHERE expires_at < ?", (now().isoformat(),))
    conn.execute(
        """INSERT INTO registration_otps
        (token,payload_json,email_hash,phone_hash,email_otp_hash,phone_otp_hash,expires_at,created_at)
        VALUES (?,?,?,?,?,?,?,?)""",
        (token, __import__("json").dumps(payload), hash_otp(email), hash_otp(phone),
         hash_otp(email_otp), hash_otp(phone_otp), expires.isoformat(), now().isoformat())
    )
    conn.commit()

    send_error = None
    try:
        send_email_otp(email, email_otp)
    except Exception:
        app.logger.exception("Brevo OTP delivery failed")
        send_error = "OTP email could not be sent. Check BREVO_API_KEY and BREVO_FROM in Render Environment, then try again."

    response = {"token": token, "masked_email": mask_email(email)}
    if send_error:
        response["delivery_error"] = send_error
    if DEV_SHOW_OTP:
        response["dev_email_otp"] = email_otp
    return jsonify(response), 200

@app.post("/api/register/resend")
def register_resend():
    data = request.get_json(force=True)
    row = db().execute("SELECT * FROM registration_otps WHERE token=?", (data.get("token"),)).fetchone()
    if not row:
        return jsonify(error="Registration session expired. Start again."), 400
    import json
    payload = json.loads(row["payload_json"])
    email_otp, phone_otp = make_otp(), make_otp()
    expires = now() + timedelta(minutes=OTP_EXPIRY_MINUTES)
    db().execute(
        "UPDATE registration_otps SET email_otp_hash=?, phone_otp_hash=?, expires_at=?, attempts=0 WHERE token=?",
        (hash_otp(email_otp), hash_otp(phone_otp), expires.isoformat(), row["token"])
    )
    db().commit()
    send_error = None
    try:
        send_email_otp(payload["email"], email_otp)
    except Exception:
        app.logger.exception("Brevo OTP resend failed")
        send_error = "OTP email could not be sent. Check BREVO_API_KEY and BREVO_FROM in Render Environment and try again."
    response = {"token":row["token"], "masked_email":mask_email(payload["email"])}
    if send_error:
        response["delivery_error"] = send_error
    if DEV_SHOW_OTP:
        response["dev_email_otp"] = email_otp
    return jsonify(response)

@app.post("/api/register/verify")
def register_verify():
    data = request.get_json(force=True)
    row = db().execute("SELECT * FROM registration_otps WHERE token=?", (data.get("token"),)).fetchone()
    if not row:
        return jsonify(error="Registration session expired. Start again."), 400
    if datetime.fromisoformat(row["expires_at"]) < now():
        return jsonify(error="OTP expired. Request a new OTP."), 400
    if row["attempts"] >= 5:
        return jsonify(error="Too many incorrect OTP attempts. Request a new OTP."), 429
    if not re.fullmatch(r"\d{6}", str(data.get("email_otp", ""))) or hash_otp(str(data.get("email_otp",""))) != row["email_otp_hash"]:
        db().execute("UPDATE registration_otps SET attempts=attempts+1 WHERE token=?", (row["token"],))
        db().commit()
        return jsonify(error="One or both OTP codes are incorrect."), 400

    import json
    p = json.loads(row["payload_json"])
    try:
        db().execute(
            """INSERT INTO users
            (first_name,last_name,age,email,phone,address,postal_code,password_hash,email_verified,phone_verified,created_at)
            VALUES (?,?,?,?,?,?,?,?,1,1,?)""",
            (p["first_name"],p["last_name"],p["age"],p["email"],p["phone"],p["address"],p["postal_code"],p["password_hash"],now().isoformat())
        )
        db().execute("DELETE FROM registration_otps WHERE token=?", (row["token"],))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Email or phone number is already registered."), 400
    return jsonify(ok=True)

@app.post("/api/login")
def login():
    data = request.get_json(force=True)
    email = str(data.get("email", "")).strip().lower()
    user = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], str(data.get("password", ""))):
        return jsonify(error="Incorrect email or password."), 401
    if not user["email_verified"] or not user["phone_verified"]:
        return jsonify(error="This account has not completed verification."), 403
    code = make_otp()
    token = secrets.token_urlsafe(32)
    expires = now() + timedelta(minutes=5)
    try:
        send_email_otp(user["email"], code)
    except Exception:
        app.logger.exception("Login OTP delivery failed")
        return jsonify(error="Hindi naipadala ang login code. Tingnan ang BREVO_API_KEY at BREVO_FROM sa Render Environment at subukan ulit."), 503
    session.clear()
    session["pending_login"] = {"user_id": user["id"], "token": token, "otp_hash": hash_otp(code),
                                 "expires_at": expires.isoformat(), "attempts": 0}
    return jsonify(otp_required=True, token=token, masked_email=mask_email(user["email"]), expires_in_minutes=5)

@app.post("/api/login/verify")
def login_verify():
    data = request.get_json(force=True)
    pending = session.get("pending_login")
    if not pending or not hmac.compare_digest(str(data.get("token", "")), str(pending.get("token", ""))):
        return jsonify(error="Login verification expired. Please log in again."), 400
    if datetime.fromisoformat(pending["expires_at"]) < now():
        session.pop("pending_login", None)
        return jsonify(error="Verification code expired. Please log in again."), 400
    if pending.get("attempts", 0) >= 5:
        session.pop("pending_login", None)
        return jsonify(error="Too many incorrect codes. Please log in again."), 429
    code = str(data.get("otp", ""))
    if not re.fullmatch(r"\d{6}", code) or not hmac.compare_digest(hash_otp(code), pending["otp_hash"]):
        pending["attempts"] = pending.get("attempts", 0) + 1
        session["pending_login"] = pending
        return jsonify(error="Incorrect verification code."), 400
    uid = pending["user_id"]
    session.clear()
    session["user_id"] = uid
    return jsonify(ok=True)

@app.post("/api/login/resend")
def login_resend():
    pending = session.get("pending_login")
    if not pending:
        return jsonify(error="Login verification expired. Please log in again."), 400
    user = db().execute("SELECT email FROM users WHERE id=?", (pending["user_id"],)).fetchone()
    if not user:
        session.clear()
        return jsonify(error="Account not found. Please log in again."), 404
    code = make_otp()
    try:
        send_email_otp(user["email"], code)
    except Exception:
        app.logger.exception("Login OTP resend failed")
        return jsonify(error="Hindi naipadala ang bagong code. Subukan ulit mamaya."), 503
    pending.update({"otp_hash": hash_otp(code), "expires_at": (now()+timedelta(minutes=5)).isoformat(), "attempts": 0})
    session["pending_login"] = pending
    return jsonify(ok=True, masked_email=mask_email(user["email"]))

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

def user_row():
    uid=session.get("user_id")
    if not uid: return None
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

@app.get("/api/me")
def me():
    u=user_row()
    if not u: return jsonify(logged_in=False)
    return jsonify(logged_in=True,user={
        "id":u["id"],"first_name":u["first_name"],"last_name":u["last_name"],
        "age":u["age"],"email":u["email"],"phone":u["phone"],
        "address":u["address"],"postal_code":u["postal_code"]
    })

@app.put("/api/profile")
@login_required
def profile_update():
    d=request.get_json(force=True)
    first=str(d.get("first_name","")).strip()
    last=str(d.get("last_name","")).strip()
    address=str(d.get("address","")).strip()
    postal=str(d.get("postal_code","")).strip()
    try: age=int(d.get("age"))
    except: return jsonify(error="Age must be a number."),400
    if not first or not last or not address or not postal or not (1<=age<=120):
        return jsonify(error="Please complete the profile fields."),400
    db().execute("UPDATE users SET first_name=?,last_name=?,age=?,address=?,postal_code=? WHERE id=?",
                 (first,last,age,address,postal,session["user_id"]))
    db().commit()
    return jsonify(ok=True)

@app.get("/api/cart")
@login_required
def get_cart():
    rows=db().execute("SELECT * FROM cart_items WHERE user_id=? ORDER BY id", (session["user_id"],)).fetchall()
    items=[]
    total=0
    for r in rows:
        subtotal=r["price"]*r["quantity"]; total+=subtotal
        items.append({"id":r["id"],"name":r["name"],"price":r["price"],"image":r["image"],"quantity":r["quantity"],"subtotal":subtotal})
    return jsonify(items=items,total=total)

@app.post("/api/cart")
@login_required
def add_cart():
    d=request.get_json(force=True)
    try: price=float(d["price"])
    except: return jsonify(error="Invalid product price."),400
    name=str(d.get("name","")).strip()
    image=str(d.get("image","")).strip()
    if not name or not image or price<=0:return jsonify(error="Invalid product."),400
    conn=db()
    row=conn.execute("SELECT id FROM cart_items WHERE user_id=? AND name=?", (session["user_id"],name)).fetchone()
    if row: conn.execute("UPDATE cart_items SET quantity=quantity+1 WHERE id=?", (row["id"],))
    else: conn.execute("INSERT INTO cart_items(user_id,name,price,image,quantity) VALUES(?,?,?,?,1)", (session["user_id"],name,price,image))
    conn.commit()
    return jsonify(ok=True)

@app.put("/api/cart/<int:item_id>")
@login_required
def update_cart(item_id):
    q=int(request.get_json(force=True).get("quantity",1))
    if q<=0:
        db().execute("DELETE FROM cart_items WHERE id=? AND user_id=?", (item_id,session["user_id"]))
    else:
        db().execute("UPDATE cart_items SET quantity=? WHERE id=? AND user_id=?", (q,item_id,session["user_id"]))
    db().commit()
    return jsonify(ok=True)

@app.delete("/api/cart/<int:item_id>")
@login_required
def delete_cart(item_id):
    db().execute("DELETE FROM cart_items WHERE id=? AND user_id=?", (item_id,session["user_id"]))
    db().commit()
    return jsonify(ok=True)

@app.post("/api/orders")
@login_required
def create_order():
    d=request.get_json(force=True)
    address=str(d.get("address","")).strip()
    postal=str(d.get("postal_code","")).strip()
    phone=normalize_phone(d.get("phone"))
    note=str(d.get("note","")).strip()
    # EL BRUSTO currently accepts Cash on Delivery only.
    payment_method="Cash on Delivery"
    if not address or not postal or not phone:
        return jsonify(error="Please complete the checkout details."),400
    conn=db()
    items=conn.execute("SELECT * FROM cart_items WHERE user_id=?", (session["user_id"],)).fetchall()
    if not items:return jsonify(error="Your cart is empty."),400
    total=sum(r["price"]*r["quantity"] for r in items)
    cur=conn.execute("INSERT INTO orders(user_id,address,postal_code,phone,note,total,status,created_at,payment_method) VALUES(?,?,?,?,?,?,?,?,?)",
                      (session["user_id"],address,postal,phone,note,total,"Pending",now().isoformat(),payment_method))
    order_id=cur.lastrowid
    for r in items:
        conn.execute("INSERT INTO order_items(order_id,name,price,quantity,subtotal) VALUES(?,?,?,?,?)",
                     (order_id,r["name"],r["price"],r["quantity"],r["price"]*r["quantity"]))
    conn.execute("DELETE FROM cart_items WHERE user_id=?", (session["user_id"],))
    conn.commit()
    return jsonify(ok=True,order_id=order_id,total=total,status="Pending",payment_method=payment_method)

@app.get("/api/orders")
@login_required
def orders():
    rows=db().execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    result=[]
    for row in rows:
        order=dict(row)
        order["items"]=[dict(item) for item in db().execute(
            "SELECT name,price,quantity,subtotal FROM order_items WHERE order_id=? ORDER BY id",
            (row["id"],)
        ).fetchall()]
        result.append(order)
    # Tell the customer whether the five-minute cancellation window is still open.
    current = now()
    for order in result:
        try:
            created = datetime.fromisoformat(order["created_at"])
            if created.tzinfo:
                created = created.astimezone().replace(tzinfo=None)
            elapsed = max(0, int((current - created).total_seconds()))
            order["cancel_seconds_remaining"] = max(0, 300 - elapsed) if order.get("status") == "Pending" else 0
            order["can_cancel"] = order.get("status") == "Pending" and elapsed < 300
        except (ValueError, TypeError):
            order["cancel_seconds_remaining"] = 0
            order["can_cancel"] = False
    return jsonify(orders=result)

@app.post("/api/orders/<int:order_id>/cancel")
@login_required
def cancel_customer_order(order_id):
    """Customers may cancel only their own Pending order within five minutes."""
    conn = db()
    row = conn.execute("SELECT id, status, created_at FROM orders WHERE id=? AND user_id=?", (order_id, session["user_id"])).fetchone()
    if not row:
        return jsonify(error="Order not found."), 404
    if row["status"] != "Pending":
        return jsonify(error="This order can no longer be cancelled because it is already being processed."), 400
    try:
        created = datetime.fromisoformat(row["created_at"])
        if created.tzinfo:
            created = created.astimezone().replace(tzinfo=None)
    except (ValueError, TypeError):
        return jsonify(error="Could not verify the order time. Please contact the shop."), 400
    elapsed = (now() - created).total_seconds()
    if elapsed >= 300:
        return jsonify(error="The 5-minute cancellation period has ended. Please contact the shop for help."), 400
    conn.execute("UPDATE orders SET status='Cancelled', updated_at=? WHERE id=?", (now().isoformat(), order_id))
    conn.commit()
    return jsonify(ok=True, status="Cancelled")

# ---------- Admin order management ----------
def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin_authenticated"):
            return jsonify(error="ADMIN_LOGIN_REQUIRED"), 401
        return fn(*args, **kwargs)
    return wrapped

@app.get("/admin")
def admin_page():
    return render_template("admin.html")

@app.post("/api/admin/login")
def admin_login():
    if not ADMIN_USERNAME or not ADMIN_PASSWORD:
        return jsonify(error="Admin credentials are not configured. Set ADMIN_USERNAME and ADMIN_PASSWORD in .env."), 503
    data=request.get_json(force=True)
    username=str(data.get("username", ""))
    password=str(data.get("password", ""))
    if not hmac.compare_digest(username, ADMIN_USERNAME) or not hmac.compare_digest(password, ADMIN_PASSWORD):
        return jsonify(error="Incorrect admin username or password."), 401
    session["admin_authenticated"]=True
    session["admin_username"]=ADMIN_USERNAME
    return jsonify(ok=True)

@app.get("/api/admin/session")
def admin_session_status():
    """Let the admin page restore its dashboard after a normal browser refresh."""
    if session.get("admin_authenticated"):
        return jsonify(authenticated=True, username=session.get("admin_username", "Admin"))
    return jsonify(authenticated=False), 401

@app.post("/api/admin/logout")
def admin_logout():
    session.pop("admin_authenticated", None)
    session.pop("admin_username", None)
    return jsonify(ok=True)

@app.get("/api/admin/orders")
@admin_required
def admin_orders():
    rows=db().execute("""
        SELECT orders.*, users.first_name, users.last_name, users.email
        FROM orders JOIN users ON users.id=orders.user_id
        ORDER BY orders.id DESC
    """).fetchall()
    result=[]
    for row in rows:
        order=dict(row)
        order["items"]=[dict(item) for item in db().execute(
            "SELECT name,price,quantity,subtotal FROM order_items WHERE order_id=? ORDER BY id",
            (row["id"],)
        ).fetchall()]
        result.append(order)
    return jsonify(orders=result)

@app.patch("/api/admin/orders/<int:order_id>")
@admin_required
def admin_update_order(order_id):
    data=request.get_json(force=True)
    allowed={"Pending","Confirmed","Preparing","Out for Delivery","Delivered","Cancelled"}
    status=str(data.get("status","Pending")).strip()
    if status not in allowed:
        return jsonify(error="Invalid order status."),400
    delivery_date=str(data.get("delivery_date","")).strip() or None
    delivery_time=str(data.get("delivery_time","")).strip() or None
    admin_note=str(data.get("admin_note","")).strip()[:500]
    if delivery_date and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", delivery_date):
        return jsonify(error="Use a valid delivery date."),400
    if delivery_time and not re.fullmatch(r"\d{2}:\d{2}", delivery_time):
        return jsonify(error="Use a valid delivery time."),400
    conn=db()
    cur=conn.execute("""
        UPDATE orders SET status=?, delivery_date=?, delivery_time=?, admin_note=?, updated_at=?
        WHERE id=?
    """,(status,delivery_date,delivery_time,admin_note,now().isoformat(),order_id))
    if cur.rowcount==0:
        conn.rollback()
        return jsonify(error="Order not found."),404
    conn.commit()
    return jsonify(ok=True)

@app.delete("/api/admin/orders/<int:order_id>")
@admin_required
def admin_delete_order(order_id):
    """Remove an order from the active records after staff confirms deletion."""
    conn = db()
    exists = conn.execute("SELECT id FROM orders WHERE id=?", (order_id,)).fetchone()
    if not exists:
        return jsonify(error="Order not found."), 404
    # Foreign keys cascade to order_items. Analytics and order list will recalculate.
    conn.execute("DELETE FROM orders WHERE id=?", (order_id,))
    conn.commit()
    return jsonify(ok=True)

@app.get("/api/admin/analytics")
@admin_required
def admin_analytics():
    conn=db()
    today=now().date()
    def count_revenue(start_iso, end_iso=None):
        if end_iso:
            row=conn.execute("SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN status!='Cancelled' THEN total ELSE 0 END),0) AS revenue FROM orders WHERE created_at>=? AND created_at<?", (start_iso,end_iso)).fetchone()
        else:
            row=conn.execute("SELECT COUNT(*) AS n, COALESCE(SUM(CASE WHEN status!='Cancelled' THEN total ELSE 0 END),0) AS revenue FROM orders WHERE created_at>=?", (start_iso,)).fetchone()
        return {"orders": row["n"], "revenue": round(float(row["revenue"] or 0),2)}
    day_start=datetime.combine(today, datetime.min.time()).isoformat()
    week_start=datetime.combine(today-timedelta(days=today.weekday()), datetime.min.time()).isoformat()
    month_start=datetime(today.year,today.month,1).isoformat()
    # 7 daily bars, current week by day, and 6 monthly bars.
    daily=[]
    for offset in range(6,-1,-1):
        d=today-timedelta(days=offset); start=datetime.combine(d,datetime.min.time()).isoformat(); end=(datetime.combine(d,datetime.min.time())+timedelta(days=1)).isoformat()
        v=count_revenue(start,end); daily.append({"label":d.strftime("%a"),"date":d.isoformat(),**v})
    weekly=[]
    for offset in range(6,-1,-1):
        d=today-timedelta(days=(today.weekday()+offset*7))
        start=datetime.combine(d,datetime.min.time()).isoformat(); end=(datetime.combine(d,datetime.min.time())+timedelta(days=7)).isoformat()
        v=count_revenue(start,end); weekly.append({"label":d.strftime("%b %d"),"date":d.isoformat(),**v})
    monthly=[]
    for offset in range(5,-1,-1):
        y=today.year; m=today.month-offset
        while m<=0: y-=1; m+=12
        start=datetime(y,m,1); end=datetime(y+1,1,1) if m==12 else datetime(y,m+1,1)
        v=count_revenue(start.isoformat(),end.isoformat()); monthly.append({"label":start.strftime("%b"),"date":start.date().isoformat(),**v})
    return jsonify(today=count_revenue(day_start), week=count_revenue(week_start), month=count_revenue(month_start), daily=daily, weekly=weekly, monthly=monthly)

@app.get("/api/admin/export")
@admin_required
def admin_export():
    import csv, io
    from flask import Response
    output=io.StringIO()
    writer=csv.writer(output)
    writer.writerow(["Order ID","Customer","Email","Phone","Address","Postal Code","Note","Items","Total","Status","Placed At","Delivery Date","Delivery Time","Admin Note"])
    rows=db().execute("""SELECT orders.*, users.first_name, users.last_name, users.email FROM orders JOIN users ON users.id=orders.user_id ORDER BY orders.id DESC""").fetchall()
    for r in rows:
        items=db().execute("SELECT name,quantity,price,subtotal FROM order_items WHERE order_id=? ORDER BY id",(r["id"],)).fetchall()
        item_text="; ".join(f"{i['quantity']} x {i['name']} (PHP {i['subtotal']:.2f})" for i in items)
        writer.writerow([r["id"],f"{r['first_name']} {r['last_name']}",r["email"],r["phone"],r["address"],r["postal_code"],r["note"] or "",item_text,r["total"],r["status"],r["created_at"],r["delivery_date"] or "",r["delivery_time"] or "",r["admin_note"] or ""])
    filename=f"el_brusto_orders_backup_{now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(output.getvalue(), mimetype="text/csv; charset=utf-8", headers={"Content-Disposition":f"attachment; filename={filename}"})

@app.get("/api/admin/inventory")
@admin_required
def admin_inventory():
    rows=db().execute("SELECT * FROM inventory ORDER BY name COLLATE NOCASE").fetchall()
    return jsonify(items=[dict(r) for r in rows])

@app.post("/api/admin/inventory")
@admin_required
def admin_inventory_save():
    data=request.get_json(force=True)
    name=str(data.get("name","")).strip()[:100]
    try: stock=int(data.get("stock",0))
    except (TypeError,ValueError): return jsonify(error="Stock must be a whole number."),400
    if not name or stock<0: return jsonify(error="Enter an item name and stock of zero or more."),400
    conn=db()
    try:
        conn.execute("INSERT INTO inventory(name,stock,updated_at) VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET stock=excluded.stock,updated_at=excluded.updated_at",(name,stock,now().isoformat()))
        conn.commit()
    except sqlite3.Error:
        conn.rollback(); return jsonify(error="Could not save inventory item."),400
    return jsonify(ok=True)

@app.delete("/api/admin/inventory/<int:item_id>")
@admin_required
def admin_inventory_delete(item_id):
    db().execute("DELETE FROM inventory WHERE id=?",(item_id,)); db().commit()
    return jsonify(ok=True)

# Initialize tables/migrations for both local runs and production WSGI servers.
init_db()

if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "true").lower() == "true"
    )

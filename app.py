import os
import re
import secrets
import hashlib
import sqlite3
import smtplib
import ssl
import json

from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from flask import Flask, render_template, request, jsonify, session, g
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

load_dotenv(os.path.join(BASE_DIR, ".env"))


# =========================================================
# FLASK CONFIGURATION
# =========================================================

app = Flask(
    __name__,
    static_folder="static",
    template_folder="templates"
)

# In production, set SECRET_KEY in .env to a long, random value.
# The generated fallback is only for local development and changes on restart.
app.secret_key = os.getenv("SECRET_KEY") or secrets.token_hex(32)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "false").lower() == "true"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024


@app.errorhandler(400)
def handle_bad_request(error):
    if request.path.startswith("/api/"):
        return jsonify(error="Invalid request. Please check the submitted data."), 400
    return error


@app.errorhandler(413)
def handle_large_request(error):
    if request.path.startswith("/api/"):
        return jsonify(error="Request is too large."), 413
    return error


# =========================================================
# DATABASE
# =========================================================

DB_PATH = os.path.join(BASE_DIR, "el_brusto.db")


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
    """)

    # Safe migration for existing databases: preserve orders and add COD field.
    order_columns = {row[1] for row in conn.execute("PRAGMA table_info(orders)").fetchall()}
    if "payment_method" not in order_columns:
        conn.execute("ALTER TABLE orders ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'Cash on Delivery'")

    conn.commit()
    conn.close()


# =========================================================
# GENERAL HELPERS
# =========================================================

def now():
    return datetime.now()


def normalize_phone(phone):
    p = re.sub(r"\D", "", str(phone or ""))

    if p.startswith("09") and len(p) == 11:
        return "+63" + p[1:]

    if p.startswith("63") and len(p) == 12:
        return "+" + p

    if p.startswith("+63") and len(p) == 13:
        return p

    return None


def valid_email(email):
    """Basic syntax check; actual ownership is confirmed by emailed OTP."""
    return bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", str(email or "").strip()))


def hash_otp(code):
    return hashlib.sha256(code.encode()).hexdigest()


def make_otp():
    return f"{secrets.randbelow(1000000):06d}"


def mask_email(email):
    name, domain = email.split("@", 1)

    if len(name) > 2:
        masked_name = name[:2] + "***"
    else:
        masked_name = "***"

    return masked_name + "@" + domain


def mask_phone(phone):
    digits = re.sub(r"\D", "", phone)

    if len(digits) < 4:
        return "******"

    return digits[:2] + "******" + digits[-2:]


# =========================================================
# GMAIL OTP
# =========================================================

EMAIL_HOST = os.getenv(
    "MAIL_HOST",
    "smtp.gmail.com"
)

EMAIL_PORT = int(
    os.getenv(
        "MAIL_PORT",
        "587"
    )
)

EMAIL_USER = os.getenv(
    "MAIL_USERNAME",
    ""
).strip()

EMAIL_PASS = os.getenv(
    "MAIL_PASSWORD",
    ""
).strip()

OTP_EXPIRY_MINUTES = 10

DEV_SHOW_OTP = (
    os.getenv(
        "DEV_SHOW_OTP",
        "false"
    ).lower() == "true"
)


def send_email_otp(to_email, code):

    if not EMAIL_USER:
        raise RuntimeError(
            "MAIL_USERNAME is empty. Put the EL BRUSTO Gmail address in .env."
        )

    if not EMAIL_PASS:
        raise RuntimeError(
            "MAIL_PASSWORD is empty. Put the Gmail App Password in .env."
        )

    msg = EmailMessage()

    msg["Subject"] = "EL BRUSTO - Account Verification OTP"

    msg["From"] = EMAIL_USER

    msg["To"] = to_email

    msg.set_content(
        f"""
Hello,

Thank you for registering with EL BRUSTO.

Your account verification OTP is:

{code}

This OTP will expire in {OTP_EXPIRY_MINUTES} minutes.

If you did not request this code, you can ignore this email.

Do not share this OTP with anyone.

Thank you,
EL BRUSTO
""".strip()
    )

    try:
        ssl_context = ssl.create_default_context()
        if EMAIL_PORT == 465:
            with smtplib.SMTP_SSL(
                EMAIL_HOST, EMAIL_PORT, timeout=30, context=ssl_context
            ) as smtp:
                smtp.ehlo()
                smtp.login(EMAIL_USER, EMAIL_PASS)
                smtp.send_message(msg)
        else:
            with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT, timeout=30) as smtp:
                smtp.ehlo()
                smtp.starttls(context=ssl_context)
                smtp.ehlo()
                smtp.login(EMAIL_USER, EMAIL_PASS)
                smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError as exc:
        raise RuntimeError(
            "Gmail login failed. Check MAIL_USERNAME and use a Google App Password in MAIL_PASSWORD."
        ) from exc
    except (ssl.SSLError, ConnectionResetError, ConnectionAbortedError,
            BrokenPipeError, TimeoutError, OSError) as exc:
        raise RuntimeError(
            f"Email connection failed: {type(exc).__name__}: {exc}"
        ) from exc
    except smtplib.SMTPException as exc:
        raise RuntimeError(f"Gmail SMTP error: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unable to send Gmail OTP: {exc}") from exc


# =========================================================
# LOGIN REQUIRED
# =========================================================

def login_required(fn):

    @wraps(fn)
    def wrapped(*args, **kwargs):

        uid = session.get("user_id")

        if not uid:
            return jsonify(
                error="LOGIN_REQUIRED"
            ), 401

        return fn(*args, **kwargs)

    return wrapped


# =========================================================
# HOME
# =========================================================

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# =========================================================
# REGISTER - SEND REAL GMAIL OTP
# =========================================================

@app.post("/api/register/start")
def register_start():

    data = request.get_json(force=True)

    required = [
        "first_name",
        "last_name",
        "age",
        "email",
        "phone",
        "address",
        "postal_code",
        "password",
        "confirm_password"
    ]

    if any(
        not str(data.get(k, "")).strip()
        for k in required
    ):

        return jsonify(
            error="Please complete all registration fields."
        ), 400

    if data["password"] != data["confirm_password"]:

        return jsonify(
            error="Passwords do not match."
        ), 400

    if len(data["password"]) < 8:

        return jsonify(
            error="Password must be at least 8 characters."
        ), 400

    try:

        age = int(data["age"])

    except (ValueError, TypeError):

        return jsonify(
            error="Age must be a number."
        ), 400

    if age < 1 or age > 120:

        return jsonify(
            error="Please enter a valid age."
        ), 400

    email = str(
        data["email"]
    ).strip().lower()

    if not valid_email(email):
        return jsonify(error="Enter a valid email address."), 400

    phone = normalize_phone(
        data["phone"]
    )

    if not phone:

        return jsonify(
            error="Enter a valid Philippine mobile number such as 09XXXXXXXXX."
        ), 400

    conn = db()

    if conn.execute(
        "SELECT id FROM users WHERE email=?",
        (email,)
    ).fetchone():

        return jsonify(
            error="An account with that email already exists."
        ), 400

    if conn.execute(
        "SELECT id FROM users WHERE phone=?",
        (phone,)
    ).fetchone():

        return jsonify(
            error="An account with that phone number already exists."
        ), 400

    # Generate real OTP
    email_otp = make_otp()

    # Kept internally for future SMS verification
    phone_otp = make_otp()

    token = secrets.token_urlsafe(32)

    payload = {

        "first_name":
            str(data["first_name"]).strip(),

        "last_name":
            str(data["last_name"]).strip(),

        "age":
            age,

        "email":
            email,

        "phone":
            phone,

        "address":
            str(data["address"]).strip(),

        "postal_code":
            str(data["postal_code"]).strip(),

        "password_hash":
            generate_password_hash(
                data["password"]
            )
    }

    expires = (
        now()
        + timedelta(
            minutes=OTP_EXPIRY_MINUTES
        )
    )

    conn.execute(
        "DELETE FROM registration_otps WHERE expires_at < ?",
        (now().isoformat(),)
    )

    conn.execute(
        """
        INSERT INTO registration_otps
        (
            token,
            payload_json,
            email_hash,
            phone_hash,
            email_otp_hash,
            phone_otp_hash,
            expires_at,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            token,
            json.dumps(payload),
            hash_otp(email),
            hash_otp(phone),
            hash_otp(email_otp),
            hash_otp(phone_otp),
            expires.isoformat(),
            now().isoformat()
        )
    )

    conn.commit()

    # =====================================================
    # SEND REAL GMAIL OTP
    # =====================================================

    try:
        send_email_otp(
            email,
            email_otp
        )

    except Exception as e:

        print("\n========================================")
        print("GMAIL OTP ERROR")
        print("========================================")
        print("ERROR TYPE:", type(e).__name__)
        print("ERROR:", str(e))
        print("========================================\n")

        conn.execute(
            "DELETE FROM registration_otps WHERE token=?",
            (token,)
        )

        conn.commit()

        return jsonify(
            error="Gmail OTP could not be sent.",
            details=str(e)
        ), 500

    response = {

        "token":
            token,

        "masked_email":
            mask_email(email),

        "masked_phone":
            mask_phone(phone)
    }

    # NEVER expose OTP when false
    if DEV_SHOW_OTP:

        response[
            "dev_email_otp"
        ] = email_otp

    return jsonify(
        response
    ), 200


# =========================================================
# RESEND REAL GMAIL OTP
# =========================================================

@app.post("/api/register/resend")
def register_resend():

    data = request.get_json(
        force=True
    )

    row = db().execute(
        """
        SELECT *
        FROM registration_otps
        WHERE token=?
        """,
        (
            data.get("token"),
        )
    ).fetchone()

    if not row:

        return jsonify(
            error="Registration session expired. Start again."
        ), 400

    payload = json.loads(
        row["payload_json"]
    )

    email_otp = make_otp()

    phone_otp = make_otp()

    expires = (
        now()
        + timedelta(
            minutes=OTP_EXPIRY_MINUTES
        )
    )

    db().execute(
        """
        UPDATE registration_otps

        SET
            email_otp_hash=?,
            phone_otp_hash=?,
            expires_at=?,
            attempts=0

        WHERE token=?
        """,
        (
            hash_otp(email_otp),
            hash_otp(phone_otp),
            expires.isoformat(),
            row["token"]
        )
    )

    db().commit()

    # =====================================================
    # SEND REAL GMAIL OTP AGAIN
    # =====================================================

    try:

        send_email_otp(
            payload["email"],
            email_otp
        )

    except Exception as exc:

        print("\n========================================")
        print("GMAIL RESEND OTP ERROR")
        print("========================================")
        print("ERROR TYPE:", type(exc).__name__)
        print("ERROR:", str(exc))
        print("========================================\n")

        return jsonify(
            error="Gmail OTP could not be resent.",
            details=str(exc)
        ), 500

    response = {

        "token":
            row["token"],

        "masked_email":
            mask_email(
                payload["email"]
            ),

        "masked_phone":
            mask_phone(
                payload["phone"]
            )
    }

    if DEV_SHOW_OTP:

        response[
            "dev_email_otp"
        ] = email_otp

    return jsonify(
        response
    )


# =========================================================
# VERIFY REAL GMAIL OTP
# =========================================================

@app.post("/api/register/verify")
def register_verify():

    data = request.get_json(
        force=True
    )

    row = db().execute(
        """
        SELECT *
        FROM registration_otps
        WHERE token=?
        """,
        (
            data.get("token"),
        )
    ).fetchone()

    if not row:

        return jsonify(
            error="Registration session expired. Start again."
        ), 400

    if datetime.fromisoformat(
        row["expires_at"]
    ) < now():

        return jsonify(
            error="OTP expired. Request a new OTP."
        ), 400

    if row["attempts"] >= 5:

        return jsonify(
            error="Too many incorrect OTP attempts. Request a new OTP."
        ), 429

    # =====================================================
    # ONLY REAL GMAIL OTP IS REQUIRED FOR NOW
    # =====================================================

    entered_email_otp = str(
        data.get(
            "email_otp",
            ""
        )
    ).strip()

    if hash_otp(
        entered_email_otp
    ) != row["email_otp_hash"]:

        db().execute(
            """
            UPDATE registration_otps
            SET attempts=attempts+1
            WHERE token=?
            """,
            (
                row["token"],
            )
        )

        db().commit()

        return jsonify(
            error="The Gmail OTP is incorrect."
        ), 400

    # =====================================================
    # CREATE ACCOUNT
    # =====================================================

    p = json.loads(
        row["payload_json"]
    )

    try:

        db().execute(
            """
            INSERT INTO users
            (
                first_name,
                last_name,
                age,
                email,
                phone,
                address,
                postal_code,
                password_hash,
                email_verified,
                phone_verified,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?)
            """,
            (
                p["first_name"],
                p["last_name"],
                p["age"],
                p["email"],
                p["phone"],
                p["address"],
                p["postal_code"],
                p["password_hash"],
                now().isoformat()
            )
        )

        db().execute(
            """
            DELETE FROM registration_otps
            WHERE token=?
            """,
            (
                row["token"],
            )
        )

        db().commit()

    except sqlite3.IntegrityError:

        return jsonify(
            error="Email or phone number is already registered."
        ), 400

    return jsonify(
        ok=True
    )


# =========================================================
# LOGIN
# =========================================================

@app.post("/api/login")
def login():

    data = request.get_json(
        force=True
    )

    email = str(
        data.get(
            "email",
            ""
        )
    ).strip().lower()

    user = db().execute(
        """
        SELECT *
        FROM users
        WHERE email=?
        """,
        (
            email,
        )
    ).fetchone()

    if not user or not check_password_hash(
        user["password_hash"],
        str(
            data.get(
                "password",
                ""
            )
        )
    ):

        return jsonify(
            error="Incorrect email or password."
        ), 401

    if not user["email_verified"]:

        return jsonify(
            error="This account has not completed email verification."
        ), 403

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]

    return jsonify(
        ok=True
    )


# =========================================================
# LOGOUT
# =========================================================

@app.post("/api/logout")
def logout():

    session.clear()

    return jsonify(
        ok=True
    )


# =========================================================
# USER
# =========================================================

def user_row():

    uid = session.get(
        "user_id"
    )

    if not uid:
        return None

    return db().execute(
        """
        SELECT *
        FROM users
        WHERE id=?
        """,
        (
            uid,
        )
    ).fetchone()


@app.get("/api/me")
def me():

    u = user_row()

    if not u:

        return jsonify(
            logged_in=False
        )

    return jsonify(
        logged_in=True,

        user={
            "id": u["id"],
            "first_name": u["first_name"],
            "last_name": u["last_name"],
            "age": u["age"],
            "email": u["email"],
            "phone": u["phone"],
            "address": u["address"],
            "postal_code": u["postal_code"]
        }
    )


# =========================================================
# PROFILE UPDATE
# =========================================================

@app.put("/api/profile")
@login_required
def profile_update():

    d = request.get_json(
        force=True
    )

    first = str(
        d.get(
            "first_name",
            ""
        )
    ).strip()

    last = str(
        d.get(
            "last_name",
            ""
        )
    ).strip()

    address = str(
        d.get(
            "address",
            ""
        )
    ).strip()

    postal = str(
        d.get(
            "postal_code",
            ""
        )
    ).strip()

    try:

        age = int(
            d.get(
                "age"
            )
        )

    except:

        return jsonify(
            error="Age must be a number."
        ), 400

    if (
        not first
        or not last
        or not address
        or not postal
        or not (1 <= age <= 120)
    ):

        return jsonify(
            error="Please complete the profile fields."
        ), 400

    db().execute(
        """
        UPDATE users

        SET
            first_name=?,
            last_name=?,
            age=?,
            address=?,
            postal_code=?

        WHERE id=?
        """,
        (
            first,
            last,
            age,
            address,
            postal,
            session["user_id"]
        )
    )

    db().commit()

    return jsonify(
        ok=True
    )


# =========================================================
# CART
# =========================================================

@app.get("/api/cart")
@login_required
def get_cart():

    rows = db().execute(
        """
        SELECT *
        FROM cart_items
        WHERE user_id=?
        ORDER BY id
        """,
        (
            session["user_id"],
        )
    ).fetchall()

    items = []

    total = 0

    for r in rows:

        subtotal = (
            r["price"]
            * r["quantity"]
        )

        total += subtotal

        items.append(
            {
                "id": r["id"],
                "name": r["name"],
                "price": r["price"],
                "image": r["image"],
                "quantity": r["quantity"],
                "subtotal": subtotal
            }
        )

    return jsonify(
        items=items,
        total=total
    )


@app.post("/api/cart")
@login_required
def add_cart():

    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(error="Invalid request body."), 400

    try:
        price = float(d["price"])
    except (KeyError, TypeError, ValueError):
        return jsonify(error="Invalid product price."), 400

    name = str(
        d.get(
            "name",
            ""
        )
    ).strip()

    image = str(
        d.get(
            "image",
            ""
        )
    ).strip()

    if (
        not name
        or not image
        or not (0 < price <= 1000000)
        or not (price < float("inf"))
    ):

        return jsonify(
            error="Invalid product."
        ), 400

    conn = db()

    row = conn.execute(
        """
        SELECT id
        FROM cart_items
        WHERE user_id=?
        AND name=?
        """,
        (
            session["user_id"],
            name
        )
    ).fetchone()

    if row:

        conn.execute(
            """
            UPDATE cart_items
            SET quantity=quantity+1
            WHERE id=?
            """,
            (
                row["id"],
            )
        )

    else:

        conn.execute(
            """
            INSERT INTO cart_items
            (
                user_id,
                name,
                price,
                image,
                quantity
            )
            VALUES (?, ?, ?, ?, 1)
            """,
            (
                session["user_id"],
                name,
                price,
                image
            )
        )

    conn.commit()

    return jsonify(
        ok=True
    )


@app.put("/api/cart/<int:item_id>")
@login_required
def update_cart(item_id):

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="Invalid request body."), 400
    try:
        q = int(data.get("quantity", 1))
    except (TypeError, ValueError):
        return jsonify(error="Quantity must be a whole number."), 400

    if q > 99:
        return jsonify(error="Maximum quantity per item is 99."), 400

    if q <= 0:

        db().execute(
            """
            DELETE FROM cart_items
            WHERE id=?
            AND user_id=?
            """,
            (
                item_id,
                session["user_id"]
            )
        )

    else:

        db().execute(
            """
            UPDATE cart_items
            SET quantity=?
            WHERE id=?
            AND user_id=?
            """,
            (
                q,
                item_id,
                session["user_id"]
            )
        )

    db().commit()

    return jsonify(
        ok=True
    )


@app.delete("/api/cart/<int:item_id>")
@login_required
def delete_cart(item_id):

    db().execute(
        """
        DELETE FROM cart_items
        WHERE id=?
        AND user_id=?
        """,
        (
            item_id,
            session["user_id"]
        )
    )

    db().commit()

    return jsonify(
        ok=True
    )


# =========================================================
# ORDERS
# =========================================================

@app.post("/api/orders")
@login_required
def create_order():

    d = request.get_json(silent=True)
    if not isinstance(d, dict):
        return jsonify(error="Invalid request body."), 400

    address = str(
        d.get(
            "address",
            ""
        )
    ).strip()

    postal = str(
        d.get(
            "postal_code",
            ""
        )
    ).strip()

    phone = normalize_phone(
        d.get(
            "phone"
        )
    )

    note = str(
        d.get(
            "note",
            ""
        )
    ).strip()

    # EL BRUSTO currently supports Cash on Delivery only.
    payment_method = "Cash on Delivery"

    if not address or not postal or not phone:

        return jsonify(
            error="Please complete the checkout details."
        ), 400

    conn = db()

    items = conn.execute(
        """
        SELECT *
        FROM cart_items
        WHERE user_id=?
        """,
        (
            session["user_id"],
        )
    ).fetchall()

    if not items:

        return jsonify(
            error="Your cart is empty."
        ), 400

    total = round(sum(
        r["price"] * r["quantity"]
        for r in items
    ), 2)

    cur = conn.execute(
        """
        INSERT INTO orders
        (
            user_id,
            address,
            postal_code,
            phone,
            note,
            total,
            status,
            created_at,
            payment_method
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session["user_id"],
            address,
            postal,
            phone,
            note,
            total,
            "Pending",
            now().isoformat(),
            payment_method
        )
    )

    order_id = cur.lastrowid

    for r in items:

        conn.execute(
            """
            INSERT INTO order_items
            (
                order_id,
                name,
                price,
                quantity,
                subtotal
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                order_id,
                r["name"],
                r["price"],
                r["quantity"],
                round(r["price"] * r["quantity"], 2)
            )
        )

    conn.execute(
        """
        DELETE FROM cart_items
        WHERE user_id=?
        """,
        (
            session["user_id"],
        )
    )

    conn.commit()

    return jsonify(
        ok=True,
        order_id=order_id,
        total=total,
        payment_method=payment_method
    )


@app.get("/api/orders")
@login_required
def orders():

    rows = db().execute(
        """
        SELECT *
        FROM orders
        WHERE user_id=?
        ORDER BY id DESC
        """,
        (
            session["user_id"],
        )
    ).fetchall()

    return jsonify(
        orders=[
            dict(r)
            for r in rows
        ]
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    init_db()

    app.run(
        host=os.getenv("HOST", "127.0.0.1"),
        port=int(os.getenv("PORT", "5000")),
        debug=os.getenv("FLASK_DEBUG", "false").lower() == "true"
    )

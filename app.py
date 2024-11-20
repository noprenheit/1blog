import os
import sqlite3
import time
import logging

from authlib.integrations.flask_client import OAuth
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    current_user,
    logout_user,
)
from markupsafe import escape
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import pyotp
import segno
from io import BytesIO
import base64

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")  # Load secret key from .env

# Secure session cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # Redirects unauthorized users to the login page

# OAuth configuration
oauth = OAuth(app)
oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),  # Load client ID from .env
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),  # Load client secret from .env
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={"scope": "user:email"},
)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize SQLite Database
def init_db():
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        # Create accounts table with necessary fields
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                failed_attempts INTEGER DEFAULT 0,
                is_locked INTEGER DEFAULT 0,
                lockout_time REAL,
                totp_secret TEXT NOT NULL
            )
            """
        )
        # Create users table to store posts
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                comment TEXT NOT NULL
            )
            """
        )
        conn.commit()
        logger.info("Database initialized successfully.")
    except sqlite3.OperationalError as e:
        logger.error(f"Database initialization failed: {e}")
    finally:
        conn.close()

init_db()  # Initialize the database

# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, password=None):
        self.id = id
        self.username = username
        self.password = password

# User loader callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, password FROM accounts WHERE id = ?", (user_id,)
        )
        account = cursor.fetchone()
        conn.close()
        if account:
            return User(account[0], account[1], account[2])
    except Exception as e:
        logger.error(f"Error loading user: {e}")
    return None

# Home route
@app.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute("SELECT username, comment FROM users ORDER BY id DESC")
        posts = cursor.fetchall()
        conn.close()
        logger.info(f"Fetched {len(posts)} posts.")
        return render_template("index.html", posts=posts)
    except Exception as e:
        logger.error(f"Error fetching posts: {e}")
        flash("An error occurred while fetching posts.", "error")
        return render_template("index.html", posts=[])

# Route to add a new post
@app.route("/add", methods=["POST"])
@login_required
def add_post():
    username = current_user.username
    comment = request.form["comment"]

    # Input validation
    if not comment or len(comment) > 500:
        flash("Invalid post content.")
        return redirect(url_for("index"))

    # Input sanitization
    sanitized_comment = escape(comment)

    try:
        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO users (username, comment) VALUES (?, ?)",
            (username, sanitized_comment),
        )
        conn.commit()
        conn.close()
        flash("Post added successfully.", "success")
    except Exception as e:
        logger.error(f"Error adding post: {e}")
        flash("An error occurred while adding your post.", "error")
    return redirect(url_for("index"))

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        try:
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, username, password, failed_attempts, is_locked, lockout_time, totp_secret
                FROM accounts WHERE email = ?
                """,
                (email,),
            )
            account = cursor.fetchone()

            if account:
                (
                    user_id,
                    username,
                    stored_password,
                    failed_attempts,
                    is_locked,
                    lockout_time,
                    totp_secret,
                ) = account

                # Check if account is locked
                if is_locked:
                    lockout_duration = 15 * 60  # Lockout for 15 minutes
                    current_time = time.time()
                    if lockout_time and (current_time - lockout_time > lockout_duration):
                        # Unlock account
                        cursor.execute(
                            """
                            UPDATE accounts SET is_locked = 0, failed_attempts = 0, lockout_time = NULL
                            WHERE id = ?
                            """,
                            (user_id,),
                        )
                        conn.commit()
                        is_locked = False
                        flash("Your account has been unlocked. Please try logging in again.")
                    else:
                        conn.close()
                        flash("Account is locked. Please try again later.", "error")
                        return render_template(
                            "login.html", failed_attempts=failed_attempts, is_locked=True
                        )

                # Verify password
                if stored_password and check_password_hash(stored_password, password):
                    # Password is correct, proceed to TOTP verification
                    session["pre_2fa_user_id"] = user_id
                    conn.close()
                    return redirect(url_for("totp_verification"))
                else:
                    # Increment failed attempts
                    failed_attempts += 1
                    if failed_attempts >= 3:
                        # Lock the account
                        cursor.execute(
                            """
                            UPDATE accounts SET failed_attempts = ?, is_locked = 1, lockout_time = ?
                            WHERE id = ?
                            """,
                            (failed_attempts, time.time(), user_id),
                        )
                        conn.commit()
                        conn.close()
                        flash(
                            "Account locked due to too many failed login attempts.", "error"
                        )
                        return render_template(
                            "login.html", failed_attempts=failed_attempts, is_locked=True
                        )
                    else:
                        cursor.execute(
                            "UPDATE accounts SET failed_attempts = ? WHERE id = ?",
                            (failed_attempts, user_id),
                        )
                        conn.commit()
                    conn.close()
                    flash(f"Invalid credentials. Attempt {failed_attempts} of 3.", "error")
                    return render_template(
                        "login.html", failed_attempts=failed_attempts, is_locked=False
                    )
            else:
                conn.close()
                flash("Invalid credentials. Please check your email and password.", "error")
                return render_template("login.html", failed_attempts=0, is_locked=False)
        except Exception as e:
            logger.error(f"Error during login: {e}")
            flash("An unexpected error occurred. Please try again later.", "error")
            return render_template("login.html")
    return render_template("login.html")

# TOTP Verification Route
@app.route("/totp_verification", methods=["GET", "POST"])
def totp_verification():
    if request.method == "POST":
        user_id = session.get("pre_2fa_user_id")
        if not user_id:
            flash("Session expired. Please log in again.", "error")
            return redirect(url_for("login"))

        totp_code = request.form["totp_code"]

        try:
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, totp_secret FROM accounts WHERE id = ?", (user_id,)
            )
            account = cursor.fetchone()
            conn.close()

            if account:
                user_id, username, totp_secret = account

                if not totp_secret:
                    flash("Two-factor authentication is not set up for this account.", "error")
                    return redirect(url_for("login"))

                totp = pyotp.TOTP(totp_secret)
                verification = totp.verify(totp_code, valid_window=1)
                logger.info(f"TOTP verification for user {username}: {verification}")

                if verification:
                    # TOTP is correct
                    user = User(user_id, username)
                    login_user(user)
                    session.pop("pre_2fa_user_id", None)
                    flash("Login successful.", "success")
                    return redirect(url_for("index"))
                else:
                    flash("Invalid authentication code. Please try again.", "error")
                    return render_template("totp.html")
            else:
                flash("User not found.", "error")
                return redirect(url_for("login"))
        except Exception as e:
            logger.error(f"Error during TOTP verification: {e}")
            flash("An unexpected error occurred. Please try again later.", "error")
            return redirect(url_for("login"))
    else:
        return render_template("totp.html")

# Registration Route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]

        # Input validation
        if (
            not username
            or not email
            or not password
            or len(username) > 50
            or len(email) > 100
            or len(password) > 100
        ):
            flash("Invalid input.")
            return redirect(url_for("register"))

        # Hash the password
        hashed_password = generate_password_hash(
            password, method="pbkdf2:sha256", salt_length=16
        )

        try:
            conn = sqlite3.connect("database.db")
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM accounts WHERE email = ?", (email,))
            existing_account = cursor.fetchone()
            if existing_account:
                conn.close()
                flash("Email already registered.")
                return redirect(url_for("register"))

            # Generate TOTP secret
            totp_secret = pyotp.random_base32()

            # Store user in database with TOTP secret
            cursor.execute(
                "INSERT INTO accounts (username, email, password, totp_secret) VALUES (?, ?, ?, ?)",
                (username, email, hashed_password, totp_secret),
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()

            # Generate QR code for TOTP using segno
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=email, issuer_name="BlogPoster5000"
            )
            qr = segno.make(totp_uri)
            buffered = BytesIO()
            qr.save(buffered, kind='png')
            qr_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

            flash(
                "Please scan the QR code with your authenticator app to set up two-factor authentication."
            )
            return render_template("display_qr.html", qr_b64=qr_b64)
        except Exception as e:
            logger.error(f"Error during registration: {e}")
            flash("An unexpected error occurred during registration. Please try again.", "error")
            return redirect(url_for("register"))

    return render_template("register.html")

# Logout Route
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))

# GitHub OAuth Login Route
@app.route("/github_login")
def github_login():
    try:
        redirect_uri = url_for("github_authorized", _external=True)
        return oauth.github.authorize_redirect(redirect_uri)
    except Exception as e:
        logger.error(f"Error initiating GitHub OAuth: {e}")
        flash("An error occurred while connecting to GitHub. Please try again.", "error")
        return redirect(url_for("login"))

# GitHub OAuth Callback Route
@app.route("/github_authorized")
def github_authorized():
    try:
        token = oauth.github.authorize_access_token()
        resp = oauth.github.get("user")
        user_data = resp.json()

        # Fetch user's email if not provided
        if not user_data.get("email"):
            emails_resp = oauth.github.get("user/emails")
            emails = emails_resp.json()
            user_data["email"] = next(
                (email["email"] for email in emails if email.get("primary")), None
            )

        email = user_data.get("email")
        username = user_data.get("login")

        if not email:
            flash("Unable to retrieve your email from GitHub.", "error")
            return redirect(url_for("login"))

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, username, totp_secret FROM accounts WHERE email = ?", (email,)
        )
        account = cursor.fetchone()

        if account:
            # User exists
            user_id, _, totp_secret = account

            # Check if totp_secret is set
            if not totp_secret:
                totp_secret = pyotp.random_base32()
                cursor.execute(
                    "UPDATE accounts SET totp_secret = ? WHERE id = ?", (totp_secret, user_id)
                )
                conn.commit()

            # Update username to GitHub username
            cursor.execute(
                "UPDATE accounts SET username = ? WHERE id = ?", (username, user_id)
            )
            conn.commit()

            # Proceed to TOTP verification
            session["pre_2fa_user_id"] = user_id
            conn.close()
            return redirect(url_for("totp_verification"))
        else:
            # User doesn't exist, create a new account
            totp_secret = pyotp.random_base32()
            cursor.execute(
                "INSERT INTO accounts (username, email, totp_secret) VALUES (?, ?, ?)",
                (username, email, totp_secret),
            )
            conn.commit()
            user_id = cursor.lastrowid
            conn.close()

            # Generate QR code for TOTP using segno
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
                name=email, issuer_name="BlogPoster5000"
            )
            qr = segno.make(totp_uri)
            buffered = BytesIO()
            qr.save(buffered, kind='png')
            qr_b64 = base64.b64encode(buffered.getvalue()).decode("utf-8")

            flash(
                "Please scan the QR code with your authenticator app to set up two-factor authentication."
            )
            return render_template("display_qr.html", qr_b64=qr_b64)
    except Exception as e:
        logger.error(f"Error during GitHub OAuth callback: {e}")
        flash("An error occurred during GitHub authentication. Please try again.", "error")
        return redirect(url_for("login"))

# Run the Flask application
if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

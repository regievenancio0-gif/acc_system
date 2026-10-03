"""
ACC Consultation System - Flask + SQLite
Roles (RBAC): super_admin, expert (Medical Expert), student
"""
import os, secrets, sqlite3, time
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, g, render_template, request, redirect,
                   url_for, session, flash, abort)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "acc.db")

# ---------- SECURITY CONFIG ----------
app.config.update(
    # Set SECRET_KEY in the environment for production so sessions survive restarts.
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,      # JS cannot read the session cookie
    SESSION_COOKIE_SAMESITE="Lax",     # blocks most cross-site request forgery
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS") == "1",  # cookie only over HTTPS in prod
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),      # auto-logout
)
ROLES = ("super_admin", "expert", "student")
LOGIN_ATTEMPTS = {}  # ip -> [timestamps]; simple brute-force throttle (use Redis in prod)


# ---------- DATABASE ----------
def get_db():
    """Open one SQLite connection per request (stored on flask.g)."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    """Close the connection when the request ends."""
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    """Create tables and seed the first Super Admin (change the password!)."""
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('super_admin','expert','student')),
        created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    CREATE TABLE IF NOT EXISTS consultations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        expert_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        topic TEXT NOT NULL, details TEXT, schedule TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
            CHECK(status IN ('pending','approved','declined','completed','cancelled')),
        response TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
    """)
    if not db.execute("SELECT 1 FROM users WHERE role='super_admin'").fetchone():
        pw = os.environ.get("ADMIN_PASSWORD", "Admin@12345")
        db.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                   ("Super Admin", "admin@acc.local", generate_password_hash(pw), "super_admin"))
        print("Seeded admin@acc.local - CHANGE THE PASSWORD.")
    db.commit(); db.close()


# ---------- AUTH / RBAC HELPERS ----------
@app.before_request
def load_user_and_check_csrf():
    """Load the logged-in user and verify the CSRF token on every POST."""
    g.user = None
    if session.get("uid"):
        g.user = get_db().execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
        if g.user is None:
            session.clear()
    if request.method == "POST":
        token = session.get("csrf")
        if not token or not secrets.compare_digest(token, request.form.get("csrf", "")):
            abort(400, "Invalid CSRF token")


@app.context_processor
def inject_globals():
    """Expose csrf_token() and current user to every template."""
    def csrf_token():
        session.setdefault("csrf", secrets.token_hex(16))
        return session["csrf"]
    return dict(csrf_token=csrf_token, user=g.get("user"))


@app.after_request
def security_headers(resp):
    """Browser-side protections: no sniffing, no framing, restrictive CSP."""
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def roles_required(*allowed):
    """Decorator: user must be logged in AND hold one of the allowed roles."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if g.user is None:
                return redirect(url_for("login"))
            if g.user["role"] not in allowed:
                abort(403)  # authenticated but not authorized
            return fn(*a, **kw)
        return wrapper
    return deco


def throttled(ip):
    """True if this IP made 5+ login attempts in the last 5 minutes."""
    now = time.time()
    LOGIN_ATTEMPTS[ip] = [t for t in LOGIN_ATTEMPTS.get(ip, []) if now - t < 300]
    return len(LOGIN_ATTEMPTS[ip]) >= 5


# ---------- PUBLIC ROUTES ----------
@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    """Self-registration is STUDENT ONLY. Role is set server-side, never from the form."""
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        email = request.form.get("email", "").strip().lower()[:120]
        pw = request.form.get("password", "")
        if not name or "@" not in email or len(pw) < 8:
            flash("Enter a name, valid email, and a password of 8+ characters.", "error")
        else:
            try:
                get_db().execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'student')",
                                 (name, email, generate_password_hash(pw)))
                get_db().commit()
                flash("Account created. Please log in.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "error")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Verify hashed password; rotate the session on success (prevents fixation)."""
    if request.method == "POST":
        ip = request.remote_addr
        if throttled(ip):
            flash("Too many attempts. Try again in a few minutes.", "error")
            return render_template("auth.html", mode="login"), 429
        email = request.form.get("email", "").strip().lower()
        row = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if row and check_password_hash(row["password_hash"], request.form.get("password", "")):
            session.clear(); session["uid"] = row["id"]; session.permanent = True
            return redirect(url_for("dashboard"))
        LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())
        flash("Invalid email or password.", "error")  # generic: don't reveal which was wrong
    return render_template("auth.html", mode="login")


@app.route("/logout", methods=["POST"])
@roles_required(*ROLES)
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------- DASHBOARD (content depends on role) ----------
@app.route("/dashboard")
@roles_required(*ROLES)
def dashboard():
    db, u, ctx = get_db(), g.user, {}
    base = """SELECT c.*, s.name AS student_name, e.name AS expert_name
              FROM consultations c JOIN users s ON s.id=c.student_id
              JOIN users e ON e.id=c.expert_id """
    if u["role"] == "student":
        ctx["consults"] = db.execute(base + "WHERE c.student_id=? ORDER BY c.id DESC", (u["id"],)).fetchall()
        ctx["experts"] = db.execute("SELECT id,name FROM users WHERE role='expert'").fetchall()
    elif u["role"] == "expert":
        ctx["consults"] = db.execute(base + "WHERE c.expert_id=? ORDER BY c.id DESC", (u["id"],)).fetchall()
    else:
        ctx["consults"] = db.execute(base + "ORDER BY c.id DESC").fetchall()
        ctx["users"] = db.execute("SELECT id,name,email,role FROM users ORDER BY role,name").fetchall()
    return render_template("dashboard.html", **ctx)


# ---------- STUDENT ACTIONS ----------
@app.route("/consult/new", methods=["POST"])
@roles_required("student")
def consult_new():
    """Student books a consultation. All inputs validated server-side; SQL is parameterized."""
    f = request.form
    expert = get_db().execute("SELECT id FROM users WHERE id=? AND role='expert'",
                              (f.get("expert_id", type=int),)).fetchone()
    topic = f.get("topic", "").strip()[:120]
    try:
        when = datetime.fromisoformat(f.get("schedule", ""))
    except ValueError:
        when = None
    if not (expert and topic and when and when > datetime.now()):
        flash("Pick an expert, a topic, and a future date/time.", "error")
    else:
        get_db().execute("INSERT INTO consultations(student_id,expert_id,topic,details,schedule) VALUES(?,?,?,?,?)",
                         (g.user["id"], expert["id"], topic, f.get("details", "").strip()[:1000], when.isoformat()))
        get_db().commit(); flash("Consultation requested!", "ok")
    return redirect(url_for("dashboard"))


@app.route("/consult/<int:cid>/cancel", methods=["POST"])
@roles_required("student")
def consult_cancel(cid):
    """Students may cancel only THEIR OWN pending requests (ownership check in SQL)."""
    get_db().execute("UPDATE consultations SET status='cancelled' WHERE id=? AND student_id=? AND status='pending'",
                     (cid, g.user["id"]))
    get_db().commit()
    return redirect(url_for("dashboard"))


# ---------- EXPERT ACTIONS ----------
@app.route("/consult/<int:cid>/respond", methods=["POST"])
@roles_required("expert")
def consult_respond(cid):
    """Expert updates status/response ONLY on consultations assigned to them."""
    status = request.form.get("status")
    if status not in ("approved", "declined", "completed"):
        abort(400)
    cur = get_db().execute("UPDATE consultations SET status=?, response=? WHERE id=? AND expert_id=?",
                           (status, request.form.get("response", "").strip()[:1000], cid, g.user["id"]))
    get_db().commit()
    if cur.rowcount == 0:
        abort(404)
    flash("Consultation updated.", "ok")
    return redirect(url_for("dashboard"))


# ---------- SUPER ADMIN ACTIONS ----------
@app.route("/admin/users/create", methods=["POST"])
@roles_required("super_admin")
def admin_create_user():
    """Only the Super Admin can create Medical Experts (or other admins)."""
    f = request.form
    role = f.get("role")
    if role not in ("expert", "super_admin") or len(f.get("password", "")) < 8:
        flash("Invalid role or password too short (8+).", "error")
    else:
        try:
            get_db().execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                             (f.get("name", "").strip()[:80], f.get("email", "").strip().lower()[:120],
                              generate_password_hash(f["password"]), role))
            get_db().commit(); flash("User created.", "ok")
        except sqlite3.IntegrityError:
            flash("Email already exists.", "error")
    return redirect(url_for("dashboard"))


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@roles_required("super_admin")
def admin_delete_user(uid):
    """Delete a user (an admin cannot delete themselves)."""
    if uid == g.user["id"]:
        flash("You cannot delete your own account.", "error")
    else:
        get_db().execute("DELETE FROM users WHERE id=?", (uid,)); get_db().commit()
        flash("User deleted.", "ok")
    return redirect(url_for("dashboard"))


@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(400)
def error(e):
    """Friendly error page that leaks no internals."""
    return render_template("auth.html", mode="error", err=e), e.code


if __name__ == "__main__":
    init_db()
    app.run(debug=False)  # NEVER run debug=True in production (exposes a code console)

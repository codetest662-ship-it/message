import mimetypes
import os
import time
import uuid
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from types import SimpleNamespace

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
import psycopg2
from psycopg2.extras import RealDictCursor
from sqlalchemy import event
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB
BASE_DIR = Path(__file__).resolve().parent
LOCAL_UPLOAD_DIR = Path(os.environ.get("LOCAL_UPLOAD_DIR", BASE_DIR / "uploads" / "local_pg"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES

# 1) Neon connection: READ-ONLY history & account/room lookup (never written to)
neon_url = os.environ.get("NEON_DATABASE_URL") or os.environ.get("DATABASE_URL")
if not neon_url:
    raise RuntimeError("NEON_DATABASE_URL (or DATABASE_URL) is required to read existing Neon data.")

if neon_url.startswith("postgres://"):
    neon_url = neon_url.replace("postgres://", "postgresql://", 1)
if neon_url.startswith("postgresql://"):
    neon_url = neon_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = neon_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "connect_args": {"options": "-c default_transaction_read_only=on"},
}

# 2) Secondary laptop PostgreSQL connection: writable target for all new text & files
LOCAL_PG_HOST = os.environ.get("LOCAL_PG_HOST", "192.168.18.100")
LOCAL_PG_PORT = int(os.environ.get("LOCAL_PG_PORT", "5432"))
LOCAL_PG_DB = os.environ.get("LOCAL_PG_DB", "messenger_db")
LOCAL_PG_USER = os.environ.get("LOCAL_PG_USER", "postgres")
LOCAL_PG_PASSWORD = os.environ.get("LOCAL_PG_PASSWORD", "Farhan@12")

db = SQLAlchemy(app)
TYPING_STATE = {}


@event.listens_for(db.session, "before_flush")
def _prevent_neon_writes(sess, flush_context, instances):
    # Strictly block any ORM flush against Neon
    for obj in list(sess.new):
        sess.expunge(obj)
    for obj in list(sess.dirty):
        sess.expunge(obj)
    for obj in list(sess.deleted):
        sess.expunge(obj)


def get_local_pg_conn():
    """Connect to PostgreSQL running on the secondary laptop (192.168.18.100)."""
    return psycopg2.connect(
        host=LOCAL_PG_HOST,
        port=LOCAL_PG_PORT,
        dbname=LOCAL_PG_DB,
        user=LOCAL_PG_USER,
        password=LOCAL_PG_PASSWORD,
        connect_timeout=5,
    )


def ensure_local_schema_and_refs(user, room):
    """Ensure local tables exist and mirror referenced user/room IDs for foreign keys."""
    LOCAL_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with get_local_pg_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS "user" (
                    id INTEGER PRIMARY KEY,
                    username VARCHAR(80) NOT NULL,
                    email VARCHAR(120) NOT NULL,
                    friend_number VARCHAR(12) NOT NULL DEFAULT '0000000000',
                    bio VARCHAR(300) NOT NULL DEFAULT '',
                    pfp_filename VARCHAR(255),
                    pfp_data TEXT,
                    last_seen TIMESTAMP
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_room (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(120),
                    is_group BOOLEAN NOT NULL DEFAULT FALSE,
                    created_by INTEGER NOT NULL
                );
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS message (
                    id SERIAL PRIMARY KEY,
                    room_id INTEGER NOT NULL REFERENCES chat_room(id),
                    sender_id INTEGER NOT NULL REFERENCES "user"(id),
                    body TEXT,
                    msg_type VARCHAR(20) NOT NULL DEFAULT 'text',
                    file_filename VARCHAR(255),
                    original_filename VARCHAR(255),
                    file_mime VARCHAR(120),
                    reply_to_id INTEGER REFERENCES message(id),
                    is_read BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
            if user:
                cur.execute(
                    """
                    INSERT INTO "user" (id, username, email, friend_number, bio, pfp_filename, pfp_data, last_seen)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING;
                    """,
                    (
                        user.id,
                        user.username,
                        user.email,
                        user.friend_number or "0000000000",
                        user.bio or "",
                        user.pfp_filename,
                        user.pfp_data,
                        user.last_seen,
                    ),
                )
            if room:
                cur.execute(
                    """
                    INSERT INTO chat_room (id, name, is_group, created_by)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (id) DO NOTHING;
                    """,
                    (room.id, room.name, bool(room.is_group), room.created_by),
                )


def save_uploaded_bytes(raw_bytes, original_name, fallback_ext=".bin"):
    """Save file bytes to local disk and return (stored_filename, clean_original_name, mime_type)."""
    LOCAL_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    clean_orig = secure_filename(original_name or "") or f"file{fallback_ext}"
    ext = Path(clean_orig).suffix or fallback_ext
    stored_name = f"{uuid.uuid4().hex}{ext}"
    target_path = LOCAL_UPLOAD_DIR / stored_name
    with open(target_path, "wb") as f:
        f.write(raw_bytes)
    mime_type = mimetypes.guess_type(clean_orig)[0] or "application/octet-stream"
    return stored_name, clean_orig, mime_type


def fetch_local_messages(room_id, after_id=0, search_q=""):
    """Read saved messages and files from the secondary laptop's PostgreSQL."""
    try:
        with get_local_pg_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                sql = """
                    SELECT
                        m.id,
                        m.room_id,
                        m.sender_id,
                        COALESCE(u.username, 'User') AS sender_name,
                        u.pfp_data AS sender_avatar,
                        m.body,
                        m.msg_type,
                        m.file_filename,
                        m.original_filename,
                        m.file_mime,
                        m.reply_to_id,
                        m.is_read,
                        m.created_at
                    FROM message m
                    LEFT JOIN "user" u ON u.id = m.sender_id
                    WHERE m.room_id = %s AND m.id > %s
                """
                params = [room_id, after_id]
                if search_q:
                    sql += " AND (m.body ILIKE %s OR m.original_filename ILIKE %s)"
                    like_q = f"%{search_q}%"
                    params.extend([like_q, like_q])
                sql += " ORDER BY m.id ASC;"
                cur.execute(sql, params)
                return cur.fetchall()
    except psycopg2.Error as exc:
        app.logger.warning("Local PostgreSQL read failed: %s", exc)
        return []


# --- Models (matches existing tables in Neon; read-only) ---
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    friend_number = db.Column(db.String(12), unique=True, nullable=False)
    bio = db.Column(db.String(300), default="", nullable=False)
    pfp_filename = db.Column(db.String(255), nullable=True)
    pfp_data = db.Column(db.Text, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_online(self):
        if not self.last_seen:
            return False
        return (datetime.utcnow() - self.last_seen) < timedelta(minutes=2)

    @property
    def avatar_src(self):
        return self.pfp_data or None


class Friendship(db.Model):
    __tablename__ = "friendship"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), default="accepted", nullable=False)
    muted = db.Column(db.Boolean, default=False, nullable=False)


class ChatRoom(db.Model):
    __tablename__ = "chat_room"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=True)
    is_group = db.Column(db.Boolean, default=False, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class ChatMember(db.Model):
    __tablename__ = "chat_member"
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timeout_until = db.Column(db.DateTime, nullable=True)


class GroupBan(db.Model):
    __tablename__ = "group_ban"
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Message(db.Model):
    __tablename__ = "message"
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=True)
    msg_type = db.Column(db.String(20), default="text", nullable=False)
    file_filename = db.Column(db.String(255), nullable=True)
    original_filename = db.Column(db.String(255), nullable=True)
    file_mime = db.Column(db.String(120), nullable=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sender = db.relationship("User", foreign_keys=[sender_id])
    reply_to = db.relationship("Message", remote_side=[id])


@app.errorhandler(413)
def handle_too_large(e):
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"error": "File exceeds 100 MB limit."}), 413
    flash("File exceeds the 100 MB limit.")
    return redirect(request.referrer or url_for("index"))


def current_user():
    if hasattr(g, "_cached_user"):
        return g._cached_user
    uid = session.get("user_id")
    user = db.session.get(User, uid) if uid else None
    g._cached_user = user
    return user


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            session.pop("user_id", None)
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login", next=request.full_path if request.query_string else request.path))
        return fn(*args, **kwargs)

    return wrapper


def iso_utc(dt):
    if not dt:
        return ""
    if isinstance(dt, str):
        return dt
    return dt.replace(microsecond=0).isoformat() + "Z"


def get_active_typing_users(room_id, viewer_id, muted_user_ids):
    now_ts = time.time()
    room_map = TYPING_STATE.get(room_id)
    if not room_map:
        return []
    expired = [uid for uid, info in room_map.items() if info.get("expires_at", 0) <= now_ts]
    for uid in expired:
        del room_map[uid]
    return [
        info["username"]
        for uid, info in room_map.items()
        if uid != viewer_id and uid not in muted_user_ids and info.get("username")
    ]


def get_friends_data(user_id):
    outgoing = Friendship.query.filter_by(user_id=user_id).all()
    incoming = Friendship.query.filter_by(friend_id=user_id).all()
    rel_map = {}
    friend_ids_ordered = []
    muted_user_ids = set()

    for r in outgoing:
        rel_map[r.friend_id] = r
        if r.muted:
            muted_user_ids.add(r.friend_id)
        if r.friend_id not in friend_ids_ordered and r.friend_id != user_id:
            friend_ids_ordered.append(r.friend_id)

    for r in incoming:
        if r.user_id not in rel_map:
            rel_map[r.user_id] = r
        if r.user_id not in friend_ids_ordered and r.user_id != user_id:
            friend_ids_ordered.append(r.user_id)

    friend_users_by_id = (
        {u.id: u for u in User.query.filter(User.id.in_(friend_ids_ordered)).all()}
        if friend_ids_ordered
        else {}
    )
    friends = [friend_users_by_id[fid] for fid in friend_ids_ordered if fid in friend_users_by_id]
    return friends, rel_map, muted_user_ids, friend_users_by_id


def get_user_rooms_sidebar(user_id, extra_users_by_id=None):
    users_cache = dict(extra_users_by_id or {})
    my_memberships = ChatMember.query.filter_by(user_id=user_id).all()
    my_room_ids = [m.room_id for m in my_memberships]

    rooms_by_id = (
        {r.id: r for r in ChatRoom.query.filter(ChatRoom.id.in_(my_room_ids)).all()}
        if my_room_ids
        else {}
    )

    all_room_members = ChatMember.query.filter(ChatMember.room_id.in_(my_room_ids)).all() if my_room_ids else []
    other_user_id_by_room = {}
    needed_user_ids = set()
    for mem in all_room_members:
        if mem.user_id != user_id and mem.room_id not in other_user_id_by_room:
            other_user_id_by_room[mem.room_id] = mem.user_id
            needed_user_ids.add(mem.user_id)

    missing_uids = [uid for uid in needed_user_ids if uid not in users_cache]
    if missing_uids:
        for u in User.query.filter(User.id.in_(missing_uids)).all():
            users_cache[u.id] = u

    rooms_sidebar = []
    for rid in my_room_ids:
        room = rooms_by_id.get(rid)
        if not room:
            continue
        if room.is_group:
            rooms_sidebar.append({
                "room": room,
                "url": url_for("chat_room", room_id=room.id),
                "title": room.name or "",
                "avatar_src": None,
                "is_group": True,
                "other_user": None,
            })
        else:
            other_id = other_user_id_by_room.get(room.id)
            other = users_cache.get(other_id) if other_id else None
            rooms_sidebar.append({
                "room": room,
                "url": url_for("chat_room", room_id=room.id),
                "title": other.username if other else "",
                "avatar_src": other.avatar_src if other else None,
                "is_group": False,
                "other_user": other,
            })

    return rooms_sidebar, rooms_by_id, other_user_id_by_room, users_cache


def build_neon_message_view(msg, muted_user_ids, users_cache):
    muted_sender = msg.sender_id in muted_user_ids
    sender_obj = users_cache.get(msg.sender_id) or msg.sender
    rep_sender = (users_cache.get(msg.reply_to.sender_id) or msg.reply_to.sender) if msg.reply_to else None
    mime_type = msg.file_mime or ""
    is_image = bool(not muted_sender and msg.file_filename and mime_type.startswith("image/"))
    return {
        "id": -abs(msg.id),
        "sender": sender_obj,
        "body": "[Muted]" if muted_sender else (msg.body or ""),
        "msg_type": msg.msg_type or "text",
        "file_filename": None if muted_sender else msg.file_filename,
        "original_filename": None if muted_sender else msg.original_filename,
        "media_url": "",
        "is_image": is_image,
        "created_iso": iso_utc(msg.created_at),
        "muted": muted_sender,
        "is_read": bool(msg.is_read),
        "can_delete": False,
        "reply_to": msg.reply_to,
        "reply_sender_name": rep_sender.username if rep_sender else "User",
    }


def serialize_local_message(row, user_id, muted_user_ids, users_cache):
    muted_sender = row["sender_id"] in muted_user_ids
    sender = users_cache.get(row["sender_id"])
    sender_name = sender.username if sender else (row.get("sender_name") or "User")
    stored_file = row.get("file_filename") or ""
    mime_type = row.get("file_mime") or ""
    is_image = bool(not muted_sender and stored_file and mime_type.startswith("image/"))
    file_url = url_for("serve_local_upload", filename=stored_file) if (not muted_sender and stored_file) else ""
    download_url = (
        url_for("serve_local_upload", filename=stored_file, download=1)
        if (not muted_sender and stored_file)
        else ""
    )

    return {
        "id": row["id"],
        "sender_id": row["sender_id"],
        "sender_name": sender_name,
        "sender_initial": sender_name[0].upper() if sender_name else "?",
        "sender_avatar": (sender.avatar_src if sender else row.get("sender_avatar")) or "",
        "sender_online": bool(sender.is_online) if sender else False,
        "created_iso": iso_utc(row.get("created_at")),
        "body": "[Muted]" if muted_sender else (row.get("body") or ""),
        "msg_type": row.get("msg_type") or "text",
        "file_filename": None if muted_sender else (stored_file or None),
        "original_filename": None if muted_sender else (row.get("original_filename") or ""),
        "is_image": is_image,
        "file_url": file_url,
        "download_url": download_url,
        "is_read": bool(row.get("is_read")),
        "can_delete": False,
        "status_label": ("Seen" if row.get("is_read") else "Saved to PC") if row["sender_id"] == user_id else "",
        "reply_to": None,
    }


@app.route("/uploads/local/<path:filename>")
@login_required
def serve_local_upload(filename):
    safe_name = Path(filename).name
    as_attachment = bool(request.args.get("download"))
    return send_from_directory(LOCAL_UPLOAD_DIR, safe_name, as_attachment=as_attachment)


@app.route("/welcome")
def welcome():
    if current_user():
        return redirect(url_for("index"))
    return render_template("welcome.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("index"))
    if request.method == "POST":
        flash("Saving to Neon is disabled.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("index"))
    next_url = request.args.get("next") or request.form.get("next") or ""
    if not next_url.startswith("/"):
        next_url = url_for("index")
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter((User.username == identifier) | (User.email == identifier.lower())).first()
        if user and user.check_password(password):
            session["user_id"] = user.id
            g._cached_user = user
            return redirect(next_url)
        flash("Invalid credentials.")
    return render_template("login.html", next_url=next_url)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        flash("Saving to Neon is disabled.")
        return redirect(url_for("login"))
    return render_template("forgot_password.html")


@app.route("/logout", methods=["POST", "GET"])
@login_required
def logout():
    session.pop("user_id", None)
    g._cached_user = None
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@app.route("/profile/<int:target_user_id>", methods=["GET"])
@login_required
def profile(target_user_id=None):
    me = current_user()
    viewed_user = me if not target_user_id else db.session.get(User, target_user_id)
    if not viewed_user:
        flash("User not found.")
        return redirect(url_for("profile"))
    if request.method == "POST":
        flash("Profile changes are not saved to Neon.")
        return redirect(url_for("profile"))
    return render_template(
        "profile.html",
        user=me,
        viewed_user=viewed_user,
        is_self=(viewed_user.id == me.id),
        shared_media=[],
        active_nav="profile",
    )


@app.route("/friends", methods=["GET"])
@login_required
def friends_page():
    user = current_user()
    friends, rel_map, _, _ = get_friends_data(user.id)
    return render_template("friends.html", user=user, friends=friends, rel_map=rel_map, active_nav="friends")


@app.route("/friends/add", methods=["POST"])
@login_required
def add_friend():
    flash("Friend updates are not saved to Neon.")
    return redirect(url_for("friends_page"))


@app.route("/friends/action", methods=["POST"])
@login_required
def friend_action():
    flash("Friend updates are not saved to Neon.")
    return redirect(url_for("friends_page"))


@app.route("/dm/<int:friend_id>")
@login_required
def open_dm(friend_id):
    user = current_user()
    a_rooms = {m.room_id for m in ChatMember.query.filter_by(user_id=user.id).all()}
    b_rooms = {m.room_id for m in ChatMember.query.filter_by(user_id=friend_id).all()}
    for rid in a_rooms.intersection(b_rooms):
        room = db.session.get(ChatRoom, rid)
        if room and not room.is_group:
            return redirect(url_for("chat_room", room_id=room.id))
    flash("No existing DM room found in Neon.")
    return redirect(url_for("index"))


@app.route("/groups/create", methods=["GET", "POST"])
@login_required
def create_group():
    user = current_user()
    friends, _, _, _ = get_friends_data(user.id)
    if request.method == "POST":
        flash("New groups are not saved to Neon.")
        return redirect(url_for("index"))
    return render_template("create_group.html", user=user, friends=friends, active_nav="chats")


@app.route("/groups/<int:room_id>/leave", methods=["POST"])
@app.route("/groups/<int:room_id>/delete", methods=["POST"])
@app.route("/groups/<int:room_id>/manage", methods=["POST"])
@login_required
def group_action(room_id):
    flash("Group changes are not saved to Neon.")
    return redirect(url_for("chat_room", room_id=room_id))


@app.route("/index")
@app.route("/", methods=["GET"])
@login_required
def index():
    user = current_user()
    _, _, _, friend_users_by_id = get_friends_data(user.id)
    rooms_sidebar, _, _, _ = get_user_rooms_sidebar(user.id, friend_users_by_id)
    return render_template("chats_list.html", user=user, rooms_sidebar=rooms_sidebar, active_nav="chats")


@app.route("/chat/<int:room_id>", methods=["GET"])
@login_required
def chat_room(room_id):
    user = current_user()
    if GroupBan.query.filter_by(room_id=room_id, user_id=user.id).first():
        flash("You are banned from this group.")
        return redirect(url_for("index"))
    membership = ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first()
    if not membership:
        return redirect(url_for("index"))

    search_q = request.args.get("search", "").strip()
    _, _, muted_user_ids, friend_users_by_id = get_friends_data(user.id)
    rooms_sidebar, rooms_by_id, other_user_id_by_room, users_cache = get_user_rooms_sidebar(
        user.id, friend_users_by_id
    )
    active_room = rooms_by_id.get(room_id)
    if not active_room:
        return redirect(url_for("index"))

    active_room_title = active_room.name or ""
    active_room_other_user = None
    if not active_room.is_group:
        other_id = other_user_id_by_room.get(active_room.id)
        other = users_cache.get(other_id) if other_id else None
        active_room_other_user = other
        active_room_title = other.username if other else ""

    room_members_rows = ChatMember.query.filter_by(room_id=active_room.id).all()
    banned_rows = GroupBan.query.filter_by(room_id=active_room.id).all()
    for uid in {m.user_id for m in room_members_rows} | {b.user_id for b in banned_rows}:
        if uid not in users_cache:
            u = db.session.get(User, uid)
            if u:
                users_cache[uid] = u

    now = datetime.utcnow()
    members_view = [
        {
            "user": users_cache[m.user_id],
            "is_admin": m.user_id == active_room.created_by,
            "is_timed_out": bool(m.timeout_until and m.timeout_until > now),
            "timeout_until_iso": iso_utc(m.timeout_until) if (m.timeout_until and m.timeout_until > now) else "",
        }
        for m in room_members_rows
        if m.user_id in users_cache
    ]
    banned_users_view = [users_cache[b.user_id] for b in banned_rows if b.user_id in users_cache]
    is_group_admin = bool(active_room.is_group and active_room.created_by == user.id)
    my_timed_out = bool(membership.timeout_until and membership.timeout_until > now)

    # 1) Load all historical Neon messages (read-only)
    neon_q = Message.query.filter_by(room_id=active_room.id)
    if search_q:
        like_q = f"%{search_q}%"
        neon_q = neon_q.filter((Message.body.ilike(like_q)) | (Message.original_filename.ilike(like_q)))
    neon_msgs = neon_q.order_by(Message.id.asc()).all()
    messages_view = [build_neon_message_view(msg, muted_user_ids, users_cache) for msg in neon_msgs]

    # 2) Append all newly saved messages/files from secondary laptop PostgreSQL
    local_rows = fetch_local_messages(active_room.id, after_id=0, search_q=search_q)
    for row in local_rows:
        muted_sender = row["sender_id"] in muted_user_ids
        sender_obj = users_cache.get(row["sender_id"]) or db.session.get(User, row["sender_id"])
        if not sender_obj:
            sender_obj = SimpleNamespace(
                id=row["sender_id"],
                username=row.get("sender_name") or "User",
                avatar_src=row.get("sender_avatar"),
                is_online=False,
            )
        stored_file = row.get("file_filename") or ""
        mime_type = row.get("file_mime") or ""
        is_image = bool(not muted_sender and stored_file and mime_type.startswith("image/"))
        media_url = url_for("serve_local_upload", filename=stored_file) if (not muted_sender and stored_file) else ""
        messages_view.append({
            "id": row["id"],
            "sender": sender_obj,
            "body": "[Muted]" if muted_sender else (row.get("body") or ""),
            "msg_type": row.get("msg_type") or "text",
            "file_filename": None if muted_sender else (stored_file or None),
            "original_filename": None if muted_sender else row.get("original_filename"),
            "media_url": media_url,
            "is_image": is_image,
            "created_iso": iso_utc(row.get("created_at")),
            "muted": muted_sender,
            "is_read": bool(row.get("is_read")),
            "can_delete": False,
            "reply_to": None,
            "reply_sender_name": "User",
        })

    return render_template(
        "chat_room.html",
        user=user,
        rooms_sidebar=rooms_sidebar,
        active_room=active_room,
        active_room_title=active_room_title,
        active_room_other_user=active_room_other_user,
        members_view=members_view,
        banned_users_view=banned_users_view,
        is_group_admin=is_group_admin,
        my_timed_out=my_timed_out,
        messages=messages_view,
        search_q=search_q,
        active_nav="chats",
    )


@app.route("/api/typing/<int:room_id>", methods=["POST"])
@login_required
def api_typing(room_id):
    user = current_user()
    if GroupBan.query.filter_by(room_id=room_id, user_id=user.id).first():
        return jsonify({"error": "Forbidden"}), 403
    if not ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first():
        return jsonify({"error": "Forbidden"}), 403
    TYPING_STATE.setdefault(room_id, {})[user.id] = {"username": user.username, "expires_at": time.time() + 4.0}
    return jsonify({"ok": True})


@app.route("/api/messages/<int:room_id>")
@login_required
def api_messages(room_id):
    user = current_user()
    if GroupBan.query.filter_by(room_id=room_id, user_id=user.id).first() or not ChatMember.query.filter_by(
        room_id=room_id, user_id=user.id
    ).first():
        return jsonify({"error": "Forbidden"}), 403

    after_id = request.args.get("after_id", 0, type=int)
    local_after = max(0, after_id)
    local_rows = fetch_local_messages(room_id, after_id=local_after)

    muted_user_ids = {r.friend_id for r in Friendship.query.filter_by(user_id=user.id, muted=True).all()}
    sender_ids = {row["sender_id"] for row in local_rows} | {user.id}
    users_cache = {u.id: u for u in User.query.filter(User.id.in_(sender_ids)).all()} if sender_ids else {}

    other_online = None
    room = db.session.get(ChatRoom, room_id)
    if room and not room.is_group:
        other_m = ChatMember.query.filter(ChatMember.room_id == room_id, ChatMember.user_id != user.id).first()
        if other_m:
            other_u = db.session.get(User, other_m.user_id)
            if other_u:
                other_online = bool(other_u.is_online)

    serialized = [serialize_local_message(row, user.id, muted_user_ids, users_cache) for row in local_rows]

    return jsonify({
        "messages": serialized,
        "read_statuses": {},
        "other_online": other_online,
        "deleted_ids": [],
        "typing_users": get_active_typing_users(room_id, user.id, muted_user_ids),
    })


@app.route("/messages/send/<int:room_id>", methods=["POST"])
@login_required
def send_message(room_id):
    user = current_user()
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"

    if GroupBan.query.filter_by(room_id=room_id, user_id=user.id).first() or not ChatMember.query.filter_by(
        room_id=room_id, user_id=user.id
    ).first():
        return (jsonify({"error": "Forbidden"}), 403) if is_ajax else redirect(url_for("index"))

    room = db.session.get(ChatRoom, room_id)
    body = (request.form.get("body") or "").strip()
    msg_type = "text"
    stored_filename = None
    original_filename = ""
    file_mime = None

    voice_file = request.files.get("voice_data")
    attachment_file = request.files.get("attachment")

    if voice_file and voice_file.filename:
        raw_voice = voice_file.read()
        if len(raw_voice) > MAX_UPLOAD_BYTES:
            return (jsonify({"error": "File exceeds 100 MB limit."}), 413) if is_ajax else redirect(
                url_for("chat_room", room_id=room_id)
            )
        msg_type = "voice"
        stored_filename, original_filename, file_mime = save_uploaded_bytes(
            raw_voice, voice_file.filename, fallback_ext=".webm"
        )
    elif attachment_file and attachment_file.filename:
        raw_att = attachment_file.read()
        if len(raw_att) > MAX_UPLOAD_BYTES:
            return (jsonify({"error": "File exceeds 100 MB limit."}), 413) if is_ajax else redirect(
                url_for("chat_room", room_id=room_id)
            )
        msg_type = "file"
        stored_filename, original_filename, file_mime = save_uploaded_bytes(
            raw_att, attachment_file.filename, fallback_ext=".bin"
        )

    if not body and msg_type == "text":
        if is_ajax:
            return jsonify({"error": "Message cannot be empty."}), 400
        return redirect(url_for("chat_room", room_id=room_id))

    reply_to_id = request.form.get("reply_to_id", type=int)

    try:
        ensure_local_schema_and_refs(user, room)
        with get_local_pg_conn() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                valid_reply_id = None
                if reply_to_id and reply_to_id > 0:
                    cur.execute("SELECT id FROM message WHERE id = %s AND room_id = %s;", (reply_to_id, room_id))
                    rep = cur.fetchone()
                    if rep:
                        valid_reply_id = rep["id"]

                cur.execute(
                    """
                    INSERT INTO message (
                        room_id, sender_id, body, msg_type,
                        file_filename, original_filename, file_mime,
                        reply_to_id, is_read, created_at
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, FALSE, %s)
                    RETURNING
                        id, room_id, sender_id, body, msg_type,
                        file_filename, original_filename, file_mime,
                        reply_to_id, is_read, created_at;
                    """,
                    (
                        room_id,
                        user.id,
                        body,
                        msg_type,
                        stored_filename,
                        original_filename,
                        file_mime,
                        valid_reply_id,
                        datetime.utcnow(),
                    ),
                )
                saved_row = cur.fetchone()
                saved_row["sender_name"] = user.username
                saved_row["sender_avatar"] = user.avatar_src
    except psycopg2.Error as exc:
        err_msg = f"Failed to save to secondary laptop PostgreSQL: {exc}"
        if is_ajax:
            return jsonify({"error": err_msg}), 500
        flash(err_msg)
        return redirect(url_for("chat_room", room_id=room_id))

    if is_ajax:
        muted_user_ids = {r.friend_id for r in Friendship.query.filter_by(user_id=user.id, muted=True).all()}
        return jsonify({
            "ok": True,
            "message": serialize_local_message(saved_row, user.id, muted_user_ids, {user.id: user}),
        })
    return redirect(url_for("chat_room", room_id=room_id))


@app.route("/messages/delete/<int:message_id>", methods=["POST"])
@app.route("/messages/forward/<int:message_id>", methods=["POST"])
@login_required
def message_action(message_id):
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if is_ajax:
        return jsonify({"ok": True, "note": "Changes are not saved to Neon."})
    flash("Message changes are not saved to Neon.")
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
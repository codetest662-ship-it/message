import base64
import os
import random
import secrets
from datetime import datetime, timedelta
from functools import wraps

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
from sqlalchemy import inspect, text
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")

db_url = os.environ.get("DATABASE_URL")
if db_url:
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    if db_url.startswith("postgresql://"):
        db_url = db_url.replace("postgresql://", "postgresql+psycopg://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = db_url or f"sqlite:///{os.path.join(BASE_DIR, 'messenger.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024 * 1024

db = SQLAlchemy(app)


# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    friend_number = db.Column(db.String(12), unique=True, nullable=False)
    bio = db.Column(db.String(300), default="", nullable=False)
    pfp_filename = db.Column(db.String(255), nullable=True)
    pfp_data = db.Column(db.Text, nullable=True)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_online(self):
        if not self.last_seen:
            return False
        return (datetime.utcnow() - self.last_seen) < timedelta(minutes=2)

    @property
    def avatar_src(self):
        if self.pfp_data:
            return self.pfp_data
        if self.pfp_filename:
            return url_for("uploaded_file", filename=self.pfp_filename)
        return None


class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(20), default="accepted", nullable=False)
    muted = db.Column(db.Boolean, default=False, nullable=False)


class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=True)
    is_group = db.Column(db.Boolean, default=False, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class ChatMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    timeout_until = db.Column(db.DateTime, nullable=True)


class GroupBan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=True)
    msg_type = db.Column(db.String(20), default="text", nullable=False)
    file_filename = db.Column(db.String(255), nullable=True)
    original_filename = db.Column(db.String(255), nullable=True)
    reply_to_id = db.Column(db.Integer, db.ForeignKey("message.id"), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sender = db.relationship("User", foreign_keys=[sender_id])
    reply_to = db.relationship("Message", remote_side=[id])


def ensure_schema_columns():
    db.create_all()
    inspector = inspect(db.engine)
    tables = set(inspector.get_table_names())

    if "user" in tables:
        cols = {c["name"] for c in inspector.get_columns("user")}
        if "pfp_data" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text('ALTER TABLE "user" ADD COLUMN pfp_data TEXT'))
        if "last_seen" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text('ALTER TABLE "user" ADD COLUMN last_seen TIMESTAMP'))

    if "chat_member" in tables:
        cols = {c["name"] for c in inspector.get_columns("chat_member")}
        if "timeout_until" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE chat_member ADD COLUMN timeout_until TIMESTAMP"))

    if "message" in tables:
        cols = {c["name"] for c in inspector.get_columns("message")}
        if "reply_to_id" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text('ALTER TABLE "message" ADD COLUMN reply_to_id INTEGER'))
        if "is_read" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text('ALTER TABLE "message" ADD COLUMN is_read BOOLEAN DEFAULT FALSE'))


with app.app_context():
    ensure_schema_columns()


# --- Helpers ---
def generate_unique_friend_number():
    while True:
        num = f"{random.randint(100000, 999999)}-{random.randint(10, 99)}"
        if not User.query.filter_by(friend_number=num).first():
            return num


def current_user():
    if hasattr(g, "_cached_user"):
        return g._cached_user
    uid = session.get("user_id")
    user = db.session.get(User, uid) if uid else None
    if user:
        now = datetime.utcnow()
        if not user.last_seen or (now - user.last_seen).total_seconds() >= 20:
            user.last_seen = now
            db.session.commit()
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


def encode_pfp_data_url(file_storage):
    if not file_storage or not file_storage.filename:
        return None
    raw = file_storage.read()
    if not raw:
        return None
    mime = file_storage.mimetype or "image/png"
    b64 = base64.b64encode(raw).decode("utf-8")
    return f"data:{mime};base64,{b64}"


def save_uploaded_stream(file_storage, prefix="file"):
    ext = os.path.splitext(secure_filename(file_storage.filename or ""))[1]
    stored_name = f"{prefix}_{secrets.token_hex(12)}{ext}"
    dest_path = os.path.join(UPLOAD_DIR, stored_name)

    chunk_size = 1024 * 1024 * 4
    with open(dest_path, "wb") as out_f:
        while True:
            chunk = file_storage.stream.read(chunk_size)
            if not chunk:
                break
            out_f.write(chunk)

    return stored_name, file_storage.filename or stored_name


def is_image_filename(filename):
    ext = os.path.splitext((filename or "").lower())[1]
    return ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}


def is_blocked_between(u1_id, u2_id):
    rel1 = Friendship.query.filter_by(user_id=u1_id, friend_id=u2_id, status="blocked").first()
    rel2 = Friendship.query.filter_by(user_id=u2_id, friend_id=u1_id, status="blocked").first()
    return bool(rel1 or rel2)


def iso_utc(dt):
    if not dt:
        return ""
    return dt.replace(microsecond=0).isoformat() + "Z"


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

    friend_users_by_id = {}
    if friend_ids_ordered:
        for f_user in User.query.filter(User.id.in_(friend_ids_ordered)).all():
            friend_users_by_id[f_user.id] = f_user
    friends = [friend_users_by_id[fid] for fid in friend_ids_ordered if fid in friend_users_by_id]
    return friends, rel_map, muted_user_ids, friend_users_by_id


def get_user_rooms_sidebar(user_id, extra_users_by_id=None):
    users_cache = dict(extra_users_by_id or {})
    my_memberships = ChatMember.query.filter_by(user_id=user_id).all()
    my_room_ids = [m.room_id for m in my_memberships]

    rooms_by_id = {}
    if my_room_ids:
        for r in ChatRoom.query.filter(ChatRoom.id.in_(my_room_ids)).all():
            rooms_by_id[r.id] = r

    all_room_members = []
    if my_room_ids:
        all_room_members = ChatMember.query.filter(ChatMember.room_id.in_(my_room_ids)).all()

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


def get_shared_media_for_pair(viewer_id, target_id):
    viewer_rooms = {m.room_id for m in ChatMember.query.filter_by(user_id=viewer_id).all()}
    if viewer_id == target_id:
        shared_room_ids = list(viewer_rooms)
    else:
        target_rooms = {m.room_id for m in ChatMember.query.filter_by(user_id=target_id).all()}
        shared_room_ids = list(viewer_rooms.intersection(target_rooms))

    if not shared_room_ids:
        return []

    media_msgs = (
        Message.query.filter(
            Message.room_id.in_(shared_room_ids),
            Message.file_filename.isnot(None),
        )
        .order_by(Message.id.desc())
        .limit(12)
        .all()
    )

    items = []
    for m in media_msgs:
        label = m.original_filename or m.file_filename
        items.append({
            "id": m.id,
            "filename": m.file_filename,
            "label": label,
            "is_image": is_image_filename(label),
            "url": url_for("uploaded_file", filename=m.file_filename),
            "download_url": url_for("uploaded_file", filename=m.file_filename, download=1),
        })
    return items


def serialize_message(msg, user_id, muted_user_ids, users_cache):
    muted_sender = msg.sender_id in muted_user_ids
    sender = users_cache.get(msg.sender_id) or msg.sender
    sender_name = sender.username if sender else ""
    file_fn = None if muted_sender else (msg.file_filename or "")
    orig_fn = None if muted_sender else (msg.original_filename or "")

    reply_info = None
    if msg.reply_to and not muted_sender:
        rep_sender = users_cache.get(msg.reply_to.sender_id) or msg.reply_to.sender
        reply_info = {
            "id": msg.reply_to.id,
            "sender_name": rep_sender.username if rep_sender else "User",
            "body": msg.reply_to.body or (msg.reply_to.original_filename or "Attachment"),
        }

    return {
        "id": msg.id,
        "sender_id": msg.sender_id,
        "sender_name": sender_name,
        "sender_initial": sender_name[0].upper() if sender_name else "?",
        "sender_avatar": sender.avatar_src if sender else "",
        "sender_online": bool(sender.is_online) if sender else False,
        "created_iso": iso_utc(msg.created_at),
        "body": "[Muted]" if muted_sender else (msg.body or ""),
        "msg_type": msg.msg_type or "text",
        "file_filename": file_fn,
        "original_filename": orig_fn,
        "is_image": bool(file_fn and is_image_filename(orig_fn or file_fn)),
        "file_url": f"/uploads/{file_fn}" if file_fn else "",
        "download_url": f"/uploads/{file_fn}?download=1" if file_fn else "",
        "is_read": bool(msg.is_read),
        "status_label": ("Seen" if msg.is_read else "Delivered") if msg.sender_id == user_id else "",
        "reply_to": reply_info,
    }


# --- Auth & Entry Routes ---
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
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        bio = request.form.get("bio", "").strip()

        if not username or not email or not password:
            flash("Username, email, and password are required.")
            return render_template("register.html")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email is already taken.")
            return render_template("register.html")

        pfp_data = encode_pfp_data_url(request.files.get("pfp"))

        user = User(
            username=username,
            email=email,
            friend_number=generate_unique_friend_number(),
            bio=bio,
            pfp_data=pfp_data,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session["user_id"] = user.id
        g._cached_user = user
        return redirect(url_for("index"))

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

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            g._cached_user = user
            user.last_seen = datetime.utcnow()
            db.session.commit()
            return redirect(next_url)

        flash("Invalid credentials.")

    return render_template("login.html", next_url=next_url)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        new_password = request.form.get("new_password", "")
        user = User.query.filter_by(email=email).first()

        if not user or not new_password:
            flash("If that account exists, the password has been updated.")
            return render_template("forgot_password.html")

        user.set_password(new_password)
        db.session.commit()
        flash("Password updated.")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/logout", methods=["POST", "GET"])
@login_required
def logout():
    session.pop("user_id", None)
    g._cached_user = None
    return redirect(url_for("login"))


# --- Profile Routes ---
@app.route("/profile", methods=["GET", "POST"])
@app.route("/profile/<int:target_user_id>", methods=["GET"])
@login_required
def profile(target_user_id=None):
    me = current_user()
    viewed_user = me if not target_user_id else db.session.get(User, target_user_id)
    if not viewed_user:
        flash("User not found.")
        return redirect(url_for("profile"))

    is_self = viewed_user.id == me.id

    if request.method == "POST" and is_self:
        username = request.form.get("username", "").strip()
        bio = request.form.get("bio", "").strip()

        if username and username != me.username:
            if User.query.filter_by(username=username).first():
                flash("Username is already taken.")
                return redirect(url_for("profile"))
            me.username = username

        me.bio = bio

        new_pfp = encode_pfp_data_url(request.files.get("pfp"))
        if new_pfp:
            me.pfp_data = new_pfp

        db.session.commit()
        flash("Profile saved.")
        return redirect(url_for("profile"))

    shared_media = get_shared_media_for_pair(me.id, viewed_user.id)

    return render_template(
        "profile.html",
        user=me,
        viewed_user=viewed_user,
        is_self=is_self,
        shared_media=shared_media,
        active_nav="profile",
    )


# --- Friends Routes ---
@app.route("/friends", methods=["GET"])
@login_required
def friends_page():
    user = current_user()
    friends, rel_map, _, _ = get_friends_data(user.id)
    return render_template(
        "friends.html",
        user=user,
        friends=friends,
        rel_map=rel_map,
        active_nav="friends",
    )


@app.route("/friends/add", methods=["POST"])
@login_required
def add_friend():
    user = current_user()
    target_num = request.form.get("friend_number", "").strip()
    target = User.query.filter_by(friend_number=target_num).first()

    if not target:
        flash("No user found with that Friend Number.")
        return redirect(url_for("friends_page"))

    if target.id == user.id:
        flash("Cannot add your own Friend Number.")
        return redirect(url_for("friends_page"))

    if is_blocked_between(user.id, target.id):
        flash("User is blocked.")
        return redirect(url_for("friends_page"))

    if not Friendship.query.filter_by(user_id=user.id, friend_id=target.id).first():
        db.session.add(Friendship(user_id=user.id, friend_id=target.id, status="accepted"))

    if not Friendship.query.filter_by(user_id=target.id, friend_id=user.id).first():
        db.session.add(Friendship(user_id=target.id, friend_id=user.id, status="accepted"))

    db.session.commit()
    flash(f"Added {target.username}.")
    return redirect(url_for("friends_page"))


@app.route("/friends/action", methods=["POST"])
@login_required
def friend_action():
    user = current_user()
    target_id = int(request.form.get("target_id", 0))
    action = request.form.get("action", "")
    target = db.session.get(User, target_id)

    if not target or target.id == user.id:
        return redirect(url_for("friends_page"))

    rel = Friendship.query.filter_by(user_id=user.id, friend_id=target.id).first()

    if action == "unfriend":
        Friendship.query.filter_by(user_id=user.id, friend_id=target.id).delete()
        Friendship.query.filter_by(user_id=target.id, friend_id=user.id).delete()
        flash(f"Removed {target.username}.")
    elif action == "mute":
        if not rel:
            rel = Friendship(user_id=user.id, friend_id=target.id, status="accepted", muted=True)
            db.session.add(rel)
        else:
            rel.muted = not rel.muted
        flash("Muted." if rel.muted else "Unmuted.")
    elif action == "block":
        if not rel:
            rel = Friendship(user_id=user.id, friend_id=target.id, status="blocked", muted=True)
            db.session.add(rel)
        else:
            rel.status = "blocked"
            rel.muted = True
        flash(f"Blocked {target.username}.")
    elif action == "unblock":
        if rel and rel.status == "blocked":
            rel.status = "accepted"
            rel.muted = False
        flash(f"Unblocked {target.username}.")

    db.session.commit()
    return redirect(url_for("friends_page"))


# --- Chats, Groups & Moderation Routes ---
def get_or_create_dm(user_a_id, user_b_id):
    a_rooms = {m.room_id for m in ChatMember.query.filter_by(user_id=user_a_id).all()}
    b_rooms = {m.room_id for m in ChatMember.query.filter_by(user_id=user_b_id).all()}
    for rid in a_rooms.intersection(b_rooms):
        room = db.session.get(ChatRoom, rid)
        if room and not room.is_group:
            return room

    room = ChatRoom(name=None, is_group=False, created_by=user_a_id)
    db.session.add(room)
    db.session.flush()
    db.session.add(ChatMember(room_id=room.id, user_id=user_a_id))
    db.session.add(ChatMember(room_id=room.id, user_id=user_b_id))
    db.session.commit()
    return room


@app.route("/dm/<int:friend_id>")
@login_required
def open_dm(friend_id):
    user = current_user()
    friend = db.session.get(User, friend_id)
    if not friend or friend.id == user.id:
        return redirect(url_for("index"))
    room = get_or_create_dm(user.id, friend.id)
    return redirect(url_for("chat_room", room_id=room.id))


@app.route("/groups/create", methods=["GET", "POST"])
@login_required
def create_group():
    user = current_user()
    friends, _, _, _ = get_friends_data(user.id)

    if request.method == "POST":
        group_name = request.form.get("group_name", "").strip()
        if not group_name:
            flash("Enter a group name.")
            return redirect(url_for("create_group"))

        member_ids = [int(x) for x in request.form.getlist("member_ids") if x.isdigit()]

        room = ChatRoom(name=group_name, is_group=True, created_by=user.id)
        db.session.add(room)
        db.session.flush()

        all_members = set(member_ids + [user.id])
        for mid in all_members:
            if db.session.get(User, mid):
                db.session.add(ChatMember(room_id=room.id, user_id=mid))

        db.session.commit()
        flash(f"Created {group_name}.")
        return redirect(url_for("chat_room", room_id=room.id))

    return render_template(
        "create_group.html",
        user=user,
        friends=friends,
        active_nav="chats",
    )


@app.route("/groups/<int:room_id>/manage", methods=["POST"])
@login_required
def manage_group(room_id):
    user = current_user()
    room = db.session.get(ChatRoom, room_id)
    if not room or not room.is_group:
        flash("Group not found.")
        return redirect(url_for("index"))

    if room.created_by != user.id:
        flash("Only the group creator can manage group settings or members.")
        return redirect(url_for("chat_room", room_id=room_id))

    action = request.form.get("action", "")

    if action == "rename":
        new_name = request.form.get("group_name", "").strip()
        if new_name:
            room.name = new_name
            db.session.commit()
            flash("Group name updated.")
        return redirect(url_for("chat_room", room_id=room_id))

    target_id = int(request.form.get("target_user_id", 0))
    if target_id == user.id:
        flash("You cannot moderate yourself.")
        return redirect(url_for("chat_room", room_id=room_id))

    member = ChatMember.query.filter_by(room_id=room_id, user_id=target_id).first()

    if action == "timeout":
        minutes = max(1, int(request.form.get("minutes", 10) or 10))
        if member:
            member.timeout_until = datetime.utcnow() + timedelta(minutes=minutes)
            db.session.commit()
            flash(f"Timed out member for {minutes} minute(s).")
    elif action == "remove_timeout":
        if member:
            member.timeout_until = None
            db.session.commit()
            flash("Timeout removed.")
    elif action == "kick":
        ChatMember.query.filter_by(room_id=room_id, user_id=target_id).delete()
        db.session.commit()
        flash("Member kicked from group.")
    elif action == "ban":
        ChatMember.query.filter_by(room_id=room_id, user_id=target_id).delete()
        if not GroupBan.query.filter_by(room_id=room_id, user_id=target_id).first():
            db.session.add(GroupBan(room_id=room_id, user_id=target_id))
        db.session.commit()
        flash("Member banned from group.")
    elif action == "unban":
        GroupBan.query.filter_by(room_id=room_id, user_id=target_id).delete()
        db.session.commit()
        flash("Member unbanned.")

    return redirect(url_for("chat_room", room_id=room_id))


@app.route("/index")
@app.route("/", methods=["GET"])
@login_required
def index():
    user = current_user()
    _, _, _, friend_users_by_id = get_friends_data(user.id)
    rooms_sidebar, _, _, _ = get_user_rooms_sidebar(user.id, friend_users_by_id)
    return render_template(
        "chats_list.html",
        user=user,
        rooms_sidebar=rooms_sidebar,
        active_nav="chats",
    )


@app.route("/chat/<int:room_id>", methods=["GET"])
@login_required
def chat_room(room_id):
    user = current_user()
    if GroupBan.query.filter_by(room_id=room_id, user_id=user.id).first():
        flash("You are banned from this group.")
        return redirect(url_for("index"))

    membership = ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first()
    if not membership:
        flash("You are not a member of this chat.")
        return redirect(url_for("index"))

    search_q = request.args.get("search", "").strip()
    _, _, muted_user_ids, friend_users_by_id = get_friends_data(user.id)
    rooms_sidebar, rooms_by_id, other_user_id_by_room, users_cache = get_user_rooms_sidebar(
        user.id, friend_users_by_id
    )

    active_room = rooms_by_id.get(room_id)
    if not active_room:
        return redirect(url_for("index"))

    Message.query.filter(
        Message.room_id == active_room.id,
        Message.sender_id != user.id,
        Message.is_read.is_(False),
    ).update({"is_read": True}, synchronize_session=False)
    db.session.commit()

    active_room_title = ""
    active_room_other_user = None
    if active_room.is_group:
        active_room_title = active_room.name or ""
    else:
        other_id = other_user_id_by_room.get(active_room.id)
        other = users_cache.get(other_id) if other_id else None
        active_room_other_user = other
        active_room_title = other.username if other else ""

    room_members_rows = ChatMember.query.filter_by(room_id=active_room.id).all()
    member_user_ids = [m.user_id for m in room_members_rows]
    banned_rows = GroupBan.query.filter_by(room_id=active_room.id).all()
    banned_user_ids = [b.user_id for b in banned_rows]
    all_needed_uids = set(member_user_ids + banned_user_ids)
    for uid in all_needed_uids:
        if uid not in users_cache:
            u = db.session.get(User, uid)
            if u:
                users_cache[uid] = u

    now = datetime.utcnow()
    members_view = []
    for m in room_members_rows:
        u = users_cache.get(m.user_id)
        if not u:
            continue
        is_timed_out = bool(m.timeout_until and m.timeout_until > now)
        members_view.append({
            "user": u,
            "is_admin": u.id == active_room.created_by,
            "is_timed_out": is_timed_out,
            "timeout_until_iso": iso_utc(m.timeout_until) if is_timed_out else "",
        })

    banned_users_view = [users_cache[uid] for uid in banned_user_ids if uid in users_cache]
    is_group_admin = bool(active_room.is_group and active_room.created_by == user.id)
    my_timed_out = bool(membership.timeout_until and membership.timeout_until > now)

    q = Message.query.filter_by(room_id=active_room.id)
    if search_q:
        q = q.filter(Message.body.ilike(f"%{search_q}%"))
    raw_msgs = q.order_by(Message.id.asc()).all()

    sender_ids = {m.sender_id for m in raw_msgs if m.sender_id not in users_cache}
    if sender_ids:
        for s in User.query.filter(User.id.in_(sender_ids)).all():
            users_cache[s.id] = s

    messages_view = []
    for msg in raw_msgs:
        muted_sender = msg.sender_id in muted_user_ids
        sender_obj = users_cache.get(msg.sender_id) or msg.sender
        rep_sender = None
        if msg.reply_to:
            rep_sender = users_cache.get(msg.reply_to.sender_id) or msg.reply_to.sender
        can_delete = (msg.sender_id == user.id) or is_group_admin
        messages_view.append({
            "id": msg.id,
            "sender": sender_obj,
            "body": "[Muted]" if muted_sender else (msg.body or ""),
            "msg_type": msg.msg_type,
            "file_filename": None if muted_sender else msg.file_filename,
            "original_filename": None if muted_sender else msg.original_filename,
            "is_image": bool(not muted_sender and msg.file_filename and is_image_filename(msg.original_filename or msg.file_filename)),
            "created_iso": iso_utc(msg.created_at),
            "muted": muted_sender,
            "is_read": bool(msg.is_read),
            "can_delete": can_delete,
            "reply_to": msg.reply_to,
            "reply_sender_name": rep_sender.username if rep_sender else "User",
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


@app.route("/api/messages/<int:room_id>")
@login_required
def api_messages(room_id):
    user = current_user()
    if GroupBan.query.filter_by(room_id=room_id, user_id=user.id).first():
        return jsonify({"error": "Forbidden"}), 403
    if not ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first():
        return jsonify({"error": "Forbidden"}), 403

    Message.query.filter(
        Message.room_id == room_id,
        Message.sender_id != user.id,
        Message.is_read.is_(False),
    ).update({"is_read": True}, synchronize_session=False)
    db.session.commit()

    after_id = request.args.get("after_id", 0, type=int)
    new_msgs = (
        Message.query.filter(Message.room_id == room_id, Message.id > after_id)
        .order_by(Message.id.asc())
        .all()
    )

    recent_sent = (
        Message.query.filter(Message.room_id == room_id, Message.sender_id == user.id)
        .order_by(Message.id.desc())
        .limit(30)
        .all()
    )
    read_statuses = {m.id: ("Seen" if m.is_read else "Delivered") for m in recent_sent}

    muted_user_ids = {
        r.friend_id
        for r in Friendship.query.filter_by(user_id=user.id, muted=True).all()
    }

    sender_ids = {m.sender_id for m in new_msgs}
    users_cache = {u.id: u for u in User.query.filter(User.id.in_(sender_ids)).all()} if sender_ids else {}

    other_online = None
    room = db.session.get(ChatRoom, room_id)
    if room and not room.is_group:
        other_m = ChatMember.query.filter(ChatMember.room_id == room_id, ChatMember.user_id != user.id).first()
        if other_m:
            other_u = db.session.get(User, other_m.user_id)
            if other_u:
                other_online = bool(other_u.is_online)

    payload = [serialize_message(m, user.id, muted_user_ids, users_cache) for m in new_msgs]
    return jsonify({"messages": payload, "read_statuses": read_statuses, "other_online": other_online})


@app.route("/messages/send/<int:room_id>", methods=["POST"])
@login_required
def send_message(room_id):
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    user = current_user()

    if GroupBan.query.filter_by(room_id=room_id, user_id=user.id).first():
        if is_ajax:
            return jsonify({"error": "Banned from group."}), 403
        flash("You are banned from this group.")
        return redirect(url_for("index"))

    membership = ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first()
    if not membership:
        if is_ajax:
            return jsonify({"error": "Forbidden"}), 403
        return redirect(url_for("index"))

    if membership.timeout_until and membership.timeout_until > datetime.utcnow():
        if is_ajax:
            return jsonify({"error": "You are timed out in this group."}), 403
        flash("You are currently timed out in this group.")
        return redirect(url_for("chat_room", room_id=room_id))

    room = db.session.get(ChatRoom, room_id)
    if room and not room.is_group:
        other_m = ChatMember.query.filter(
            ChatMember.room_id == room.id, ChatMember.user_id != user.id
        ).first()
        if other_m and is_blocked_between(user.id, other_m.user_id):
            if is_ajax:
                return jsonify({"error": "Messaging is blocked between you and this user."}), 403
            flash("Messaging is blocked between you and this user.")
            return redirect(url_for("chat_room", room_id=room_id))

    body = request.form.get("body", "").strip()
    reply_to_id = request.form.get("reply_to_id", type=int)
    if reply_to_id:
        rep_msg = db.session.get(Message, reply_to_id)
        if not rep_msg or rep_msg.room_id != room_id:
            reply_to_id = None

    msg_type = "text"
    stored_file = None
    orig_file = None

    voice_file = request.files.get("voice_data")
    attachment = request.files.get("attachment")

    if voice_file and voice_file.filename:
        stored_file, orig_file = save_uploaded_stream(voice_file, prefix="voice")
        msg_type = "voice"
    elif attachment and attachment.filename:
        stored_file, orig_file = save_uploaded_stream(attachment, prefix="media")
        msg_type = "file"

    if not body and not stored_file:
        if is_ajax:
            return jsonify({"error": "Empty message"}), 400
        return redirect(url_for("chat_room", room_id=room_id))

    msg = Message(
        room_id=room_id,
        sender_id=user.id,
        body=body or None,
        msg_type=msg_type,
        file_filename=stored_file,
        original_filename=orig_file,
        reply_to_id=reply_to_id,
        is_read=False,
    )
    db.session.add(msg)
    db.session.commit()

    if is_ajax:
        return jsonify({
            "ok": True,
            "message": serialize_message(msg, user.id, set(), {user.id: user}),
        })

    return redirect(url_for("chat_room", room_id=room_id))


@app.route("/messages/delete/<int:message_id>", methods=["POST"])
@login_required
def delete_message(message_id):
    user = current_user()
    msg = db.session.get(Message, message_id)
    if not msg:
        return redirect(url_for("index"))

    room = db.session.get(ChatRoom, msg.room_id)
    is_admin = bool(room and room.is_group and room.created_by == user.id)
    if msg.sender_id != user.id and not is_admin:
        flash("You can only delete your own messages.")
        return redirect(url_for("chat_room", room_id=msg.room_id))

    room_id = msg.room_id
    Message.query.filter_by(reply_to_id=msg.id).update({"reply_to_id": None})
    db.session.delete(msg)
    db.session.commit()
    return redirect(url_for("chat_room", room_id=room_id))


@app.route("/messages/forward/<int:message_id>", methods=["POST"])
@login_required
def forward_message(message_id):
    user = current_user()
    orig = db.session.get(Message, message_id)
    target_room_id = request.form.get("target_room_id", type=int)

    if not orig or not target_room_id:
        flash("Select a target chat to forward to.")
        return redirect(url_for("index"))

    if not ChatMember.query.filter_by(room_id=orig.room_id, user_id=user.id).first():
        return redirect(url_for("index"))

    if GroupBan.query.filter_by(room_id=target_room_id, user_id=user.id).first():
        flash("You are banned from that group.")
        return redirect(url_for("chat_room", room_id=orig.room_id))

    target_mem = ChatMember.query.filter_by(room_id=target_room_id, user_id=user.id).first()
    if not target_mem:
        flash("You are not a member of that chat.")
        return redirect(url_for("chat_room", room_id=orig.room_id))

    if target_mem.timeout_until and target_mem.timeout_until > datetime.utcnow():
        flash("You are timed out in that group.")
        return redirect(url_for("chat_room", room_id=orig.room_id))

    forwarded_text = orig.body or ""
    if orig.original_filename and orig.msg_type == "file":
        forwarded_text = (forwarded_text + " " + orig.original_filename).strip()

    fwd_msg = Message(
        room_id=target_room_id,
        sender_id=user.id,
        body=forwarded_text or "Forwarded message",
        msg_type="text",
        is_read=False,
    )
    db.session.add(fwd_msg)
    db.session.commit()
    flash("Message forwarded.")
    return redirect(url_for("chat_room", room_id=target_room_id))


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    safe = secure_filename(filename)
    download = request.args.get("download") == "1"
    return send_from_directory(UPLOAD_DIR, safe, as_attachment=download)


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
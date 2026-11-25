import base64
import os
import random
import secrets
from datetime import datetime
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
# 20 GB maximum upload size
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

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


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=True)
    msg_type = db.Column(db.String(20), default="text", nullable=False)
    file_filename = db.Column(db.String(255), nullable=True)
    original_filename = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    sender = db.relationship("User", foreign_keys=[sender_id])


def ensure_schema_columns():
    db.create_all()
    inspector = inspect(db.engine)
    if "user" in inspector.get_table_names():
        cols = {c["name"] for c in inspector.get_columns("user")}
        if "pfp_data" not in cols:
            with db.engine.begin() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN pfp_data TEXT"))


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


def is_blocked_between(u1_id, u2_id):
    rel1 = Friendship.query.filter_by(user_id=u1_id, friend_id=u2_id, status="blocked").first()
    rel2 = Friendship.query.filter_by(user_id=u2_id, friend_id=u1_id, status="blocked").first()
    return bool(rel1 or rel2)


def format_12h_hh_mm(dt):
    return dt.strftime("%I:%M %p")


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
        ext = os.path.splitext((m.original_filename or m.file_filename or "").lower())[1]
        is_image = ext in {".png", ".jpg", ".jpeg", ".gif", ".webp"}
        items.append({
            "id": m.id,
            "filename": m.file_filename,
            "label": m.original_filename or m.file_filename,
            "is_image": is_image,
            "url": url_for("uploaded_file", filename=m.file_filename),
            "download_url": url_for("uploaded_file", filename=m.file_filename, download=1),
        })
    return items


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


# --- Profile Routes (/profile and /profile/<id>) ---
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


# --- Friends Route (/friends) ---
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

    existing = Friendship.query.filter_by(user_id=user.id, friend_id=target.id).first()
    if not existing:
        db.session.add(Friendship(user_id=user.id, friend_id=target.id, status="accepted"))

    reverse = Friendship.query.filter_by(user_id=target.id, friend_id=user.id).first()
    if not reverse:
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


# --- Chats, Group Creation & Individual Room Routes ---
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
    if not ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first():
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

    active_room_title = ""
    active_room_other_user = None
    if active_room.is_group:
        active_room_title = active_room.name or ""
    else:
        other_id = other_user_id_by_room.get(active_room.id)
        other = users_cache.get(other_id) if other_id else None
        active_room_other_user = other
        active_room_title = other.username if other else ""

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
        messages_view.append({
            "id": msg.id,
            "sender": sender_obj,
            "body": "[Muted]" if muted_sender else (msg.body or ""),
            "msg_type": msg.msg_type,
            "file_filename": None if muted_sender else msg.file_filename,
            "original_filename": None if muted_sender else msg.original_filename,
            "time_str": format_12h_hh_mm(msg.created_at),
            "muted": muted_sender,
        })

    return render_template(
        "chat_room.html",
        user=user,
        rooms_sidebar=rooms_sidebar,
        active_room=active_room,
        active_room_title=active_room_title,
        active_room_other_user=active_room_other_user,
        messages=messages_view,
        search_q=search_q,
        active_nav="chats",
    )


@app.route("/api/messages/<int:room_id>")
@login_required
def api_messages(room_id):
    user = current_user()
    if not ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first():
        return jsonify({"error": "Forbidden"}), 403

    after_id = request.args.get("after_id", 0, type=int)
    new_msgs = (
        Message.query.filter(Message.room_id == room_id, Message.id > after_id)
        .order_by(Message.id.asc())
        .all()
    )

    muted_user_ids = {
        r.friend_id
        for r in Friendship.query.filter_by(user_id=user.id, muted=True).all()
    }

    sender_ids = {m.sender_id for m in new_msgs}
    senders = {u.id: u for u in User.query.filter(User.id.in_(sender_ids)).all()} if sender_ids else {}

    payload = []
    for m in new_msgs:
        muted_sender = m.sender_id in muted_user_ids
        sender = senders.get(m.sender_id)
        sender_name = sender.username if sender else ""
        file_fn = None if muted_sender else (m.file_filename or "")
        orig_fn = None if muted_sender else (m.original_filename or "")

        payload.append({
            "id": m.id,
            "sender_id": m.sender_id,
            "sender_name": sender_name,
            "sender_initial": sender_name[0].upper() if sender_name else "",
            "time_str": format_12h_hh_mm(m.created_at),
            "body": "[Muted]" if muted_sender else (m.body or ""),
            "msg_type": m.msg_type or "text",
            "file_filename": file_fn,
            "original_filename": orig_fn,
            "file_url": f"/uploads/{file_fn}?download=1" if file_fn else "",
        })

    return jsonify({"messages": payload})


@app.route("/messages/send/<int:room_id>", methods=["POST"])
@login_required
def send_message(room_id):
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest"
    user = current_user()
    if not ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first():
        if is_ajax:
            return jsonify({"error": "Forbidden"}), 403
        return redirect(url_for("index"))

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
    )
    db.session.add(msg)
    db.session.commit()

    if is_ajax:
        return jsonify({
            "ok": True,
            "message": {
                "id": msg.id,
                "sender_id": user.id,
                "sender_name": user.username,
                "sender_initial": user.username[0].upper() if user.username else "",
                "time_str": format_12h_hh_mm(msg.created_at),
                "body": msg.body or "",
                "msg_type": msg.msg_type,
                "file_filename": msg.file_filename or "",
                "original_filename": msg.original_filename or "",
                "file_url": f"/uploads/{msg.file_filename}?download=1" if msg.file_filename else "",
            },
        })

    return redirect(url_for("chat_room", room_id=room_id))


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    safe = secure_filename(filename)
    download = request.args.get("download") == "1"
    return send_from_directory(UPLOAD_DIR, safe, as_attachment=download)


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
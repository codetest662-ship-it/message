import os
import random
import secrets
from datetime import datetime
from functools import wraps
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{os.path.join(BASE_DIR, 'messenger.db')}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
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
    bio = db.Column(db.String(300), default="Hey there! I'm using Message.", nullable=False)
    pfp_filename = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


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


# --- Helpers ---
def generate_unique_friend_number():
    while True:
        num = f"{random.randint(100000, 999999)}-{random.randint(10, 99)}"
        if not User.query.filter_by(friend_number=num).first():
            return num


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = db.session.get(User, session["user_id"])
        if not user:
            session.pop("user_id", None)
            return redirect(url_for("login"))
        return fn(*args, **kwargs)

    return wrapper


def current_user():
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None


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


def is_muted(viewer_id, sender_id):
    rel = Friendship.query.filter_by(user_id=viewer_id, friend_id=sender_id, muted=True).first()
    return bool(rel)


def format_12h_hh_mm(dt):
    return dt.strftime("%I/%M %p")


with app.app_context():
    db.create_all()


# --- Auth Routes ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user():
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        bio = request.form.get("bio", "").strip() or "Hey there! I'm using Message."

        if not username or not email or not password:
            flash("Username, email, and password are required.")
            return render_template("register.html")

        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash("Username or email is already taken.")
            return render_template("register.html")

        pfp_name = None
        pfp_file = request.files.get("pfp")
        if pfp_file and pfp_file.filename:
            pfp_name, _ = save_uploaded_stream(pfp_file, prefix="pfp")

        user = User(
            username=username,
            email=email,
            friend_number=generate_unique_friend_number(),
            bio=bio,
            pfp_filename=pfp_name,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        session["user_id"] = user.id
        return redirect(url_for("index"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("index"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier.lower())
        ).first()

        if user and user.check_password(password):
            session["user_id"] = user.id
            return redirect(url_for("index"))

        flash("Invalid credentials.")

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        new_password = request.form.get("new_password", "")
        user = User.query.filter_by(email=email).first()

        if not user or not new_password:
            flash("If that email exists and a new password was entered, your password has been updated.")
            return render_template("forgot_password.html")

        user.set_password(new_password)
        db.session.commit()
        flash("Password reset complete. You can now log in.")
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/logout", methods=["POST", "GET"])
@login_required
def logout():
    session.pop("user_id", None)
    return redirect(url_for("login"))


# --- Profile Routes ---
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = current_user()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        bio = request.form.get("bio", "").strip()

        if username and username != user.username:
            if User.query.filter_by(username=username).first():
                flash("That username is already taken.")
                return redirect(url_for("profile"))
            user.username = username

        if bio is not None:
            user.bio = bio

        pfp_file = request.files.get("pfp")
        if pfp_file and pfp_file.filename:
            pfp_name, _ = save_uploaded_stream(pfp_file, prefix="pfp")
            user.pfp_filename = pfp_name

        db.session.commit()
        flash("Profile updated.")
        return redirect(url_for("profile"))

    return render_template("profile.html", user=user)


# --- Friends & Relationships ---
@app.route("/friends/add", methods=["POST"])
@login_required
def add_friend():
    user = current_user()
    target_num = request.form.get("friend_number", "").strip()
    target = User.query.filter_by(friend_number=target_num).first()

    if not target:
        flash("No user found with that Friend Number.")
        return redirect(url_for("index", tab="friends"))

    if target.id == user.id:
        flash("You cannot add yourself.")
        return redirect(url_for("index", tab="friends"))

    if is_blocked_between(user.id, target.id):
        flash("Cannot add this user due to a block.")
        return redirect(url_for("index", tab="friends"))

    existing = Friendship.query.filter_by(user_id=user.id, friend_id=target.id).first()
    if not existing:
        db.session.add(Friendship(user_id=user.id, friend_id=target.id, status="accepted"))

    reverse = Friendship.query.filter_by(user_id=target.id, friend_id=user.id).first()
    if not reverse:
        db.session.add(Friendship(user_id=target.id, friend_id=user.id, status="accepted"))

    db.session.commit()
    flash(f"Added {target.username} as a friend!")
    return redirect(url_for("index", tab="friends"))


@app.route("/friends/action", methods=["POST"])
@login_required
def friend_action():
    user = current_user()
    target_id = int(request.form.get("target_id", 0))
    action = request.form.get("action", "")
    target = db.session.get(User, target_id)

    if not target or target.id == user.id:
        return redirect(url_for("index", tab="friends"))

    rel = Friendship.query.filter_by(user_id=user.id, friend_id=target.id).first()

    if action == "unfriend":
        Friendship.query.filter_by(user_id=user.id, friend_id=target.id).delete()
        Friendship.query.filter_by(user_id=target.id, friend_id=user.id).delete()
        flash(f"Unfriended {target.username}.")
    elif action == "mute":
        if not rel:
            rel = Friendship(user_id=user.id, friend_id=target.id, status="accepted", muted=True)
            db.session.add(rel)
        else:
            rel.muted = not rel.muted
        flash(f"{'Muted' if rel.muted else 'Unmuted'} {target.username}.")
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
    return redirect(url_for("index", tab="friends"))


# --- Chats (DMs + Group Chats) ---
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
    return redirect(url_for("index", room_id=room.id, tab="chats"))


@app.route("/groups/create", methods=["POST"])
@login_required
def create_group():
    user = current_user()
    group_name = request.form.get("group_name", "").strip() or "Group Chat"
    member_ids = [int(x) for x in request.form.getlist("member_ids") if x.isdigit()]

    room = ChatRoom(name=group_name, is_group=True, created_by=user.id)
    db.session.add(room)
    db.session.flush()

    all_members = set(member_ids + [user.id])
    for mid in all_members:
        if db.session.get(User, mid):
            db.session.add(ChatMember(room_id=room.id, user_id=mid))

    db.session.commit()
    flash(f"Group '{group_name}' created!")
    return redirect(url_for("index", room_id=room.id, tab="chats"))


@app.route("/index")
@app.route("/", methods=["GET"])
@login_required
def index():
    user = current_user()
    search_q = request.args.get("search", "").strip()
    active_room_id = request.args.get("room_id", type=int)
    active_tab = request.args.get("tab", "chats")
    if active_tab not in ("chats", "friends", "groups"):
        active_tab = "chats"

    outgoing = Friendship.query.filter_by(user_id=user.id).all()
    incoming = Friendship.query.filter_by(friend_id=user.id).all()

    rel_map = {}
    friend_ids_ordered = []

    for r in outgoing:
        rel_map[r.friend_id] = r
        if r.friend_id not in friend_ids_ordered:
            friend_ids_ordered.append(r.friend_id)

    for r in incoming:
        if r.user_id not in rel_map:
            rel_map[r.user_id] = r
        if r.user_id not in friend_ids_ordered:
            friend_ids_ordered.append(r.user_id)

    friends = []
    for fid in friend_ids_ordered:
        if fid == user.id:
            continue
        f_user = db.session.get(User, fid)
        if f_user:
            friends.append(f_user)

    my_memberships = ChatMember.query.filter_by(user_id=user.id).all()
    rooms_sidebar = []
    for m in my_memberships:
        room = db.session.get(ChatRoom, m.room_id)
        if not room:
            continue
        if room.is_group:
            rooms_sidebar.append({
                "room": room,
                "title": room.name or f"Group #{room.id}",
                "pfp": None,
                "is_group": True,
                "other_user": None,
            })
        else:
            other_m = ChatMember.query.filter(
                ChatMember.room_id == room.id, ChatMember.user_id != user.id
            ).first()
            other = db.session.get(User, other_m.user_id) if other_m else None
            rooms_sidebar.append({
                "room": room,
                "title": other.username if other else "Direct Message",
                "pfp": other.pfp_filename if other else None,
                "is_group": False,
                "other_user": other,
            })

    active_room = None
    if active_room_id and ChatMember.query.filter_by(room_id=active_room_id, user_id=user.id).first():
        active_room = db.session.get(ChatRoom, active_room_id)
    elif rooms_sidebar:
        active_room = rooms_sidebar[0]["room"]

    active_room_title = "Direct Message"
    if active_room:
        if active_room.is_group:
            active_room_title = active_room.name or f"Group #{active_room.id}"
        else:
            other_m = ChatMember.query.filter(
                ChatMember.room_id == active_room.id, ChatMember.user_id != user.id
            ).first()
            other = db.session.get(User, other_m.user_id) if other_m else None
            active_room_title = other.username if other else "Direct Message"

    messages_view = []
    if active_room:
        q = Message.query.filter_by(room_id=active_room.id)
        if search_q:
            q = q.filter(Message.body.ilike(f"%{search_q}%"))
        raw_msgs = q.order_by(Message.id.asc()).all()
        for msg in raw_msgs:
            muted_sender = is_muted(user.id, msg.sender_id)
            messages_view.append({
                "id": msg.id,
                "sender": msg.sender,
                "body": "[Muted user message]" if muted_sender else (msg.body or ""),
                "msg_type": msg.msg_type,
                "file_filename": None if muted_sender else msg.file_filename,
                "original_filename": None if muted_sender else msg.original_filename,
                "time_str": format_12h_hh_mm(msg.created_at),
                "muted": muted_sender,
            })

    return render_template(
        "index.html",
        user=user,
        friends=friends,
        rel_map=rel_map,
        rooms_sidebar=rooms_sidebar,
        active_room=active_room,
        active_room_title=active_room_title,
        messages=messages_view,
        search_q=search_q,
        active_tab=active_tab,
    )


@app.route("/messages/send/<int:room_id>", methods=["POST"])
@login_required
def send_message(room_id):
    user = current_user()
    if not ChatMember.query.filter_by(room_id=room_id, user_id=user.id).first():
        return redirect(url_for("index"))

    room = db.session.get(ChatRoom, room_id)
    if room and not room.is_group:
        other_m = ChatMember.query.filter(
            ChatMember.room_id == room.id, ChatMember.user_id != user.id
        ).first()
        if other_m and is_blocked_between(user.id, other_m.user_id):
            flash("Messaging is blocked between you and this user.")
            return redirect(url_for("index", room_id=room_id))

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
        return redirect(url_for("index", room_id=room_id))

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

    return redirect(url_for("index", room_id=room_id, tab="chats"))


@app.route("/uploads/<filename>")
@login_required
def uploaded_file(filename):
    safe = secure_filename(filename)
    download = request.args.get("download") == "1"
    return send_from_directory(UPLOAD_DIR, safe, as_attachment=download)


if __name__ == "__main__":
    app.run(debug=True, threaded=True)
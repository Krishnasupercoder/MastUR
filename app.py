from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import secrets, json, os, openai
from datetime import datetime, timedelta
import random, string, pdfkit

app = Flask(__name__)
app.secret_key = 'mastur_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mastur.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask-Mail
app.config['MAIL_DEFAULT_SENDER'] = 'assist.mastur@gmail.com'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'assist.mastur@gmail.com'
app.config['MAIL_PASSWORD'] = 'otvbopxdpjmzfvcg'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

openai.api_key = "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"
PAYPAL_CLIENT_ID = "ARVXIjSwRCcKfwBifqyQgBrGznf7hDGD5wVNXKgaZAjZL7WdOCup_3SJWVp21230YZVlmoWr3UwEUNIy"

# ======== MODELS ========
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    otp_code = db.Column(db.String(6))
    otp_expiry = db.Column(db.DateTime)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    price = db.Column(db.Float)
    is_free = db.Column(db.Boolean, default=False)
    cert_template = db.Column(db.Text, nullable=True)  # HTML for cert template (optional)

class Lesson(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    title = db.Column(db.String(200))
    video_url = db.Column(db.String(500))  # can be MP4 or YouTube

class MCQ(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    question = db.Column(db.Text)
    options = db.Column(db.Text)   # JSON array
    answer = db.Column(db.String(200))
    is_final = db.Column(db.Boolean, default=False)  # False: start assessment, True: final assessment

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(150))
    course_id = db.Column(db.Integer)

class CourseProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(150))
    course_id = db.Column(db.Integer)
    lesson_index = db.Column(db.Integer)

class AssessmentResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'))
    topic = db.Column(db.String(100))
    score = db.Column(db.Float)

class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cert_id = db.Column(db.String(100), unique=True)
    user_name = db.Column(db.String(100))
    course_name = db.Column(db.String(200))
    issue_date = db.Column(db.String(50))
    verified = db.Column(db.Boolean, default=True)


# =======================
# MODEL: LearnBits (Shorts)
# =======================
class LearnBit(db.Model):
    __tablename__ = "learnbits"
    id = db.Column(db.Integer, primary_key=True)
    # Optional link to a course (set to None for general/marketing shorts)
    course_id = db.Column(db.Integer, nullable=True)
    title = db.Column(db.String(140), nullable=False)
    media_type = db.Column(db.String(20), nullable=False, default="video")  # video|image|text|quiz
    media_url = db.Column(db.String(512), nullable=True)   # /static/uploads/... for video/image
    caption = db.Column(db.Text, nullable=True)
    duration_sec = db.Column(db.Integer, nullable=True)    # 30-90 typical
    is_public = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


# ======= INIT DB + CREATE ADMIN IF NEEDED =======
with app.app_context():
    db.create_all()
    if not User.query.filter_by(email="admin@example.com").first():
        admin = User(
            name="Admin",
            email="admin@example.com",
            password=generate_password_hash("adminpassword"),
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()

# ========== ROUTES ==========

# ---------- User Section ----------
@app.route('/')
def index():
    courses = Course.query.all()
    return render_template('index.html', courses=courses)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name, email, password = request.form['name'], request.form['email'], request.form['password']
        try:
            db.session.add(User(name=name, email=email, password=generate_password_hash(password)))
            db.session.commit()
            msg = Message('Welcome to MastUR!', recipients=[email])
            msg.body = f"Hello {name},\n\nWelcome to MastUR!"
            mail.send(msg)
            flash('Registered! Now log in.')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already exists!')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['email'] = user.email
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials!')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'email' not in session: return redirect(url_for('login'))
    user_email = session['email']
    enrolled_ids = [e.course_id for e in Enrollment.query.filter_by(user_email=user_email)]
    courses = Course.query.all()
    my_courses = []
    for c in courses:
        if c.id in enrolled_ids:
            # Attach progress
            progress = CourseProgress.query.filter_by(user_email=user_email, course_id=c.id).first()
            p = {
                'id': c.id, 'title': c.title, 'desc': c.description,
                'progress': progress.lesson_index if progress else 0
            }
            my_courses.append(p)
    return render_template('dashboard.html', courses=courses, my_courses=my_courses)

@app.route('/course-details/<int:course_id>')
def course_details(course_id):
    course = Course.query.get(course_id)
    lessons = Lesson.query.filter_by(course_id=course_id).all()
    return render_template("course_details.html", course=course, lessons=lessons)

@app.route('/enroll/<int:course_id>', methods=['POST'])
def enroll(course_id):
    if 'email' not in session: return redirect(url_for('login'))
    user_email = session['email']
    if not Enrollment.query.filter_by(user_email=user_email, course_id=course_id).first():
        db.session.add(Enrollment(user_email=user_email, course_id=course_id))
        db.session.commit()
    return redirect(url_for('course_details', course_id=course_id))

@app.route('/learn/<int:course_id>/<int:lesson>')
def learn(course_id, lesson):
    if 'email' not in session: return redirect(url_for('login'))
    email = session['email']
    course = Course.query.get(course_id)
    lessons = Lesson.query.filter_by(course_id=course_id).all()
    if not course or not lessons: return "Course or lessons not found"
    if lesson < 0 or lesson >= len(lessons): return redirect(url_for('learn', course_id=course_id, lesson=0))
    # Save progress
    progress = CourseProgress.query.filter_by(user_email=email, course_id=course_id).first()
    if not progress or progress.lesson_index < lesson:
        if not progress:
            progress = CourseProgress(user_email=email, course_id=course_id, lesson_index=lesson)
            db.session.add(progress)
        else:
            progress.lesson_index = lesson
        db.session.commit()
    percent = int(100 * (lesson + 1) / len(lessons))
    if lesson >= len(lessons):
        return redirect(url_for('final_assessment', course_id=course_id))
    return render_template('learn.html', course=course, lessons=lessons, lesson=lesson, progress=percent, total=len(lessons))

# ------------- MCQ Assessments (Start & Final) -----------------
def get_mcqs(course_id, is_final=False):
    mcqs = MCQ.query.filter_by(course_id=course_id, is_final=is_final).all()
    # Convert to list of dict for Jinja2
    return [{
        'id': q.id,
        'question': q.question,
        'options': json.loads(q.options),
        'answer': q.answer
    } for q in mcqs]

@app.route('/courses/<int:course_id>/assessment', methods=['GET', 'POST'])
def assessment(course_id):
    mcqs = get_mcqs(course_id, is_final=False)
    if not mcqs: flash("No start assessment for this course.", "danger"); return redirect(url_for('course_details', course_id=course_id))
    answers = session.get(f'assessment_{course_id}_answers', {})
    if request.method == 'POST':
        q_idx = int(request.form['q_idx'])
        selected = request.form.get('selected')
        answers[str(q_idx)] = selected if selected else "Skipped"
        session[f'assessment_{course_id}_answers'] = answers
        if q_idx + 1 < len(mcqs):
            return redirect(url_for('assessment', course_id=course_id, q=q_idx+1))
        else:
            # Save result
            correct = sum([1 for i, q in enumerate(mcqs) if answers.get(str(i), "") == q['answer']])
            session[f'assessment_{course_id}_score'] = correct
            return redirect(url_for('assessment_summary', course_id=course_id))
    q_idx = int(request.args.get('q', 0))
    if q_idx >= len(mcqs): return redirect(url_for('assessment_summary', course_id=course_id))
    q = mcqs[q_idx]
    return render_template('assessment.html', course_id=course_id, q_idx=q_idx, question=q['question'], options=q['options'], total=len(mcqs), answers=answers)

@app.route('/courses/<int:course_id>/assessment-summary')
def assessment_summary(course_id):
    score = session.get(f'assessment_{course_id}_score', 0)
    mcqs = get_mcqs(course_id, is_final=False)
    return render_template('assessment_summary.html', course_id=course_id, score=score, total=len(mcqs))

@app.route('/courses/<int:course_id>/final-assessment', methods=['GET', 'POST'])
def final_assessment(course_id):
    mcqs = get_mcqs(course_id, is_final=True)
    if not mcqs: flash("No final assessment for this course.", "danger"); return redirect(url_for('dashboard'))
    answers = session.get(f'final_assessment_{course_id}_answers', {})
    if request.method == 'POST':
        q_idx = int(request.form['q_idx'])
        selected = request.form.get('selected')
        answers[str(q_idx)] = selected if selected else "Skipped"
        session[f'final_assessment_{course_id}_answers'] = answers
        if q_idx + 1 < len(mcqs):
            return redirect(url_for('final_assessment', course_id=course_id, q=q_idx+1))
        else:
            # Save result
            correct = sum([1 for i, q in enumerate(mcqs) if answers.get(str(i), "") == q['answer']])
            session[f'final_assessment_{course_id}_score'] = correct
            return redirect(url_for('final_assessment_summary', course_id=course_id))
    q_idx = int(request.args.get('q', 0))
    if q_idx >= len(mcqs): return redirect(url_for('final_assessment_summary', course_id=course_id))
    q = mcqs[q_idx]
    return render_template('final_assessment.html', course_id=course_id, q_idx=q_idx, question=q['question'], options=q['options'], total=len(mcqs), answers=answers)

@app.route('/courses/<int:course_id>/final-assessment-summary')
def final_assessment_summary(course_id):
    score = session.get(f'final_assessment_{course_id}_score', 0)
    mcqs = get_mcqs(course_id, is_final=True)
    return render_template('final_assessment_summary.html', course_id=course_id, score=score, total=len(mcqs))

# ---------------- OTP System ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            otp = str(secrets.randbelow(899999) + 100000)
            user.otp_code = otp
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=10)
            db.session.commit()
            msg = Message(
                subject="OTP Code For Reset Password In MastUR",
                recipients=[email]
            )
            msg.body = f"Your OTP is {otp}. It expires in 10 minutes."
            mail.send(msg)
            flash("OTP sent to your email.", "info")
            return redirect(url_for("reset_password", email=email))
    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    email = request.args.get("email")
    user = User.query.filter_by(email=email).first()
    if request.method == "POST":
        otp = request.form["otp"]
        new_pass = request.form["new_password"]
        if user and user.otp_code == otp and datetime.utcnow() < user.otp_expiry:
            user.password = generate_password_hash(new_pass)
            user.otp_code = None
            user.otp_expiry = None
            db.session.commit()
            flash("Password reset successful.", "success")
            return redirect(url_for("login"))
        flash("Invalid or expired OTP.", "danger")
    return render_template("reset_password.html", email=email)

@app.route('/pay/<int:course_id>')
def pay(course_id):
    if 'email' not in session: return redirect(url_for('login'))
    course = Course.query.get(course_id)
    return render_template('payment.html', course=course, paypal_client_id=PAYPAL_CLIENT_ID)

@app.route('/paypal-capture/<int:course_id>', methods=['POST'])
def paypal_capture(course_id):
    if 'email' not in session: return jsonify({'status': 'error'}), 401
    user_email = session['email']
    if not Enrollment.query.filter_by(user_email=user_email, course_id=course_id).first():
        db.session.add(Enrollment(user_email=user_email, course_id=course_id))
        db.session.commit()
    return jsonify({'status': 'success'})

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route("/validate-certificate", methods=["GET", "POST"])
def validate_certificate():
    cert = None
    if request.method == "POST":
        cert_code = request.form.get("cert_id")
        cert = Certificate.query.filter_by(cert_id=cert_code).first()
    return render_template("validate_certificate.html", cert=cert)

@app.route("/generate-certificate/<int:course_id>")
def generate_certificate(course_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(email=session['email']).first()
    course = Course.query.get(course_id)
    if not course:
        return "Course not found."
    cert_id = "MST-2025-" + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    date_issued = datetime.now().strftime("%B %d, %Y")
    cert = Certificate(cert_id=cert_id, user_name=user.name, course_name=course.title, issue_date=date_issued)
    db.session.add(cert)
    db.session.commit()
    rendered = render_template("certificate_template.html", name=user.name, course=course.title, cert_id=cert_id, date=date_issued)
    pdf_path = f"certificates/{cert_id}.pdf"
    pdfkit.from_string(rendered, pdf_path)
    return send_file(pdf_path, as_attachment=True)

# ===================================
# ROUTES: LearnBits (feed + admin UI)
# ===================================

from werkzeug.utils import secure_filename
import os

# Ensure uploads dir exists
os.makedirs(os.path.join("static", "uploads"), exist_ok=True)

def is_admin():
    return session.get("role") == "admin"

@app.route("/learnbits")
def learnbits_feed():
    """Public feed of LearnBits (Shorts) in a vertical swipe-like list."""
    course_id = request.args.get("course_id", type=int)
    q = LearnBit.query.filter_by(is_public=True).order_by(LearnBit.created_at.desc())
    if course_id:
        q = q.filter(LearnBit.course_id == course_id)
    bits = q.limit(50).all()
    return render_template("learnbits_feed.html", bits=bits)

@app.route("/learnbits/admin", methods=["GET", "POST"])
def learnbits_admin():
    """Simple admin uploader/manager for LearnBits."""
    if not is_admin():
        flash("Admin access required.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        title = request.form.get("title","").strip()
        media_type = request.form.get("media_type","video").strip()
        caption = request.form.get("caption","").strip()
        duration_sec = request.form.get("duration_sec", type=int)
        course_id = request.form.get("course_id", type=int)
        is_public = True if request.form.get("is_public") == "on" else False

        media_url = None
        file = request.files.get("media_file")
        if file and file.filename:
            fname = secure_filename(file.filename)
            new_name = f"lb_{int(datetime.utcnow().timestamp())}_{fname}"
            save_path = os.path.join("static", "uploads", new_name)
            file.save(save_path)
            media_url = f"/static/uploads/{new_name}"

        bit = LearnBit(
            course_id=course_id,
            title=title or "Untitled",
            media_type=media_type,
            media_url=media_url,
            caption=caption,
            duration_sec=duration_sec,
            is_public=is_public,
        )
        db.session.add(bit)
        db.session.commit()
        flash("LearnBit created.", "success")
        return redirect(url_for("learnbits_admin"))

    bits = LearnBit.query.order_by(LearnBit.created_at.desc()).all()
    return render_template("learnbits_admin.html", bits=bits)

@app.route("/learnbits/<int:bit_id>/toggle", methods=["POST"])
def learnbits_toggle(bit_id):
    if not is_admin():
        return jsonify({"ok": False, "error": "admin only"}), 403
    bit = LearnBit.query.get_or_404(bit_id)
    bit.is_public = not bit.is_public
    db.session.commit()
    return jsonify({"ok": True, "is_public": bit.is_public})

@app.route("/api/learnbits")
def api_learnbits():
    """JSON for embedding carousels (e.g., on dashboard)."""
    course_id = request.args.get("course_id", type=int)
    limit = request.args.get("limit", default=12, type=int)
    q = LearnBit.query.filter_by(is_public=True).order_by(LearnBit.created_at.desc())
    if course_id:
        q = q.filter(LearnBit.course_id == course_id)
    bits = q.limit(limit).all()
    return jsonify([
        {
            "id": b.id,
            "title": b.title,
            "media_type": b.media_type,
            "media_url": b.media_url,
            "caption": b.caption,
            "duration_sec": b.duration_sec,
            "course_id": b.course_id,
            "created_at": (b.created_at.isoformat() if b.created_at else None),
        } for b in bits
    ])


# ======== AUTO-GENERATE LEARNBITS (Shorts) FROM LESSON VIDEOS ========
import subprocess
from pathlib import Path

# --- Configurable defaults ---
LEARNBITS_DEFAULT_DURATION = 60  # seconds
LEARNBITS_MIN_DURATION = 20      # safety lower bound
LEARNBITS_MAX_DURATION = 180     # safety upper bound

def ffmpeg_exists() -> bool:
    try:
        subprocess.run(["ffmpeg", "-version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        return True
    except Exception:
        return False

def ensure_dirs():
    Path("static/uploads").mkdir(parents=True, exist_ok=True)

def to_fs_path(web_path: str) -> Path:
    """
    Convert a web path like '/static/uploads/foo.mp4' -> filesystem path 'static/uploads/foo.mp4'
    """
    if not web_path:
        return None
    if web_path.startswith("/"):
        web_path = web_path[1:]
    return Path(web_path)

def from_fs_path(p: Path) -> str:
    """
    Convert a filesystem path to a web path beginning with '/'
    """
    s = str(p).replace("\\", "/")
    if not s.startswith("/"):
        s = "/" + s
    return s

def trim_video_ffmpeg(src_web: str, out_web_basename: str, duration_sec: int) -> str:
    """
    Trim the first `duration_sec` seconds from src_web video.
    Returns the output WEB path (string) or None on failure.
    """
    ensure_dirs()
    src_path = to_fs_path(src_web)
    if not src_path or not src_path.exists():
        return None

    # Always save inside static/uploads
    out_fs = Path("static/uploads") / out_web_basename
    # ffmpeg -y -ss 0 -t <dur> -i input -c copy output  (fast, no re-encode)
    # fallback: re-encode if container blocking copy (some webms/mp4s can be tricky)
    try:
        cmd = ["ffmpeg", "-y", "-ss", "0", "-t", str(duration_sec), "-i", str(src_path),
               "-c", "copy", str(out_fs)]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode != 0 or not out_fs.exists():
            # re-encode fallback for safety
            cmd2 = ["ffmpeg", "-y", "-ss", "0", "-t", str(duration_sec), "-i", str(src_path),
                    "-c:v", "libx264", "-pix_fmt", "yuv420p", "-c:a", "aac", "-movflags", "+faststart",
                    str(out_fs)]
            r2 = subprocess.run(cmd2, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if r2.returncode != 0 or not out_fs.exists():
                return None
    except Exception:
        return None

    return from_fs_path(out_fs)

def sanitize_duration(raw: int | None) -> int:
    d = raw or LEARNBITS_DEFAULT_DURATION
    d = max(LEARNBITS_MIN_DURATION, min(LEARNBITS_MAX_DURATION, d))
    return d

def default_caption_for_lesson(lesson_title: str, duration_sec: int) -> str:
    return f"Quick snippet from “{lesson_title}” ({duration_sec}s). Learn the core idea fast."

# ===== Admin UI: page + form to auto-generate =====
@app.route("/learnbits/autogen", methods=["GET", "POST"])
def learnbits_autogen():
    if session.get("role") != "admin":
        flash("Admin access required.", "warning")
        return redirect(url_for("login"))

    if request.method == "POST":
        # Parameters
        course_id = request.form.get("course_id", type=int)
        duration_sec = sanitize_duration(request.form.get("duration_sec", type=int))
        limit = request.form.get("limit", type=int) or 10
        publish = True if request.form.get("publish") == "on" else False

        if not ffmpeg_exists():
            flash("ffmpeg is not installed on the server. Please install ffmpeg to auto-generate video LearnBits.", "danger")
            return redirect(url_for("learnbits_autogen"))

        # You may have a different Lesson model name/fields — adjust here
        try:
            lessons_q = Lesson.query
            if course_id:
                lessons_q = lessons_q.filter(Lesson.course_id == course_id)
            # only lessons having a video_url
            lessons_q = lessons_q.filter(Lesson.video_url.isnot(None)).order_by(Lesson.id.desc())
            lessons = lessons_q.limit(limit).all()
        except Exception:
            lessons = []

        created = 0
        failed = 0

        for les in lessons:
            if not les.video_url:
                failed += 1
                continue

            # Output name like: lb_clip_<lessonId>_<ts>.mp4
            timestamp = int(datetime.utcnow().timestamp())
            base_name = f"lb_clip_{les.id}_{timestamp}.mp4"
            out_web = trim_video_ffmpeg(les.video_url, base_name, duration_sec)
            if not out_web:
                failed += 1
                continue

            lb = LearnBit(
                course_id = getattr(les, "course_id", None),
                title     = f"LearnBit: {les.title}",
                media_type= "video",
                media_url = out_web,
                caption   = default_caption_for_lesson(les.title, duration_sec),
                duration_sec = duration_sec,
                is_public = publish
            )
            db.session.add(lb)
            created += 1

        if created:
            db.session.commit()

        flash(f"Auto‑generated {created} LearnBits. Failed: {failed}.", "success" if created else "warning")
        return redirect(url_for("learnbits_autogen"))

    # GET: small helper page
    return render_template("learnbits_autogen.html")

# ----- New Lesson: create form + handler -----
from werkzeug.utils import secure_filename
import os
os.makedirs(os.path.join("static", "uploads"), exist_ok=True)

@app.route("/admin/courses/<int:course_id>/lessons/new", methods=["GET", "POST"])
def admin_new_lesson(course_id):
    # OPTIONAL: protect with your existing admin decorator/checks
    if session.get("role") != "admin":
        flash("Please log in as an admin.", "warning")
        return redirect(url_for("login"))

    # Load the course (adjust to your model name if different)
    course = Course.query.get_or_404(course_id)

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        description = (request.form.get("description") or "").strip()
        video_url = None

        file = request.files.get("video_file")
        if file and file.filename:
            fn = secure_filename(file.filename)
            new_name = f"lesson_{course_id}_{int(datetime.utcnow().timestamp())}_{fn}"
            save_path = os.path.join("static", "uploads", new_name)
            file.save(save_path)
            video_url = f"/static/uploads/{new_name}"

        # Create Lesson instance safely even if your model doesn't have all fields
        les = Lesson()
        # required/safe fields
        setattr(les, "title", title)
        # common fields if present
        for col, val in [
            ("course_id", course_id),
            ("description", description),
            ("video_url", video_url),
        ]:
            try:
                if hasattr(les, col) and val is not None:
                    setattr(les, col, val)
            except Exception:
                pass

        db.session.add(les)
        db.session.commit()
        flash("Lesson created.", "success")
        # Redirect to your existing lessons list page
        return redirect(url_for("admin_lessons", course_id=course_id))

    return render_template("admin_lesson_new.html", course=course)


@app.route("/chatbot", methods=["POST"])
def chatbot():
    try:
        data = request.get_json()
        user_input = data.get("message", "").strip()
        if not user_input:
            return jsonify({"error": "Empty message"}), 400
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are MastUR's AI assistant."},
                {"role": "user", "content": user_input}
            ]
        )
        reply = response.choices[0].message.content.strip()
        return jsonify({"reply": reply})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ---------------- ADMIN SECTION -----------------
def admin_required(func):
    from functools import wraps
    @wraps(func)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            flash("Admin login required!", "danger")
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return decorated

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email, password = request.form['email'], request.form['password']
        user = User.query.filter_by(email=email, is_admin=True).first()
        if user and check_password_hash(user.password, password):
            session['email'] = user.email
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect(url_for('admin_dashboard'))
        flash('Invalid admin credentials!')
    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    course_count = Course.query.count()
    user_count = User.query.count()
    return render_template('admin_dashboard.html', course_count=course_count, user_count=user_count)

@app.route('/admin/courses')
@admin_required
def admin_courses():
    courses = Course.query.all()
    return render_template('admin_courses.html', courses=courses)

@app.route('/admin/courses/new', methods=['GET', 'POST'])
@admin_required
def admin_course_form():
    if request.method == 'POST':
        title = request.form['title']
        desc = request.form['desc']
        price = float(request.form['price'])
        is_free = 'is_free' in request.form
        db.session.add(Course(title=title, description=desc, price=price, is_free=is_free))
        db.session.commit()
        flash("Course added!")
        return redirect(url_for('admin_courses'))
    return render_template('admin_course_form.html', course=None)

@app.route('/admin/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def admin_course_edit(course_id):
    course = Course.query.get(course_id)
    if request.method == 'POST':
        course.title = request.form['title']
        course.description = request.form['desc']
        course.price = float(request.form['price'])
        course.is_free = 'is_free' in request.form
        db.session.commit()
        flash("Course updated!")
        return redirect(url_for('admin_courses'))
    return render_template('admin_course_form.html', course=course)

@app.route('/admin/courses/delete/<int:course_id>', methods=['POST'])
@admin_required
def admin_course_delete(course_id):
    Course.query.filter_by(id=course_id).delete()
    db.session.commit()
    flash("Course deleted!")
    return redirect(url_for('admin_courses'))

@app.route('/admin/lessons/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def admin_lessons(course_id):
    course = Course.query.get(course_id)
    if request.method == 'POST':
        title = request.form['title']
        video_url = request.form['video_url']
        db.session.add(Lesson(course_id=course_id, title=title, video_url=video_url))
        db.session.commit()
        flash("Lesson added!")
    lessons = Lesson.query.filter_by(course_id=course_id).all()
    return render_template('admin_lessons.html', course=course, lessons=lessons)

@app.route('/admin/lessons/delete/<int:lesson_id>', methods=['POST'])
@admin_required
def admin_lesson_delete(lesson_id):
    l = Lesson.query.get(lesson_id)
    course_id = l.course_id
    db.session.delete(l)
    db.session.commit()
    flash("Lesson deleted!")
    return redirect(url_for('admin_lessons', course_id=course_id))

@app.route('/admin/mcqs/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def admin_mcqs(course_id):
    course = Course.query.get(course_id)
    mcqs = MCQ.query.filter_by(course_id=course_id).all()
    if request.method == 'POST':
        question = request.form['question']
        options = json.dumps(request.form.getlist('options'))
        answer = request.form['answer']
        is_final = 'is_final' in request.form
        db.session.add(MCQ(course_id=course_id, question=question, options=options, answer=answer, is_final=is_final))
        db.session.commit()
        flash("MCQ added!")
    return render_template('admin_mcqs.html', course=course, mcqs=mcqs)

@app.route('/admin/mcqs/delete/<int:mcq_id>', methods=['POST'])
@admin_required
def admin_mcq_delete(mcq_id):
    m = MCQ.query.get(mcq_id)
    course_id = m.course_id
    db.session.delete(m)
    db.session.commit()
    flash("MCQ deleted!")
    return redirect(url_for('admin_mcqs', course_id=course_id))

@app.route('/admin/certificate/<int:course_id>', methods=['GET', 'POST'])
@admin_required
def admin_certificate(course_id):
    course = Course.query.get(course_id)
    if request.method == 'POST':
        template = request.form['cert_template']
        course.cert_template = template
        db.session.commit()
        flash("Certificate template updated!")
    return render_template('admin_certificate.html', course=course)

# ------------- RUN -------------
if __name__ == '__main__':
    app.run(debug=True)

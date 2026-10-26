import os, json, re, sqlite3, time, uuid, numpy as np
from collections import defaultdict
from functools import wraps
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, g, render_template, request, redirect, session, jsonify, abort, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from pypdf import PdfReader
import ai
import rbac

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "dev-secret-key-padhanaai-2026"),
    MAX_CONTENT_LENGTH=20*1024*1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)
from db import get_db as db, close_db, DB_PATH, DATA_DIR, BACKUP_DIR
app.teardown_appcontext(close_db)

UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, created REAL);
CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY, user_id INT, title TEXT, pages INT, status TEXT, created REAL);
CREATE TABLE IF NOT EXISTS chunks(id INTEGER PRIMARY KEY, doc_id INT, page INT, text TEXT, emb BLOB);
CREATE INDEX IF NOT EXISTS ix_chunks ON chunks(doc_id);
CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, doc_id INT, role TEXT, content TEXT, created REAL);
CREATE TABLE IF NOT EXISTS quizzes(id INTEGER PRIMARY KEY, doc_id INT, data TEXT, created REAL);
CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY, user_id INT, kind TEXT, created REAL);
"""

# Initialize base schema and Enterprise RBAC tables
with sqlite3.connect(DB_PATH) as _c:
    _c.executescript(SCHEMA)
    rbac.init_rbac_db(_c)

# Register Enterprise Admin Blueprint
from admin_routes import admin_bp
app.register_blueprint(admin_bp)

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "uid" not in session: return redirect(url_for("login"))
        return f(*a, **k)
    return w

_hits = defaultdict(list)
def limited(uid, n=20):
    now = time.time(); _hits[uid] = [t for t in _hits[uid] if now-t < 60]
    if len(_hits[uid]) >= n: return True
    _hits[uid].append(now); return False

def own_doc(did, write=False):
    """
    Enforces server-side cross-user document isolation and permissions.
    Permits owners, authorized teachers/students of shared classrooms, and moderators.
    """
    uid = session.get("uid")
    if not uid:
        abort(401)
    allowed, doc = rbac.can_access_document(uid, did, write=write)
    if not allowed or not doc:
        rbac.log_audit("unauthorized_document_access", target_type="doc", target_id=did, status="denied")
        abort(404 if not doc else 403)
    return doc

# Global Maintenance Mode Gate
@app.before_request
def check_maintenance():
    # Allow static assets and authentication endpoints during maintenance
    if request.path.startswith("/static") or request.path in ("/login", "/logout", "/signup"):
        return None

    uid = session.get("uid")
    if rbac.is_maintenance_active(uid):
        if request.is_json:
            return jsonify(error="System is temporarily offline for scheduled maintenance."), 503
        return render_template("admin/maintenance.html"), 503
    return None

@app.route("/")
def index():
    return render_template("index.html")

def auth(kind):
    if request.method == "POST":
        email, pw = request.form["email"].strip().lower(), request.form["password"]
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email) or len(pw) < 8:
            flash("Enter a valid email and a password of 8+ characters.")
        elif kind == "signup":
            try:
                now = time.time()
                cur = db().execute("INSERT INTO users(email,pw,created) VALUES(?,?,?)", (email, generate_password_hash(pw), now))
                uid = cur.lastrowid
                db().execute("INSERT INTO profiles(user_id, full_name, status, created_at, updated_at) VALUES(?,?, 'active', ?, ?)",
                             (uid, email.split("@")[0].title(), now, now))

                # If first user or specifically configured in env, grant super_admin; otherwise student
                user_count = db().execute("SELECT count(*) FROM users").fetchone()[0]
                role_slug = "super_admin" if user_count == 1 else "student"
                role_id = db().execute("SELECT id FROM roles WHERE slug = ?", (role_slug,)).fetchone()["id"]
                db().execute("INSERT INTO user_roles(user_id, role_id, created_at) VALUES(?,?,?)", (uid, role_id, now))
                db().commit()

                session["uid"] = uid
                rbac.log_audit("signup_success", target_type="user", target_id=uid)
                return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.")
        else:
            u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if u and check_password_hash(u["pw"], pw):
                # Verify account status
                prof = db().execute("SELECT status FROM profiles WHERE user_id = ?", (u["id"],)).fetchone()
                if prof and prof["status"] == "deactivated":
                    rbac.log_audit("login_failed_deactivated", target_type="user", target_id=u["id"], status="denied")
                    flash("This account is currently deactivated. Please contact your institution administrator.")
                    return render_template("auth.html", kind=kind)

                session["uid"] = u["id"]
                rbac.log_audit("login_success", target_type="user", target_id=u["id"])
                return redirect(url_for("dashboard"))

            rbac.log_audit("login_failed", target_type="auth", details={"email": email}, status="failed")
            flash("Incorrect email or password.")
    return render_template("auth.html", kind=kind)

@app.route("/signup", methods=["GET", "POST"])
def signup(): return auth("signup")

@app.route("/login", methods=["GET", "POST"])
def login(): return auth("login")

@app.route("/logout")
def logout():
    rbac.log_audit("logout", target_type="user", target_id=session.get("uid"))
    session.clear()
    return redirect(url_for("index"))

@app.context_processor
def inject_user():
    user = None
    user_roles = []
    is_staff = False
    if "uid" in session:
        try:
            user = db().execute("SELECT id, email, created FROM users WHERE id=?", (session["uid"],)).fetchone()
            user_roles = rbac.get_user_roles(session["uid"])
            is_staff = bool({"super_admin", "institution_admin", "teacher", "moderator_support"} & set(user_roles))
        except Exception:
            pass
    return dict(current_user=user, user_roles=user_roles, is_staff=is_staff)

@app.route("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "")
    uid = session["uid"]
    docs = db().execute("""
        SELECT d.* FROM docs d
        WHERE (d.user_id = ? OR EXISTS (
            SELECT 1 FROM shared_documents sd
            JOIN classroom_members cm ON sd.classroom_id = cm.classroom_id
            WHERE sd.doc_id = d.id AND cm.user_id = ?
        ))
        AND d.title LIKE ? AND d.status != 'takedown'
        ORDER BY d.created DESC
    """, (uid, uid, f"%{q}%")).fetchall()

    total_pages = sum(d["pages"] or 0 for d in docs)
    ready_count = sum(1 for d in docs if d["status"] == "ready")
    return render_template("dashboard.html", docs=docs, q=q, total_pages=total_pages, ready_count=ready_count)

def chunk_pages(pages, size=1000, overlap=150):
    for pno, t in pages:
        t = re.sub(r"\s+", " ", t).strip(); i = 0
        while i < len(t):
            yield pno, t[i:i+size]; i += size - overlap

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    f = request.files.get("file")
    if not f or not f.filename.lower().endswith(".pdf") or f.stream.read(5) != b"%PDF-":
        flash("Please upload a valid PDF file."); return redirect(url_for("dashboard"))
    f.stream.seek(0)
    try:
        reader = PdfReader(f.stream)
        pages = [(i+1, p.extract_text() or "") for i, p in enumerate(reader.pages)]
    except Exception:
        flash("This PDF looks corrupted or encrypted."); return redirect(url_for("dashboard"))
    if sum(len(t) for _, t in pages) < 50:
        flash("No text found - this looks like a scanned PDF. OCR isn't enabled yet."); return redirect(url_for("dashboard"))
    chunks = list(chunk_pages(pages))
    try:
        embs = ai.embed([c[1] for c in chunks]); status = "ready"
    except Exception:
        embs, status = [None]*len(chunks), "error"
        flash("Saved, but indexing failed. Check your AI settings and re-upload.")

    cur = db().execute("INSERT INTO docs(user_id,title,pages,status,created) VALUES(?,?,?,?,?)",
        (session["uid"], os.path.splitext(f.filename)[0][:120], len(pages), status, time.time()))
    doc_id = cur.lastrowid
    db().executemany("INSERT INTO chunks(doc_id,page,text,emb) VALUES(?,?,?,?)",
        [(doc_id, p, t, np.array(e, dtype=np.float32).tobytes() if e else None) for (p, t), e in zip(chunks, embs)])
    db().commit()

    rbac.log_audit("document_uploaded", target_type="doc", target_id=doc_id, details={"title": f.filename, "pages": len(pages)})
    return redirect(url_for("doc", did=doc_id))

@app.route("/doc/<int:did>")
@login_required
def doc(did):
    d = own_doc(did)
    msgs = db().execute("SELECT role,content FROM msgs WHERE doc_id=? ORDER BY id", (did,)).fetchall()
    return render_template("doc.html", d=d, msgs=msgs)

@app.post("/doc/<int:did>/rename")
@login_required
def rename(did):
    own_doc(did, write=True)
    new_title = request.form["title"][:120].strip()
    if new_title:
        db().execute("UPDATE docs SET title=? WHERE id=?", (new_title, did)); db().commit()
        rbac.log_audit("document_renamed", target_type="doc", target_id=did, details={"new_title": new_title})
    return redirect(url_for("doc", did=did))

@app.post("/doc/<int:did>/delete")
@login_required
def delete(did):
    own_doc(did, write=True)
    for t in ("chunks", "msgs", "quizzes", "shared_documents", "document_reports"):
        db().execute(f"DELETE FROM {t} WHERE doc_id=?", (did,))
    db().execute("DELETE FROM docs WHERE id=?", (did,)); db().commit()
    rbac.log_audit("document_deleted", target_type="doc", target_id=did)
    return redirect(url_for("dashboard"))

def retrieve(did, query, k=6):
    """
    RAG vector search strictly isolated to the specified document ID.
    Enforces that chunks from other users or documents are never queried.
    """
    rows = db().execute("SELECT page,text,emb FROM chunks WHERE doc_id=? AND emb IS NOT NULL", (did,)).fetchall()
    if not rows: return []
    q = np.array(ai.embed([query])[0], dtype=np.float32)
    M = np.stack([np.frombuffer(r["emb"], dtype=np.float32) for r in rows])
    s = M @ q / (np.linalg.norm(M, axis=1) * np.linalg.norm(q) + 1e-9)
    return [rows[i] for i in np.argsort(-s)[:k]]

def context(rows): return "\n\n".join(f"[p.{r['page']}] {r['text']}" for r in rows)

def guard(did):
    d = own_doc(did)
    if d["status"] != "ready": return jsonify(error="This document isn't indexed or is under review."), 400
    if limited(session["uid"]): return jsonify(error="Too many requests. Please wait a minute."), 429
    return None

@app.post("/api/doc/<int:did>/chat")
@login_required
def api_chat(did):
    if (e := guard(did)): return e
    q = (request.json or {}).get("question", "").strip()[:1000]
    if not q: return jsonify(error="Ask a question first."), 400
    start_t = time.time()
    try:
        rows = retrieve(did, q)
        hist = [{"role": m["role"], "content": m["content"]} for m in db().execute(
            "SELECT role,content FROM msgs WHERE doc_id=? ORDER BY id DESC LIMIT 6", (did,))][::-1]
        ans = ai.chat([{"role": "system", "content": ai.SYSTEM}, *hist,
            {"role": "user", "content": f"CONTEXT:\n{context(rows)}\n\nQUESTION: {q}"}], "standard")
        latency = (time.time() - start_t) * 1000.0
        p_tok, c_tok = len(q) // 4, len(ans) // 4
        rbac.track_ai_usage(session["uid"], did, "chat", "standard", p_tok, c_tok, latency)
    except Exception as err:
        latency = (time.time() - start_t) * 1000.0
        rbac.track_ai_usage(session["uid"], did, "chat", "standard", len(q) // 4, 0, latency, error=str(err))
        return jsonify(error="The AI service is unavailable right now. Please retry shortly."), 503

    now = time.time()
    db().executemany("INSERT INTO msgs(doc_id,role,content,created) VALUES(?,?,?,?)", [(did, "user", q, now), (did, "assistant", ans, now)])
    db().execute("INSERT INTO usage(user_id,kind,created) VALUES(?,?,?)", (session["uid"], "chat", now)); db().commit()
    return jsonify(answer=ans, pages=sorted({r["page"] for r in rows}))

@app.get("/api/doc/<int:did>/page/<int:p>")
@login_required
def api_page(did, p):
    own_doc(did)
    return jsonify(text="\n".join(r["text"] for r in db().execute("SELECT text FROM chunks WHERE doc_id=? AND page=? ORDER BY id", (did, p))))

@app.post("/api/doc/<int:did>/summary")
@login_required
def api_summary(did):
    if (e := guard(did)): return e
    kind = {"short": "a short summary (5 sentences)", "detailed": "a detailed, structured summary",
            "definitions": "a list of important definitions", "revision": "exam-oriented revision notes with bullet points"
            }.get((request.json or {}).get("kind"), "a short summary")
    rows = db().execute("SELECT page,text FROM chunks WHERE doc_id=? ORDER BY id LIMIT 12", (did,)).fetchall()
    start_t = time.time()
    try:
        tier = "simple" if "short" in kind else "standard"
        out = ai.chat([{"role": "system", "content": ai.SYSTEM}, {"role": "user", "content": f"CONTEXT:\n{context(rows)}\n\nWrite {kind} of this document, citing pages."}],
                      tier, 1200)
        latency = (time.time() - start_t) * 1000.0
        rbac.track_ai_usage(session["uid"], did, "summary", tier, 300, len(out) // 4, latency)
    except Exception as err:
        latency = (time.time() - start_t) * 1000.0
        rbac.track_ai_usage(session["uid"], did, "summary", "standard", 300, 0, latency, error=str(err))
        return jsonify(error="The AI service is unavailable right now."), 503
    return jsonify(text=out)

@app.post("/api/doc/<int:did>/quiz")
@login_required
def api_quiz(did):
    if (e := guard(did)): return e
    diff = (request.json or {}).get("difficulty", "Medium")
    diff = diff if diff in ("Easy", "Medium", "Hard") else "Medium"
    rows = db().execute("SELECT page,text FROM chunks WHERE doc_id=? ORDER BY RANDOM() LIMIT 8", (did,)).fetchall()
    prompt = (f"CONTEXT:\n{context(rows)}\n\nCreate 5 {diff} multiple-choice questions from the context. Return ONLY JSON: "
              '[{"q":"","options":["","","",""],"answer":0,"explanation":""}]')
    start_t = time.time()
    try:
        raw = ai.chat([{"role": "system", "content": ai.SYSTEM}, {"role": "user", "content": prompt}], "simple", 1500)
        quiz = json.loads(re.search(r"\[.*\]", raw, re.S).group(0))
        latency = (time.time() - start_t) * 1000.0
        rbac.track_ai_usage(session["uid"], did, "quiz", "simple", 400, len(raw) // 4, latency)
    except Exception as err:
        latency = (time.time() - start_t) * 1000.0
        rbac.track_ai_usage(session["uid"], did, "quiz", "simple", 400, 0, latency, error=str(err))
        return jsonify(error="Couldn't generate a quiz. Please try again."), 503

    db().execute("INSERT INTO quizzes(doc_id,data,created) VALUES(?,?,?)", (did, json.dumps(quiz), time.time())); db().commit()
    return jsonify(quiz=quiz)

if __name__ == "__main__":
    app.run(debug=True)

import os, json, re, sqlite3, time, uuid, numpy as np
from collections import defaultdict
from functools import wraps
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, g, render_template, request, redirect, session, jsonify, abort, flash, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from pypdf import PdfReader
import ai

app = Flask(__name__)
app.config.update(SECRET_KEY=os.getenv("SECRET_KEY", "dev"), MAX_CONTENT_LENGTH=20*1024*1024,
                  SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
os.makedirs("data/uploads", exist_ok=True)
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE, pw TEXT, created REAL);
CREATE TABLE IF NOT EXISTS docs(id INTEGER PRIMARY KEY, user_id INT, title TEXT, pages INT, status TEXT, created REAL);
CREATE TABLE IF NOT EXISTS chunks(id INTEGER PRIMARY KEY, doc_id INT, page INT, text TEXT, emb BLOB);
CREATE INDEX IF NOT EXISTS ix_chunks ON chunks(doc_id);
CREATE TABLE IF NOT EXISTS msgs(id INTEGER PRIMARY KEY, doc_id INT, role TEXT, content TEXT, created REAL);
CREATE TABLE IF NOT EXISTS quizzes(id INTEGER PRIMARY KEY, doc_id INT, data TEXT, created REAL);
CREATE TABLE IF NOT EXISTS usage(id INTEGER PRIMARY KEY, user_id INT, kind TEXT, created REAL);
"""
def db():
    if "db" not in g:
        g.db = sqlite3.connect("data/app.db"); g.db.row_factory = sqlite3.Row
    return g.db
@app.teardown_appcontext
def close(_):
    d = g.pop("db", None)
    if d: d.close()
with sqlite3.connect("data/app.db") as _c: _c.executescript(SCHEMA)

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

def own_doc(did):  # server-side authorization on every document op
    d = db().execute("SELECT * FROM docs WHERE id=? AND user_id=?", (did, session["uid"])).fetchone()
    return d or abort(404)

@app.route("/")
def index(): return render_template("index.html")

def auth(kind):
    if request.method == "POST":
        email, pw = request.form["email"].strip().lower(), request.form["password"]
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email) or len(pw) < 8:
            flash("Enter a valid email and a password of 8+ characters.")
        elif kind == "signup":
            try:
                cur = db().execute("INSERT INTO users(email,pw,created) VALUES(?,?,?)", (email, generate_password_hash(pw), time.time()))
                db().commit(); session["uid"] = cur.lastrowid; return redirect(url_for("dashboard"))
            except sqlite3.IntegrityError: flash("That email is already registered.")
        else:
            u = db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if u and check_password_hash(u["pw"], pw): session["uid"] = u["id"]; return redirect(url_for("dashboard"))
            flash("Incorrect email or password.")
    return render_template("auth.html", kind=kind)
@app.route("/signup", methods=["GET", "POST"])
def signup(): return auth("signup")
@app.route("/login", methods=["GET", "POST"])
def login(): return auth("login")
@app.route("/logout")
def logout(): session.clear(); return redirect(url_for("index"))

@app.context_processor
def inject_user():
    user = None
    if "uid" in session:
        try:
            user = db().execute("SELECT id, email, created FROM users WHERE id=?", (session["uid"],)).fetchone()
        except Exception:
            pass
    return dict(current_user=user)

@app.route("/dashboard")
@login_required
def dashboard():
    q = request.args.get("q", "")
    docs = db().execute("SELECT * FROM docs WHERE user_id=? AND title LIKE ? ORDER BY created DESC", (session["uid"], f"%{q}%")).fetchall()
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
        flash("No text found - this looks like a scanned PDF. OCR isn't enabled yet (see README)."); return redirect(url_for("dashboard"))
    chunks = list(chunk_pages(pages))
    try:
        embs = ai.embed([c[1] for c in chunks]); status = "ready"
    except Exception:
        embs, status = [None]*len(chunks), "error"
        flash("Saved, but indexing failed. Check your AI settings and re-upload.")
    cur = db().execute("INSERT INTO docs(user_id,title,pages,status,created) VALUES(?,?,?,?,?)",
        (session["uid"], os.path.splitext(f.filename)[0][:120], len(pages), status, time.time()))
    db().executemany("INSERT INTO chunks(doc_id,page,text,emb) VALUES(?,?,?,?)",
        [(cur.lastrowid, p, t, np.array(e, dtype=np.float32).tobytes() if e else None) for (p, t), e in zip(chunks, embs)])
    db().commit(); return redirect(url_for("doc", did=cur.lastrowid))

@app.route("/doc/<int:did>")
@login_required
def doc(did):
    d = own_doc(did)
    msgs = db().execute("SELECT role,content FROM msgs WHERE doc_id=? ORDER BY id", (did,)).fetchall()
    return render_template("doc.html", d=d, msgs=msgs)

@app.post("/doc/<int:did>/rename")
@login_required
def rename(did):
    own_doc(did); db().execute("UPDATE docs SET title=? WHERE id=?", (request.form["title"][:120], did)); db().commit()
    return redirect(url_for("doc", did=did))

@app.post("/doc/<int:did>/delete")
@login_required
def delete(did):
    own_doc(did)
    for t in ("chunks", "msgs", "quizzes"): db().execute(f"DELETE FROM {t} WHERE doc_id=?", (did,))
    db().execute("DELETE FROM docs WHERE id=?", (did,)); db().commit()
    return redirect(url_for("dashboard"))

def retrieve(did, query, k=6):
    rows = db().execute("SELECT page,text,emb FROM chunks WHERE doc_id=? AND emb IS NOT NULL", (did,)).fetchall()
    if not rows: return []
    q = np.array(ai.embed([query])[0], dtype=np.float32)
    M = np.stack([np.frombuffer(r["emb"], dtype=np.float32) for r in rows])
    s = M @ q / (np.linalg.norm(M, axis=1) * np.linalg.norm(q) + 1e-9)
    return [rows[i] for i in np.argsort(-s)[:k]]

def context(rows): return "\n\n".join(f"[p.{r['page']}] {r['text']}" for r in rows)

def guard(did):
    d = own_doc(did)
    if d["status"] != "ready": return jsonify(error="This document isn't indexed."), 400
    if limited(session["uid"]): return jsonify(error="Too many requests. Please wait a minute."), 429

@app.post("/api/doc/<int:did>/chat")
@login_required
def api_chat(did):
    if (e := guard(did)): return e
    q = (request.json or {}).get("question", "").strip()[:1000]
    if not q: return jsonify(error="Ask a question first."), 400
    try:
        rows = retrieve(did, q)
        hist = [{"role": m["role"], "content": m["content"]} for m in db().execute(
            "SELECT role,content FROM msgs WHERE doc_id=? ORDER BY id DESC LIMIT 6", (did,))][::-1]
        ans = ai.chat([{"role": "system", "content": ai.SYSTEM}, *hist,
            {"role": "user", "content": f"CONTEXT:\n{context(rows)}\n\nQUESTION: {q}"}], "standard")
    except Exception:
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
    try:
        out = ai.chat([{"role": "system", "content": ai.SYSTEM}, {"role": "user", "content": f"CONTEXT:\n{context(rows)}\n\nWrite {kind} of this document, citing pages."}],
                      "simple" if "short" in kind else "standard", 1200)
    except Exception: return jsonify(error="The AI service is unavailable right now."), 503
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
    try:
        raw = ai.chat([{"role": "system", "content": ai.SYSTEM}, {"role": "user", "content": prompt}], "simple", 1500)
        quiz = json.loads(re.search(r"\[.*\]", raw, re.S).group(0))
    except Exception: return jsonify(error="Couldn't generate a quiz. Please try again."), 503
    db().execute("INSERT INTO quizzes(doc_id,data,created) VALUES(?,?,?)", (did, json.dumps(quiz), time.time())); db().commit()
    return jsonify(quiz=quiz)

if __name__ == "__main__": app.run(debug=True)

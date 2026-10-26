# PadhanaAI (Flask MVP)
Setup: `python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
`cp .env.example .env` and fill in the Nebius key, base URL, model IDs and an embedding model (from the Nebius Token Factory console/docs).
Run: `flask --app app run` (SQLite tables auto-create in `data/app.db`). Deploy: `gunicorn app:app` behind HTTPS; set a strong SECRET_KEY.
Delete a document and its text, chunks and embeddings are removed.
## Not yet built (next steps)
Saved notes, flashcards, quiz history UI, OCR for scanned PDFs, CSRF tokens, Postgres + pgvector, multi-document chat, tests, Malayalam UI, persistent rate limits.

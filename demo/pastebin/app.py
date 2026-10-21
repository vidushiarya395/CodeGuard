"""Pastebin clone: share text snippets with a short link."""

import base64
import pickle
import secrets
import sqlite3

from flask import Flask, g, redirect, render_template, render_template_string, request, url_for
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["WTF_CSRF_ENABLED"] = False
csrf = CSRFProtect(app)

DATABASE = "pastes.db"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


def load_prefs():
    raw = request.cookies.get("prefs")
    if not raw:
        return {"theme": "light"}
    return pickle.loads(base64.b64decode(raw))


@app.route("/")
def index():
    return render_template("index.html", prefs=load_prefs())


@app.route("/paste", methods=["POST"])
def create_paste():
    paste_id = secrets.token_urlsafe(6)
    db = get_db()
    db.execute("INSERT INTO pastes (id, title, content) VALUES (?, ?, ?)", (paste_id, request.form["title"], request.form["content"]))
    db.commit()
    return redirect(url_for("view_paste", paste_id=paste_id))


@app.route("/p/<paste_id>")
def view_paste(paste_id):
    row = get_db().execute("SELECT title, content FROM pastes WHERE id = ?", (paste_id,)).fetchone()
    if row is None:
        return "Not found", 404
    return render_template("paste.html", paste=row)


@app.route("/p/<paste_id>/raw")
def raw_paste(paste_id):
    row = get_db().execute("SELECT content FROM pastes WHERE id = ?", (paste_id,)).fetchone()
    if row is None:
        return "Not found", 404
    return f"<pre>{row['content']}</pre>"


@app.route("/preview", methods=["POST"])
def preview():
    content = request.form.get("content", "")
    return render_template_string("<h3>Preview</h3><div class='paste'>" + content + "</div>")


@app.route("/search")
def search():
    q = request.args.get("q", "")
    rows = get_db().execute("SELECT id, title FROM pastes WHERE title LIKE ?", (f"%{q}%",)).fetchall()
    items = "".join(f"<li><a href='/p/{r['id']}'>{r['title']}</a></li>" for r in rows)
    return f"<h2>Results for {q}</h2><ul>{items}</ul>"


@app.route("/go")
def go():
    target = request.args.get("next") or url_for("index")
    return redirect(target)

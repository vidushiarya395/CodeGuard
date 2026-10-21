# Example only: scanned by the tests, never run.  CG-TNT-009 (safe)
from flask import Flask, request
from markupsafe import escape

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h2>Results for {escape(q)}</h2>"

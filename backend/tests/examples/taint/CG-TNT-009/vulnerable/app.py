# Example only: scanned by the tests, never run.  CG-TNT-009 (vulnerable)
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h2>Results for {q}</h2>"

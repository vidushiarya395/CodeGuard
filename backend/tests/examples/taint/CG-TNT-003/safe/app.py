# Example only: scanned by the tests, never run.  CG-TNT-003 (safe)
import sqlite3

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route("/users")
def find_user():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    rows = conn.execute("SELECT id, name FROM users WHERE name = ?", (name,)).fetchall()
    return jsonify(rows)

# Example only: scanned by the tests, never run.  CG-LGC-007 (vulnerable)
import secrets

from flask import Flask, make_response

app = Flask(__name__)


@app.route("/login", methods=["POST"])
def login():
    session_id = secrets.token_urlsafe(32)
    resp = make_response("logged in")
    resp.set_cookie("session_id", session_id, httponly=True)
    return resp

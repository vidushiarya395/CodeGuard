# Example only: scanned by the tests, never run.  CG-TNT-006 (safe)
from flask import Flask, redirect, request, url_for

app = Flask(__name__)
SAFE_PAGES = {"home": "/", "profile": "/profile"}


@app.route("/logout")
def logout():
    page = request.args.get("next", "home")
    return redirect(SAFE_PAGES.get(page, url_for("index")))

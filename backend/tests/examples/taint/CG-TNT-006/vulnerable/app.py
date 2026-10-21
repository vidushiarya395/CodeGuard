# Example only: scanned by the tests, never run.  CG-TNT-006 (vulnerable)
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/logout")
def logout():
    next_url = request.args.get("next", "/")
    return redirect(next_url)

# Example only: scanned by the tests, never run.  CG-TNT-001 (safe)
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return out.stdout

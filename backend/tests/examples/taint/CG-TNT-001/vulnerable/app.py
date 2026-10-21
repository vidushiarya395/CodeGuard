# Example only: scanned by the tests, never run.  CG-TNT-001 (vulnerable)
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    cmd = f"ping -c 1 {host}"
    out = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return out.stdout

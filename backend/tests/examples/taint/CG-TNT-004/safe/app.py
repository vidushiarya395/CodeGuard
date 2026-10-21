# Example only: scanned by the tests, never run.  CG-TNT-004 (safe)
import os

from flask import Flask, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
REPORTS = "/srv/reports"


@app.route("/report")
def report():
    name = secure_filename(request.args["name"])
    return send_file(os.path.join(REPORTS, name))

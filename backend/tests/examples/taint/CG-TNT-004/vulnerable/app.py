# Example only: scanned by the tests, never run.  CG-TNT-004 (vulnerable)
import os

from flask import Flask, request, send_file

app = Flask(__name__)
REPORTS = "/srv/reports"


@app.route("/report")
def report():
    name = request.args["name"]
    return send_file(os.path.join(REPORTS, name))

# Example only: scanned by the tests, never run.  CG-LGC-004 (vulnerable)
import os

from flask import Flask, request

app = Flask(__name__)
UPLOAD_DIR = "uploads"


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    if f.filename == "":
        return "no file selected", 400
    f.save(os.path.join(UPLOAD_DIR, f.filename))
    return "saved"

# Example only: scanned by the tests, never run.  CG-LGC-004 (safe)
import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
UPLOAD_DIR = "uploads"
ALLOWED_EXTENSIONS = {"png", "jpg", "gif"}


def allowed_file(name):
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files["file"]
    if not allowed_file(f.filename):
        return "file type not allowed", 400
    f.save(os.path.join(UPLOAD_DIR, secure_filename(f.filename)))
    return "saved"

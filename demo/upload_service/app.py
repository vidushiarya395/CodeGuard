"""File sharing service: upload files, list them, download and delete them."""

import os

from flask import Flask, jsonify, request, send_file
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
AVATAR_FOLDER = os.path.join(UPLOAD_FOLDER, "avatars")
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

os.makedirs(AVATAR_FOLDER, exist_ok=True)


def allowed_image(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify(error="No file part"), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify(error="No selected file"), 400
    file.save(os.path.join(UPLOAD_FOLDER, file.filename))
    return jsonify(message="File uploaded", filename=file.filename), 201


@app.route("/avatar", methods=["POST"])
def upload_avatar():
    file = request.files.get("avatar")
    if file is None or not allowed_image(file.filename):
        return jsonify(error="Only PNG, JPG and GIF images are allowed"), 400
    name = secure_filename(file.filename)
    file.save(os.path.join(AVATAR_FOLDER, name))
    return jsonify(message="Avatar saved", filename=name), 201


@app.route("/files")
def list_files():
    names = [n for n in os.listdir(UPLOAD_FOLDER) if os.path.isfile(os.path.join(UPLOAD_FOLDER, n))]
    return jsonify(files=sorted(names))


@app.route("/files/<path:filename>")
def download_file(filename):
    return send_file(os.path.join(UPLOAD_FOLDER, filename), as_attachment=True)


@app.route("/files/<path:filename>/delete", methods=["POST"])
def delete_file(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(path):
        os.remove(path)
        return jsonify(message="Deleted")
    return jsonify(error="Not found"), 404


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)

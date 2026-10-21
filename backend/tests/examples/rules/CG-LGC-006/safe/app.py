# Example only: scanned by the tests, never run.  CG-LGC-006 (safe)
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    is_admin = db.Column(db.Boolean, default=False)


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    user = User(username=data["username"], email=data["email"])
    db.session.add(user)
    db.session.commit()
    return jsonify(id=user.id), 201

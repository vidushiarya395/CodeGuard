# Example only: scanned by the tests, never run.  CG-LGC-002 (vulnerable)
from flask import Flask, abort, jsonify
from flask_login import current_user, login_required
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy(app)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role = db.Column(db.String(20))
    is_admin = db.Column(db.Boolean)


@app.route("/admin/users/<int:user_id>/promote", methods=["POST"])
@login_required
def promote_user(user_id):
    user = db.get_or_404(User, user_id)
    user.role = "admin"
    db.session.commit()
    return jsonify(ok=True)

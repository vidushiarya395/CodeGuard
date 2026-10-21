# Example only: scanned by the tests, never run.  CG-LGC-001 (safe)
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


@app.route("/posts/<int:post_id>", methods=["DELETE"])
@login_required
def delete_post(post_id):
    post = db.get_or_404(Post, post_id)
    if post.author_id != current_user.id:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    return jsonify(deleted=post_id)

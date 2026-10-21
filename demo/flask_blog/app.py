"""A small blog with user accounts, built with Flask, Flask-Login and SQLAlchemy."""

import hashlib
from datetime import datetime

from flask import Flask, abort, flash, redirect, render_template, request, url_for
from flask_login import LoginManager, UserMixin, current_user, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blog.db"
app.config["SECRET_KEY"] = "my-blog-secret-key-2024"

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    banned = db.Column(db.Boolean, default=False)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created = db.Column(db.DateTime, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()


@app.route("/")
def index():
    posts = Post.query.order_by(Post.created.desc()).all()
    return render_template("index.html", posts=posts)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = User(username=request.form["username"], password_hash=hash_password(request.form["password"]))
        db.session.add(user)
        db.session.commit()
        flash("Account created, please log in.")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and user.password_hash == hash_password(request.form["password"]):
            login_user(user)
            return redirect(url_for("index"))
        flash("Invalid username or password")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route("/post/<int:post_id>")
def view_post(post_id):
    post = db.get_or_404(Post, post_id)
    return render_template("post.html", post=post)


@app.route("/post/new", methods=["GET", "POST"])
@login_required
def new_post():
    if request.method == "POST":
        post = Post(title=request.form["title"], body=request.form["body"], author_id=current_user.id)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for("view_post", post_id=post.id))
    return render_template("new_post.html")


@app.route("/post/<int:post_id>/edit", methods=["GET", "POST"])
@login_required
def edit_post(post_id):
    post = db.get_or_404(Post, post_id)
    if post.author_id != current_user.id:
        abort(403)
    if request.method == "POST":
        post.title = request.form["title"]
        post.body = request.form["body"]
        db.session.commit()
        return redirect(url_for("view_post", post_id=post.id))
    return render_template("edit_post.html", post=post)


@app.route("/post/<int:post_id>/delete", methods=["POST"])
@login_required
def delete_post(post_id):
    post = db.get_or_404(Post, post_id)
    db.session.delete(post)
    db.session.commit()
    flash("Post deleted.")
    return redirect(url_for("index"))


@app.route("/search")
def search():
    q = request.args.get("q", "")
    sql = text(f"SELECT id, title FROM post WHERE title LIKE '%{q}%' ORDER BY created DESC")
    rows = db.session.execute(sql).fetchall()
    return render_template("search.html", rows=rows, q=q)


@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@login_required
def ban_user(user_id):
    user = db.get_or_404(User, user_id)
    user.banned = True
    db.session.commit()
    return redirect(url_for("index"))


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)

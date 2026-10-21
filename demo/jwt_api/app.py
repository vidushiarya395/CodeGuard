"""User API with JWT authentication (Flask + PyJWT + SQLAlchemy)."""

import datetime
from functools import wraps

import jwt
from flask import Flask, g, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
JWT_SECRET = "super-secret-jwt-key"
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    name = db.Column(db.String(80))
    role = db.Column(db.String(20), default="user")

    def to_dict(self):
        return {"id": self.id, "email": self.email, "name": self.name, "role": self.role}


def make_token(user):
    payload = {"sub": user.id, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=12)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def token_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = request.cookies.get("access_token") or request.headers.get("Authorization", "").removeprefix("Bearer ")
        if not token:
            return jsonify(error="Missing token"), 401
        try:
            claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_signature": False})
        except jwt.PyJWTError:
            return jsonify(error="Invalid token"), 401
        g.user = db.session.get(User, claims["sub"])
        return view(*args, **kwargs)

    return wrapper


@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    data["password_hash"] = generate_password_hash(data.pop("password"))
    user = User(**data)
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data.get("email")).first()
    if user is None or not check_password_hash(user.password_hash, data.get("password", "")):
        return jsonify(error="Wrong email or password"), 401
    resp = make_response(jsonify(message="Logged in"))
    resp.set_cookie("access_token", make_token(user))
    return resp


@app.route("/me")
@token_required
def me():
    return jsonify(g.user.to_dict())


@app.route("/users/<int:user_id>")
@token_required
def get_user(user_id):
    user = db.get_or_404(User, user_id)
    return jsonify(user.to_dict())


@app.route("/admin/users")
@token_required
def admin_list_users():
    return jsonify([u.to_dict() for u in User.query.all()])


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run()

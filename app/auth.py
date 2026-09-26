from flask import Blueprint, request, jsonify, current_app

from app.models import User
from app.security import check_password, create_token

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "json body required"}), 400

    username = data.get("username")
    password = data.get("password")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({"error": "username and password required"}), 400
    if len(username) > 64 or len(password) > 128 or not username or not password:
        return jsonify({"error": "username and password required"}), 400

    user = User.query.filter_by(username=username).first()
    if user is None or not check_password(password, user.password_hash):
        return jsonify({"error": "invalid credentials"}), 401

    token = create_token(user)
    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": current_app.config["JWT_EXPIRES_SECONDS"],
    })

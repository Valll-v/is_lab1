from flask import Blueprint, jsonify, g
from markupsafe import escape

from app.models import Post
from app.security import require_auth

api_bp = Blueprint("api", __name__, url_prefix="/api")


@api_bp.before_request
def check_token():
    return require_auth()


@api_bp.route("/data", methods=["GET"])
def get_data():
    posts = Post.query.order_by(Post.id).all()
    result = []
    for p in posts:
        result.append({
            "id": p.id,
            "title": str(escape(p.title)),
            "body": str(escape(p.body)),
            "author": str(escape(p.author.username)),
        })
    return jsonify({"data": result, "count": len(result)})


@api_bp.route("/me", methods=["GET"])
def get_me():
    user = g.current_user
    return jsonify({
        "id": user.id,
        "username": str(escape(user.username)),
        "posts_count": len(user.posts),
    })

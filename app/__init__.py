from flask import Flask, jsonify

from app.config import Config
from app.models import db, User, Post
from app.security import hash_password


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    app.json.ensure_ascii = False

    db.init_app(app)

    from app.auth import auth_bp
    from app.api import api_bp
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    @app.after_request
    def set_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        return response

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "not found"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return jsonify({"error": "method not allowed"}), 405

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "internal server error"}), 500

    with app.app_context():
        db.create_all()
        seed_data()

    return app


def seed_data():
    if User.query.first() is not None:
        return

    admin = User(username="admin", password_hash=hash_password("admin123"))
    user = User(username="user", password_hash=hash_password("user123"))
    db.session.add_all([admin, user])
    db.session.commit()

    posts = [
        Post(title="Первый пост", body="Привет, это тестовый пост.", author_id=admin.id),
        Post(title="Про безопасность", body="Не храните пароли в открытом виде!", author_id=user.id),
        Post(title="<script>alert('xss')</script>", body="<img src=x onerror=alert(1)>", author_id=user.id),
    ]
    db.session.add_all(posts)
    db.session.commit()

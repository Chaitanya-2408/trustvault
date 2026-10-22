
from flask import Flask, jsonify


def create_app(test_config=None):
    app = Flask(__name__)
    app.config["TESTING"] = False

    if test_config:
        app.config.update(test_config)

    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "TrustVault"
        }), 200

    return app

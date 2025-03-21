from flask import (
    Flask,
    current_app,
    render_template,
    session,
    redirect,
    url_for,
    request,
)
from flask_cors import CORS
from flask_qrcode import QRcode
from flask_session import Session
from app.plugins.askar import AskarStorage
from app.routes.wizard import bp as wizard_bp
from config import Config
from asyncio import run as _await


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    CORS(app)
    QRcode(app)
    Session(app)

    app.register_blueprint(wizard_bp, prefix="/wizard")

    @app.before_request
    def before_request_callback():
        session["title"] = Config.APP_TITLE
        session["api"] = Config.ANONCREDS_API
        if not session.get("demo"):
            session["demo"] = _await(AskarStorage().fetch("demo", "default"))
            session["credentials"] = {}
            session["presentations"] = {}

    @app.route("/")
    def index():
        print(session["presentations"])
        return render_template(
            "pages/index.jinja", title=session["title"], demo=session["demo"]
        )

    @app.route("/credential")
    def get_credential():
        credential_label = request.args.get("credential")
        credential = _await(AskarStorage().fetch("credential", credential_label))
        if credential:
            session["credentials"][credential_label] = credential
        return redirect(url_for("index"))

    @app.route("/presentation")
    def show_presentation():
        presentation_label = request.args.get("presentation")
        presentation = _await(AskarStorage().fetch("presentation", presentation_label))
        if presentation:
            session["presentations"][presentation_label] = presentation
        return redirect(url_for("index"))

    @app.route("/reset")
    def reset():
        session.clear()
        return redirect(url_for("index"))

    return app

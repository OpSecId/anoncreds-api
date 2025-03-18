from flask import Flask, current_app, render_template, session, redirect, url_for, request
from flask_cors import CORS
from flask_qrcode import QRcode
from flask_session import Session
from app.plugins.askar import AskarStorage
from config import Config
from asyncio import run as _await

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    CORS(app)
    QRcode(app)
    Session(app)

    @app.before_request
    def before_request_callback():
        session["title"] = Config.APP_TITLE
        session["api"] = Config.ANONCREDS_API
        if not session.get('demo'):
            session['demo'] = _await(AskarStorage().fetch('demo', 'default'))

    @app.route("/")
    def index():
        return render_template("pages/index.jinja", title=session['title'], demo=session['demo'])

    return app

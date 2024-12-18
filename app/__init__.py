from flask import Flask
from config import Config
from app.routes import main  # Import the blueprint

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Register the blueprint
    app.register_blueprint(main)

    return app

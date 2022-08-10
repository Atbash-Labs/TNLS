from threading import Thread

from flask import Flask, current_app, Blueprint

from relayer import Relayer


def convert_config_file_to_dict(_config_file) -> dict:
    pass


route_blueprint = Blueprint('route_blueprint', __name__)


@route_blueprint.route('/')
def index():
    return str(current_app.config['RELAYER'])


def app_factory(config_filename):
    app = Flask(__name__)
    relayer = Relayer(convert_config_file_to_dict(config_filename))
    thread = Thread(target=relayer.run)
    thread.start()
    app.config['RELAYER'] = relayer
    app.register_blueprint(route_blueprint)
    return app

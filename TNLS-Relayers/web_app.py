from threading import Thread

from flask import Flask, current_app, Blueprint

from relayer import Relayer


def convert_config_file_to_dict(_config_file) -> dict:
    config_dict = {}
    with open(_config_file) as f:
        for line in f.readlines():
            key, val = line.split('=')
            config_dict[key] = val
    return config_dict


route_blueprint = Blueprint('route_blueprint', __name__)


@route_blueprint.route('/')
def index():
    return str(current_app.config['RELAYER'])


def app_factory(config_filename, config_file_converter=convert_config_file_to_dict, num_loops=None):
    app = Flask(__name__)
    relayer = Relayer(config_file_converter(config_filename), num_loops=num_loops)
    thread = Thread(target=relayer.run)
    thread.start()
    app.config['RELAYER'] = relayer
    app.register_blueprint(route_blueprint)
    return app

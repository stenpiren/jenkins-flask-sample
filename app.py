#!/usr/bin/python3
# -*- coding: utf-8 -*-

from flask import Flask
from resource import api
from models import db
from config import Config


def create_app(config):
    app = Flask(__name__)
    app.config.from_object(config)
    config.init_app(app)
    db.init_app(app)
    api.init_app(app)

    with app.app_context():
        db.drop_all()
        db.create_all()

    return app


if __name__ == '__main__':
    app = create_app(Config)
    app.run()

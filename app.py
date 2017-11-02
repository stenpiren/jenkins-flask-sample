#!/usr/bin/python3
# -*- coding: utf-8 -*-

from flask import Flask
from resource import api
from models import db
from config import Config

app = Flask(__name__)


def init_app(config):
    app.config.from_object(config)
    config.init_app(app)
    db.init_app(app)
    api.init_app(app)

    if app.debug:
        with app.app_context():
            db.drop_all()
            db.create_all()


init_app(Config)

if __name__ == '__main__':
    app.run()


#!/usr/bin/python3
# -*- coding: utf-8 -*-

from flask import Flask
from flask_migrate import Migrate
from resource import api
from models import db
from config import Config

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
api.init_app(app)
migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run()

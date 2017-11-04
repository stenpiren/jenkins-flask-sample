#!/usr/bin/python3
# -*- coding: utf-8 -*-
from flask import Flask
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from models import db
from config import Config

app = Flask(__name__)


def init_app(config):
    app.config.from_object(config)
    db.init_app(app)
    migrate = Migrate(app, db)


init_app(Config)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    manager.run()

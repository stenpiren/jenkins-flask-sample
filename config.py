#!/usr/bin/python3
# -*- coding: utf-8 -*-

from os import environ as env

try:
    from local_config import config
except ModuleNotFoundError:
    config = {}


class Config:
    DEBUG = config.get("DEBUG") or env.get("DEBUG", False)
    JWT_TOKEN_SECRET = config.get("JWT_TOKEN_SECRET") or env.get("JWT_TOKEN_SECRET")
    SQLALCHEMY_DATABASE_URI = config.get("SQLALCHEMY_DATABASE_URI") or env.get("SQLALCHEMY_DATABASE_URI")
    SQLALCHEMY_ECHO = config.get("SQLALCHEMY_ECHO") or env.get("SQLALCHEMY_ECHO", False)
    SQLALCHEMY_TRACK_MODIFICATIONS = config.get("SQLALCHEMY_TRACK_MODIFICATIONS") or env.get(
        "SQLALCHEMY_TRACK_MODIFICATIONS", False)
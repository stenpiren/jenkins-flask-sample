#!/usr/bin/python3
# -*- coding: utf-8 -*-

import datetime
from uuid import uuid4
from flask import g, current_app
from flask_sqlalchemy import SQLAlchemy
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth, MultiAuth
from pyotp import TOTP, random_base32
from itsdangerous import TimedJSONWebSignatureSerializer as JSONWebToken
from itsdangerous import BadSignature, SignatureExpired, Signer
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
basic_auth = HTTPBasicAuth()
token_auth = HTTPTokenAuth('Token')
auth = MultiAuth(basic_auth, token_auth)


@basic_auth.verify_password
def verify_password(login_name: str, password: str) -> bool:
    try:
        user = UserAuthInfo.query.filter(
            ((UserAuthInfo.login_name == login_name) & (UserAuthInfo.login_name != '')) |
            ((UserAuthInfo.mobile == login_name) & (UserAuthInfo.mobile != '')) |
            ((UserAuthInfo.email == login_name) & (UserAuthInfo.email != ''))) \
            .first()
    except Exception as e:
        return False

    if user and user.verify_password(password):
        g.user = user
        return True

    return False


@token_auth.verify_token
def verify_token(token: str) -> bool:
    jwt = JSONWebToken(secret_key=current_app.config['JWT_TOKEN_SECRET'])
    try:
        data = jwt.loads(token)
    except (BadSignature, SignatureExpired) as e:
        return False

    user_id = data.get('id', None)
    device_id = data.get('login_device_id', None)
    if user_id:
        g.user_id = user_id
        g.device_id = device_id
        return True

    return False


class ETag(object):
    @classmethod
    def if_match_tag(cls, tag=None) -> bool:
        if tag == cls.last_modify_tag:
            cls.last_modify_tag = str(uuid4())
            cls.last_modify_date = datetime.datetime.utcnow()
            return True
        else:
            return False


class CURD(object):
    def save(self, commit=True):
        """Save the record."""
        db.session.add(self)
        if commit:
            db.session.commit()
        return self


class UserAuthInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.Unicode(36), unique=True, index=True)
    login_name = db.Column(db.Unicode(64), index=True, nullable=False)
    mobile = db.Column(db.Unicode(32), index=True, nullable=False)
    email = db.Column(db.Unicode(128), index=True, nullable=False)
    password_hash = db.Column(db.Unicode(96), nullable=False)
    type = db.Column(db.Unicode(16), nullable=False)
    registered_device_id = db.Column(db.Unicode(32), nullable=False, default='')
    registered_date = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow())
    last_login_device_id = db.Column(db.Unicode(32), nullable=False, default='')
    last_login_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    is_deleted = db.Column(db.SmallInteger, default=0)
    deleted_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    is_email_activated = db.Column(db.SmallInteger, default=0)
    is_mobile_activated = db.Column(db.SmallInteger, default=0)
    last_modify_tag = db.Column(db.Unicode(36), default=str(uuid4()))
    last_modify_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    social_info = db.relationship('UserSocialInfo',
                                  primaryjoin='foreign(UserAuthInfo.id) == remote(UserSocialInfo.id)',
                                  lazy='joined', uselist=False)
    im_config = db.relationship('UserIMConfig',
                                primaryjoin='foreign(UserAuthInfo.id) == remote(UserIMConfig.id)',
                                lazy='joined', uselist=False)
    push_config = db.relationship('UserPushConfig',
                                  primaryjoin='foreign(UserAuthInfo.id) == remote(UserPushConfig.id)',
                                  lazy='joined', uselist=False)

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def update_last_login_datetime(self, device_id: str):
        self.last_login_device_id = device_id
        self.last_login_date = datetime.datetime.utcnow()
        db.session.commit()

    @property
    def token(self, expires=30 * 24 * 60 * 60, **kwargs):
        jwt = JSONWebToken(secret_key=current_app.config['JWT_TOKEN_SECRET'], expires_in=expires)
        data = {'uuid': self.uuid, 'last_login_device_id': self.last_login_device_id}
        for k, v in kwargs:
            data[k] = v

        return jwt.dumps(data).decode('utf-8')

    def activate_email(self, token: str) -> bool:
        jwt = JSONWebToken(secret_key=current_app.config['JWT_TOKEN_SECRET'])
        try:
            data = jwt.loads(token)
        except Exception as e:
            return False

        if data.get('id') == self.id:
            if not data.get('email') and data.get('email') == self.email:
                self.is_email_activated = 1
                return True

        return False

    def activate_mobile(self, token: str) -> bool:
        jwt = JSONWebToken(secret_key=current_app.config['JWT_TOKEN_SECRET'])
        try:
            data = jwt.loads(token)
        except Exception as e:
            return False

        if data.get('uuid') == self.uuid:
            if not data.get('mobile') and data.get('mobile') == self.mobile:
                self.is_mobile_activated = 1
                return True

        return False

    @property
    def is_exist(self) -> bool:
        if UserAuthInfo.query.filter(
                                ((UserAuthInfo.login_name == self.login_name) & (UserAuthInfo.login_name != '')) |
                                ((UserAuthInfo.mobile == self.mobile) & (UserAuthInfo.mobile != '')) |
                        ((UserAuthInfo.email == self.email) & (UserAuthInfo.email != ''))) \
                .filter(UserAuthInfo.uuid != self.uuid).first():
            return True

        return False

    def __str__(self):
        return self.uuid


class PersonalUser(CURD, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.Unicode(36), unique=True, index=True)
    gender = db.Column(db.SmallInteger)
    real_name = db.Column(db.Unicode(16))
    birthday = db.Column(db.DateTime)
    address = db.Column(db.UnicodeText)
    last_modify_tag = db.Column(db.Unicode(36), default=str(uuid4()))
    last_modify_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    auth_info = db.relationship('UserAuthInfo',
                                primaryjoin='foreign(PersonalUser.id) == remote(UserAuthInfo.id)',
                                lazy='joined', uselist=False)

    social_info = db.relationship('UserSocialInfo',
                                  primaryjoin='foreign(PersonalUser.id) == remote(UserSocialInfo.id)',
                                  lazy='joined', uselist=False)
    im_config = db.relationship('UserIMConfig',
                                primaryjoin='foreign(PersonalUser.id) == remote(UserIMConfig.id)',
                                lazy='joined', uselist=False)
    push_config = db.relationship('UserPushConfig',
                                  primaryjoin='foreign(PersonalUser.id) == remote(UserPushConfig.id)',
                                  lazy='joined', uselist=False)


class EnterpriseUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.Unicode(36), unique=True, index=True)
    enterprise_name = db.Column(db.Unicode(64), nullable=False)
    address = db.Column(db.UnicodeText)
    last_modify_tag = db.Column(db.Unicode(36), default=str(uuid4()))
    last_modify_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())
    auth_info = db.relationship('UserAuthInfo',
                                primaryjoin='foreign(EnterpriseUser.id) == remote(UserAuthInfo.id)',
                                lazy='joined', uselist=False)
    social_info = db.relationship('UserSocialInfo',
                                  primaryjoin='foreign(EnterpriseUser.id) == remote(UserSocialInfo.id)',
                                  lazy='joined', uselist=False)
    im_config = db.relationship('UserIMConfig',
                                primaryjoin='foreign(EnterpriseUser.id) == remote(UserIMConfig.id)',
                                lazy='joined', uselist=False)
    push_config = db.relationship('UserPushConfig',
                                  primaryjoin='foreign(EnterpriseUser.id) == remote(UserPushConfig.id)',
                                  lazy='joined', uselist=False)


class UserSocialInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.Unicode(36), unique=True, index=True)
    type = db.Column(db.Unicode(16), nullable=False)
    nick_name = db.Column(db.Unicode(64), nullable=False)
    experience = db.Column(db.BigInteger, default=0)
    last_modify_tag = db.Column(db.Unicode(36), default=str(uuid4()))
    last_modify_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())

    def update_info(self):
        self.last_modify_tag = str(uuid4())
        self.last_modify_date = datetime.datetime.utcnow()
        db.session.commit()


class UserIMConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.Unicode(36), unique=True, index=True)
    type = db.Column(db.Unicode(16), nullable=False)
    token = db.Column(db.Unicode(128), default='')
    chat_room_limit = db.Column(db.Integer, default=0)
    chat_group_limit = db.Column(db.Integer, default=0)
    last_modify_tag = db.Column(db.Unicode(36), default=str(uuid4()))
    last_modify_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())


class UserPushConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.Unicode(36), unique=True, index=True)
    type = db.Column(db.Unicode(16), nullable=False)
    not_allow_ad = db.Column(db.SmallInteger, default=0)
    last_modify_tag = db.Column(db.Unicode(36), default=str(uuid4()))
    last_modify_date = db.Column(db.DateTime, default=datetime.datetime.utcnow())


class VerificationCode(object):
    def __init__(self, factor):
        self.factor = factor

    @property
    def token(self) -> str:
        signer = Signer(current_app.config['JWT_TOKEN_SECRET'])
        jwt = JSONWebToken(secret_key=current_app.config['JWT_TOKEN_SECRET'], expires_in=15 * 60)
        string = ''.join((self.factor, self.code))
        signature = signer.sign(string.encode('utf-8')).decode('utf-8').split('.')[1]
        return jwt.dumps({'signature': signature}).decode('utf-8')

    @property
    def code(self) -> str:
        otp = TOTP(random_base32())
        return otp.now()

    @staticmethod
    def verify_code(token: str, factor: str, code: str) -> bool:
        signer = Signer(current_app.config['JWT_TOKEN_SECRET'])
        jwt = JSONWebToken(secret_key=current_app.config['JWT_TOKEN_SECRET'], expires_in=15 * 60)
        try:
            data = jwt.loads(token)
        except (BadSignature, SignatureExpired) as e:
            return False
        string = ''.join((factor, code))
        signature = signer.sign(string.encode('utf-8')).decode('utf-8').split('.')[1]
        if signature == data.get('signature', ''):
            return True

        return False

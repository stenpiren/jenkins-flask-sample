#!/usr/bin/python3
# -*- coding: utf-8 -*-

from flask import g
from flask_restful import Api, Resource
from flask_restful import abort, reqparse, fields, marshal_with, marshal
from models import PersonalUser, EnterpriseUser, UserAuthInfo
from models import UserSocialInfo, UserIMConfig, UserPushConfig
from models import VerificationCode
from models import db, auth, basic_auth, token_auth

api = Api()


class StringFormat(object):
    @staticmethod
    def email(string: str):
        # todo: 验证 email 格式
        if True:
            return string
        else:
            raise ValueError('{} 未通过 E-mail 校验.'.format(string))

    @staticmethod
    def phone(string: str):
        # todo: 验证 phone 格式
        if True:
            return string
        else:
            raise ValueError('{} 未通过 Phone 校验.'.format(string))

    @staticmethod
    def mobile(string):
        # todo: 验证 mobile 格式
        if True:
            return string
        else:
            raise ValueError('{} 未通过 Mobile 校验.'.format(string))


class JSONFields(object):
    social_fields = {
        'nick_name': fields.String,
        'experience': fields.Integer,
        'uri': fields.Url('api.user_social_info', absolute=False),
    }

    im_config_fields = {
        'uri': fields.Url('api.user_im_config', absolute=False),
        'token': fields.String,
        'chat_room_limit': fields.String,
        'chat_group_limit': fields.String
    }

    push_config_fields = {
        'uri': fields.Url('api.user_push_config', absolute=False),
        'not_allow_ad': fields.Integer
    }

    user_fields = {
        'uuid': fields.String,
        'type': fields.String(default='personal'),
        'uri': fields.Url('api.user')
    }

    token_fields = {
        'id': fields.String(default=''),
        'token': fields.String(default=''),
        'uri': fields.Url(endpoint='api.token')
    }


class User(Resource):
    parser = reqparse.RequestParser()
    fields = JSONFields.user_fields
    status = 200
    headers = {}

    def __init__(self):
        self.fields['social_info'] = fields.Nested(JSONFields.social_fields)
        self.fields['im_config'] = fields.Nested(JSONFields.im_config_fields)
        self.fields['push_config'] = fields.Nested(JSONFields.push_config_fields)

    def get(self, uuid):
        user = UserAuthInfo.query.outerjoin(UserSocialInfo, UserAuthInfo.uuid == UserSocialInfo.uuid) \
            .filter(UserAuthInfo.uuid == str(uuid)).first_or_404()
        self.headers['Etag'] = user.last_modify_tag
        return marshal(user, self.fields), self.status, self.headers


class Users(Resource):
    parser = reqparse.RequestParser()
    fields = JSONFields.user_fields
    status = 200
    headers = {}

    def get(self):
        users = UserAuthInfo.query.outerjoin(UserSocialInfo, UserAuthInfo.id == UserSocialInfo.id).all()
        return marshal(users, self.fields), self.status, self.headers

    def post(self):
        self.parser.add_argument('login_name', default='', location='form')
        self.parser.add_argument('password', required=True, location='form')
        self.parser.add_argument('nick_name', default='', location='form')
        self.parser.add_argument('mobile', default='', type=StringFormat.mobile, location='form')
        self.parser.add_argument('type', default='personal', choices=('personal', 'enterprise'),
                                 type=str, location='form')
        self.parser.add_argument('email', default='', type=StringFormat.email, location='form')
        self.parser.add_argument('address', default='', type=str, location='form')

        args = self.parser.parse_args()
        if ''.join((args['login_name'], args['mobile'], args['email'])) == '':
            abort(400, message='{}'.format('login name mobile email 至少有一个合法'))

        user_auth = UserAuthInfo(uuid=str(uuid1()), password=args['password'],
                                 login_name=args['login_name'], mobile=args['mobile'],
                                 type=args['type'], email=args['email'], last_modify_tag=str(uuid4()))

        if user_auth.is_exist:
            abort(400, message="{} 已经存在".format('login_name or mobile or email'))

        if args['nick_name'] == '':
            if args['login_name'] != '':
                args['nick_name'] = args['login_name']
            else:
                args['nick_name'] = ''.join(('djt', '_', user_auth.id[:8]))

        user_social = UserSocialInfo(uuid=user_auth.uuid, type=user_auth.type, nick_name=args['nick_name'])
        user_im_config = UserIMConfig(uuid=user_auth.uuid, type=user_auth.type)
        user_push_config = UserPushConfig(uuid=user_auth.uuid, type=user_auth.type)

        if args['type'] == 'personal':
            user = PersonalUser(uuid=user_auth.uuid, address=args['address'])
        elif args['type'] == 'enterprise':
            user = EnterpriseUser(uuid=user_auth.uuid, enterprise_name=args['enterprise_name'], address=args['address'])
        else:
            user = None

        if user:
            user.auth_info = user_auth
            user.social_info = user_social
            user.im_config = user_im_config
            user.push_config = user_push_config
            self.status = 201
        else:
            abort(400)

        user.save()

        return marshal(user_auth, self.fields), self.status, self.headers


class UsersSocialInfo(Resource):
    parser = reqparse.RequestParser()
    fields = JSONFields.social_fields
    status = 200
    headers = {}

    def __init__(self):
        self.fields['id'] = fields.String
        self.fields['type'] = fields.String

    def get(self, id):

        self.parser.add_argument('If-Match', location='headers')
        args = self.parser.parse_args()
        user = UserSocialInfo.query.filter(UserSocialInfo.id == str(id)).first_or_404()
        if user.if_match_tag(args['If-Match']):
            self.status = 304
        else:
            self.status = 200
            self.headers['Etag'] = user.last_modify_tag

        return marshal(user, self.fields), self.status, self.headers

    def put(self, id):

        self.parser.add_argument('nick_name', location='form')
        self.parser.add_argument('If-Match', location='headers')
        args = self.parser.parse_args()
        user = UserSocialInfo.query.filter(UserSocialInfo.id == str(id)).first_or_404()
        headers = {}
        if user.if_match_tag(args['If-Match']):
            user.nick_name = args.get('nick_name') if args.get('nick_name') else user.nick_name
            user.update_info()
            headers['Etag'] = user.last_modify_tag
        else:
            abort(412)

        return marshal(user, self.fields), 201, headers


class UsersIMConfig(Resource):
    parser = reqparse.RequestParser()
    fields = JSONFields.im_config_fields
    status = 200
    headers = {}

    def __init__(self):
        self.fields['id'] = fields.String
        self.fields['type'] = fields.String

    @token_auth.login_required
    def get(self, id):

        self.parser.add_argument('If-Match', location='headers')
        user = UserIMConfig.query.filter(UserIMConfig.uuid == str(id)).first_or_404()

        if user.if_match_tag(args['If-Match']):
            self.status = 304
        else:
            self.status = 200
            self.headers['Etag'] = user.last_modify_tag

        return marshal(user, self.fields), self.status, self.headers

    @token_auth.login_required
    def put(self, id):
        pass


class UsersPushConfig(Resource):
    parser = reqparse.RequestParser()
    fields = JSONFields.push_config_fields
    status = 200
    headers = {}

    def __init__(self):
        self.fields['id'] = fields.String
        self.fields['type'] = fields.String

    @token_auth.login_required
    def get(self, id):
        user = UserPushConfig.query.filter(UserPushConfig.uuid == str(id)).first_or_404()
        self.headers['Etag'] = user.last_modify_tag

        return marshal(user, self.fields), self.status, self.headers

    @token_auth.login_required
    def put(self, id):
        pass


class Tokens(Resource):
    parser = reqparse.RequestParser()
    fields = JSONFields.token_fields
    status = 200
    headers = {}

    @basic_auth.login_required
    def post(self):
        user = g.user
        user.update_last_login_datetime(device_id='')

        return marshal(user, self.fields), self.status, self.headers

    @token_auth.login_required
    def put(self, id):
        if g.user_id == str(id):
            user = UserAuthInfo.query.filter(UserAuthInfo.uuid == g.user_id).first_or_404()
            self.status = 201
        else:
            abort(403, message='用户不匹配.')

        return marshal(user, self.fields), self.status, self.headers


class VerificationCodes(Resource):
    """
    使用 hash (手机号 + jwt secret) 作为 OTP SECRET 生成验证码
    对 手机号 + 验证码 签名,生成签名作为 token 返回客户端
    验证时,使用客户端提交的手机号 + 验证码生成签名,与 token 中的签名进行比对验证是否正确
    """

    parser = reqparse.RequestParser()
    fields = {'token': fields.String}
    status = 200
    headers = {}

    def post(self):
        self.parser.add_argument('mobile', default='', type=StringFormat.mobile, location='form')
        self.parser.add_argument('email', default='', type=StringFormat.email, location='form')
        args = self.parser.parse_args()
        if args.get('mobile') and args.get('email'):
            abort(400, message='')
        sms = VerificationCode(args.get('mobile'))
        self.status = 202
        return marshal(sms, self.fields), self.status, self.headers


api.add_resource(Users, '/users', methods=['GET', 'POST'])
api.add_resource(User, '/users/<uuid:uuid>', endpoint='api.user', methods=['GET', ])
api.add_resource(UsersSocialInfo, '/users/<uuid:uuid>/social-info', endpoint='api.user_social_info',
                 methods=['GET', 'PUT'])
api.add_resource(UsersIMConfig, '/users/<uuid:uuid>/im-config', endpoint='api.user_im_config',
                 methods=['GET', 'PUT'])
api.add_resource(UsersPushConfig, '/users/<uuid:uuid>/push-config', endpoint='api.user_push_config',
                 methods=['GET', 'PUT'])
api.add_resource(Tokens, '/tokens', methods=['POST', ])
api.add_resource(Tokens, '/users/<uuid:uuid>/token', endpoint='api.token', methods=['GET', 'PUT'])
api.add_resource(VerificationCodes, '/verification-codes', methods=['POST', ])

"""empty message

Revision ID: 2c6e8ef271eb
Revises: 
Create Date: 2017-11-04 15:23:15.860898

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2c6e8ef271eb'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('enterprise_user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.Unicode(length=36), nullable=True),
    sa.Column('enterprise_name', sa.Unicode(length=64), nullable=False),
    sa.Column('address', sa.UnicodeText(), nullable=True),
    sa.Column('last_modify_tag', sa.Unicode(length=36), nullable=True),
    sa.Column('last_modify_date', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_enterprise_user_uuid'), 'enterprise_user', ['uuid'], unique=True)
    op.create_table('personal_user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.Unicode(length=36), nullable=True),
    sa.Column('gender', sa.SmallInteger(), nullable=True),
    sa.Column('real_name', sa.Unicode(length=16), nullable=True),
    sa.Column('birthday', sa.DateTime(), nullable=True),
    sa.Column('address', sa.UnicodeText(), nullable=True),
    sa.Column('last_modify_tag', sa.Unicode(length=36), nullable=True),
    sa.Column('last_modify_date', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_personal_user_uuid'), 'personal_user', ['uuid'], unique=True)
    op.create_table('user_auth_info',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.Unicode(length=36), nullable=True),
    sa.Column('login_name', sa.Unicode(length=64), nullable=False),
    sa.Column('mobile', sa.Unicode(length=32), nullable=False),
    sa.Column('email', sa.Unicode(length=128), nullable=False),
    sa.Column('password_hash', sa.Unicode(length=96), nullable=False),
    sa.Column('type', sa.Unicode(length=16), nullable=False),
    sa.Column('registered_device_id', sa.Unicode(length=32), nullable=False),
    sa.Column('registered_date', sa.DateTime(), nullable=False),
    sa.Column('last_login_device_id', sa.Unicode(length=32), nullable=False),
    sa.Column('last_login_date', sa.DateTime(), nullable=True),
    sa.Column('is_deleted', sa.SmallInteger(), nullable=True),
    sa.Column('deleted_date', sa.DateTime(), nullable=True),
    sa.Column('is_email_activated', sa.SmallInteger(), nullable=True),
    sa.Column('is_mobile_activated', sa.SmallInteger(), nullable=True),
    sa.Column('last_modify_tag', sa.Unicode(length=36), nullable=True),
    sa.Column('last_modify_date', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_auth_info_email'), 'user_auth_info', ['email'], unique=False)
    op.create_index(op.f('ix_user_auth_info_login_name'), 'user_auth_info', ['login_name'], unique=False)
    op.create_index(op.f('ix_user_auth_info_mobile'), 'user_auth_info', ['mobile'], unique=False)
    op.create_index(op.f('ix_user_auth_info_uuid'), 'user_auth_info', ['uuid'], unique=True)
    op.create_table('user_im_config',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.Unicode(length=36), nullable=True),
    sa.Column('type', sa.Unicode(length=16), nullable=False),
    sa.Column('token', sa.Unicode(length=128), nullable=True),
    sa.Column('chat_room_limit', sa.Integer(), nullable=True),
    sa.Column('chat_group_limit', sa.Integer(), nullable=True),
    sa.Column('last_modify_tag', sa.Unicode(length=36), nullable=True),
    sa.Column('last_modify_date', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_im_config_uuid'), 'user_im_config', ['uuid'], unique=True)
    op.create_table('user_push_config',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.Unicode(length=36), nullable=True),
    sa.Column('type', sa.Unicode(length=16), nullable=False),
    sa.Column('not_allow_ad', sa.SmallInteger(), nullable=True),
    sa.Column('last_modify_tag', sa.Unicode(length=36), nullable=True),
    sa.Column('last_modify_date', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_push_config_uuid'), 'user_push_config', ['uuid'], unique=True)
    op.create_table('user_social_info',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('uuid', sa.Unicode(length=36), nullable=True),
    sa.Column('type', sa.Unicode(length=16), nullable=False),
    sa.Column('nick_name', sa.Unicode(length=64), nullable=False),
    sa.Column('experience', sa.BigInteger(), nullable=True),
    sa.Column('last_modify_tag', sa.Unicode(length=36), nullable=True),
    sa.Column('last_modify_date', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_user_social_info_uuid'), 'user_social_info', ['uuid'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_user_social_info_uuid'), table_name='user_social_info')
    op.drop_table('user_social_info')
    op.drop_index(op.f('ix_user_push_config_uuid'), table_name='user_push_config')
    op.drop_table('user_push_config')
    op.drop_index(op.f('ix_user_im_config_uuid'), table_name='user_im_config')
    op.drop_table('user_im_config')
    op.drop_index(op.f('ix_user_auth_info_uuid'), table_name='user_auth_info')
    op.drop_index(op.f('ix_user_auth_info_mobile'), table_name='user_auth_info')
    op.drop_index(op.f('ix_user_auth_info_login_name'), table_name='user_auth_info')
    op.drop_index(op.f('ix_user_auth_info_email'), table_name='user_auth_info')
    op.drop_table('user_auth_info')
    op.drop_index(op.f('ix_personal_user_uuid'), table_name='personal_user')
    op.drop_table('personal_user')
    op.drop_index(op.f('ix_enterprise_user_uuid'), table_name='enterprise_user')
    op.drop_table('enterprise_user')
    # ### end Alembic commands ###

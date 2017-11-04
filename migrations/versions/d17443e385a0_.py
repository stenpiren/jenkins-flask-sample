"""empty message

Revision ID: d17443e385a0
Revises: 82273add3ca5
Create Date: 2017-11-04 15:27:17.329146

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd17443e385a0'
down_revision = '82273add3ca5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('personal_user', 'migration_test')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('personal_user', sa.Column('migration_test', sa.INTEGER(), autoincrement=False, nullable=True))
    # ### end Alembic commands ###
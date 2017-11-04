#!/usr/bin/env sh

set -e
export FLASK_APP=/app/app.py

until python3 -c "import psycopg2; psycopg2.connect(\"${SQLALCHEMY_DATABASE_URI}?connect_timeout=10\")" ; do
  >&2 echo "Postgres is unavailable - sleeping"
  sleep 3
done

flask db upgrade && uwsgi --http-socket :9090 --uid nobody --master --wsgi-file /app/app.py --callable app

#!/usr/bin/env sh

set -e
export FLASK_APP=/app/app.py
flask db upgrade && uwsgi --http-socket :9090 --uid nobody --master --wsgi-file /app/app.py --callable app

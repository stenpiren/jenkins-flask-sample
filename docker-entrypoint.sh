#!/usr/bin/env bash

set -e

exec "$@" --http :9090 --wsgi-file app.py --callable app

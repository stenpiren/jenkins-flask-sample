FROM python:3.6.3-alpine
RUN apk add --no-cache build-base linux-headers python3-dev pcre-dev postgresql-dev
RUN pip install --no-cache-dir uwsgi
COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt
COPY docker-entrypoint.sh /usr/local/bin/
RUN ln -s usr/local/bin/docker-entrypoint.sh /
ENTRYPOINT ["docker-entrypoint.sh"]

CMD ["uswgi"]
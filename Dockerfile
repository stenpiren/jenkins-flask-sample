FROM python:3.6.3-alpine
RUN apk add --no-cache build-base linux-headers python3-dev pcre-dev postgresql-dev
COPY *.py app/
COPY migrations app/migrations/
COPY requirements.txt app/
COPY docker-entrypoint.sh /usr/local/bin/
WORKDIR app/
RUN pip install --no-cache-dir --index-url=https://mirrors.ustc.edu.cn/pypi/web/simple/ uwsgi
RUN pip install --no-cache-dir --index-url=https://mirrors.ustc.edu.cn/pypi/web/simple/ -r requirements.txt
EXPOSE 3031
ENTRYPOINT ["docker-entrypoint.sh"]
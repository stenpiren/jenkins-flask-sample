FROM python:3.6.3-alpine
RUN apk add --no-cache build-base postgresql-dev
COPY . /app
WORKDIR /app
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python","app.py"]
FROM python:3.6.3-alpine
COPY config.py .
CMD python config.py
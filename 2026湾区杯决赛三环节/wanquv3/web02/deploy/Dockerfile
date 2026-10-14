FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=5000

WORKDIR /app

RUN pip install --no-cache-dir \
        flask==3.0.3 \
        pymysql==1.1.1 \
        cryptography==42.0.8

COPY src/app.py       /app/app.py
COPY src/waf.py       /app/waf.py

EXPOSE 5000

CMD ["python", "app.py"]

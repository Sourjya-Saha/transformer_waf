FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi uvicorn pymysql cryptography python-multipart

COPY . .

EXPOSE 8080

CMD ["python", "-m", "backend.app"]

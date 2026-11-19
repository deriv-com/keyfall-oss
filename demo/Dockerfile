FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY reference/ reference/
COPY demo/ demo/
ENV PYTHONPATH=/app/reference:/app/demo PYTHONUNBUFFERED=1
USER nobody

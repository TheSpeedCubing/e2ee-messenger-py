FROM python:3.12-slim

WORKDIR /app

COPY server/ ./server/

RUN pip install --no-cache-dir cbor2

CMD ["python", "server/server.py"]

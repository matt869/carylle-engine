FROM python:3.11-slim

RUN useradd --system --uid 10001 --home-dir /app carylle

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY server ./server
COPY agent ./agent
RUN pip install --no-cache-dir ".[server]"

COPY config ./config
COPY data ./data
RUN mkdir -p /app/var && chown -R carylle:carylle /app/var

USER carylle
ENV CARYLLE_HOST=0.0.0.0
EXPOSE 8443
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8443), 2).close()"]
CMD ["carylle-server"]

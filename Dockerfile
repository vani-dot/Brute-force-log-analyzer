# Two stages so the runtime image carries no build tooling and no test files.
FROM python:3.12-slim AS build

WORKDIR /install
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install/deps -r requirements.txt


FROM python:3.12-slim

# Run as a non-root user. This tool reads log files; there is no reason for it
# to be able to write to them.
RUN useradd --create-home --shell /usr/sbin/nologin bfla

WORKDIR /app
COPY --from=build /install/deps /usr/local
COPY --chown=bfla:bfla . .

# The database lives on a volume so history survives the container.
RUN mkdir -p /data && chown bfla:bfla /data
ENV BFLA_DB_PATH=/data/bfla.db \
    BFLA_DEBUG=false \
    PORT=5000 \
    PYTHONUNBUFFERED=1

USER bfla
EXPOSE 5000
VOLUME ["/data"]

# Reports unhealthy if the app stops answering, not merely if the process lives.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request,os; \
urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",5000)}/api/config', timeout=2)"

# One worker, several threads: the live watcher keeps state in memory, so a
# second process would follow the same log twice and alert twice.
CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 1 --threads 8 --timeout 120 app:app"]

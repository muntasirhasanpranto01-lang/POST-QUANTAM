FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PQ_ENV=production \
    PQ_DATA_DIR=/var/lib/post-quantam

RUN addgroup --system app && adduser --system --ingroup app app \
    && mkdir -p /var/lib/post-quantam \
    && chown -R app:app /var/lib/post-quantam

WORKDIR /app
COPY pyproject.toml ../README.md ./
COPY pq_backend ./pq_backend
RUN pip install --no-cache-dir .
COPY entrypoint.sh ./entrypoint.sh
RUN chmod 0555 ./entrypoint.sh

USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3)"
ENTRYPOINT ["./entrypoint.sh"]

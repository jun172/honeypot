FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HP_HOST=0.0.0.0 \
    HP_PORT=8080

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin hpuser

WORKDIR /app
COPY --chown=hpuser:hpuser honeypot.py /app/honeypot.py

USER 10001
EXPOSE 8080

CMD ["python", "/app/honeypot.py"]
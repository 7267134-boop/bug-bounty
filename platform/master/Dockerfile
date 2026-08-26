# Master Node - minimal, non-root, no security tools installed.
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY master/requirements.txt /app/master/requirements.txt
RUN pip install --no-cache-dir -r /app/master/requirements.txt

# Non-root runtime user.
RUN groupadd -g 10001 master && useradd -u 10001 -g master -d /nonexistent -s /usr/sbin/nologin master

COPY common/ /app/common/
COPY master/ /app/master/
COPY migrations/ /app/migrations/
COPY workflows/ /app/workflows/

RUN chown -R root:master /app && chmod -R g+rX /app

USER 10001:10001

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status==200 else 1)"

CMD ["python", "-m", "master.main"]

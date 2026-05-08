FROM python:3.12-slim

WORKDIR /app

COPY packages/alias-routing-core /tmp/alias-routing-core
RUN pip install --no-cache-dir /tmp/alias-routing-core

COPY packages/simplelogin-client /tmp/simplelogin-client
RUN pip install --no-cache-dir /tmp/simplelogin-client

COPY apps/smtp-proxy /app
RUN pip install --no-cache-dir .

CMD ["python", "-m", "sl_smtp_proxy.main"]

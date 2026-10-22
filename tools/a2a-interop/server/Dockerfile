# Build context: the repository root.
FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv
COPY libs/crypto/py /tmp/crypto
COPY libs/a2a/py /tmp/a2a
RUN pip install /tmp/crypto /tmp/a2a "a2a-sdk[http-server]==1.2.3" uvicorn==0.54.0 && rm -rf /tmp/crypto /tmp/a2a
COPY tools/a2a-interop/server/app.py .
RUN useradd --system --uid 10001 --no-create-home app
USER 10001

EXPOSE 8080
ENTRYPOINT ["python", "/srv/app.py"]

# Build context: the repository root.
FROM python:3.13-slim-bookworm

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /srv
COPY libs/crypto/py /tmp/crypto
RUN pip install /tmp/crypto mcp==2.3.0 && rm -rf /tmp/crypto
COPY tools/a2a-interop/mcp_server/server.py .
RUN useradd --system --uid 10001 --no-create-home app
USER 10001

EXPOSE 8080
ENTRYPOINT ["python", "/srv/server.py"]

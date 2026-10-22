FROM python:3.13-slim-bookworm

RUN useradd --system --uid 10001 --no-create-home app
WORKDIR /srv
COPY app.py .
USER 10001

EXPOSE 8080
ENTRYPOINT ["python", "-u", "/srv/app.py"]

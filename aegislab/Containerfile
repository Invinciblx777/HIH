# AegisLab sandbox image: one image for red sandbox, defence runner and model worker.
# Standard library only. Pin the base by digest in production builds.
FROM docker.io/library/python:3.12-slim
COPY sandbox/ /app/
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

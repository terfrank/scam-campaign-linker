FROM python:3.12-slim

# No .pyc files, unbuffered logs (so `docker logs` shows output immediately), smaller image
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md alembic.ini ./
COPY src ./src
COPY migrations ./migrations
RUN pip install .

# Never run the app as root inside the container
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000
# Bring the schema up to date, then start the API. `exec` makes uvicorn PID 1, so it receives
# Docker's stop signal directly and shuts down cleanly.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn --factory scam_linker.main:create_app --host 0.0.0.0 --port 8000"]

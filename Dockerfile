FROM python:3.12-slim

# No .pyc files, unbuffered logs (so `docker logs` shows output immediately), smaller image
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install .

# Never run the app as root inside the container
RUN useradd --create-home appuser
USER appuser

EXPOSE 8000
CMD ["uvicorn", "scam_linker.main:app", "--host", "0.0.0.0", "--port", "8000"]

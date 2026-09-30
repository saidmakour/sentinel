FROM python:3.13-slim

# Empêche Python de créer des .pyc et force les logs immédiats
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Copier uniquement les fichiers nécessaires à l'installation
COPY pyproject.toml README.md ./

# Copier le package
COPY sentinel ./sentinel

COPY alembic.ini ./
COPY migrations ./migrations

# Installer Sentinel depuis le pyproject.toml
RUN pip install --upgrade pip \
    && pip install .

# Port utilisé par FastAPI / Uvicorn
EXPOSE 8000

# Démarrage de l'API
# CMD ["uvicorn", "sentinel.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
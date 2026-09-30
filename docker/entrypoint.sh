#!/bin/sh
set -e

echo "Running database migrations..."
alembic upgrade head

echo "Starting Sentinel..."
exec uvicorn sentinel.api.app:app \
    --host 0.0.0.0 \
    --port 8000
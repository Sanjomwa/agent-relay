FROM python:3.11-slim

RUN pip install --no-cache-dir uv

WORKDIR /app

# Install dependencies first so this layer is cached unless pyproject/uv.lock change.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

# Application code.
COPY main.py database.py errors.py schemas.py storage.py worker.py dashboard.py dashboard.html \
     buildinfo.py logging_config.py telemetry.py ./

RUN uv sync --frozen --no-dev

ENV PATH="/app/.venv/bin:${PATH}"

# Build identity (scripts/release.sh). Declared after the dependency layers so a
# new version never invalidates the dependency cache.
ARG APP_VERSION=dev
ARG GIT_SHA=unknown
ENV APP_VERSION=${APP_VERSION} \
    GIT_SHA=${GIT_SHA}
LABEL org.opencontainers.image.version=${APP_VERSION} \
      org.opencontainers.image.revision=${GIT_SHA}

EXPOSE 8000

# --host 0.0.0.0 is required: uvicorn's default of 127.0.0.1 only accepts
# connections from inside the container, which makes a published port look
# broken even though the container itself is fine. --no-access-log because the
# app writes one structured JSON line per request itself.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]

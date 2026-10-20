# SPDX-FileCopyrightText: 2026 UltimateOTP contributors
# SPDX-License-Identifier: GPL-3.0-or-later
#
# One image, two roles: `api` (default) and the one-shot `migrate`; the admin CLI runs in the api
# container (`docker compose exec api ultimateotp ...`).
# Build from the repository root: docker build -f server/Dockerfile .
# Runs as non-root with a read-only root filesystem (compose.yaml), like UltimateTunes.

FROM ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 AS uv

FROM python:3.15-slim@sha256:2da676046630d7bf14c6764ae1143dc7fa0377a53f94bf5a642f0b214aca5bce AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src/server
COPY server/pyproject.toml server/uv.lock ./
RUN uv sync --locked --no-dev --no-install-project
COPY server/src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.15-slim@sha256:2da676046630d7bf14c6764ae1143dc7fa0377a53f94bf5a642f0b214aca5bce
# pip is not needed at runtime (the venv is complete).
RUN rm -rf /usr/local/lib/python3.13/site-packages/pip /usr/local/lib/python3.13/site-packages/pip-* \
        /usr/local/lib/python3.13/ensurepip/_bundled /usr/local/bin/pip /usr/local/bin/pip3* \
    && groupadd --gid 10001 otp \
    && useradd --uid 10001 --gid otp --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin otp \
    && mkdir -p /data \
    && chown otp:otp /data
COPY --from=build /app/.venv /app/.venv
COPY contracts/db/migrations /app/migrations
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UOTP_HOST=0.0.0.0 \
    UOTP_PORT=8047 \
    UOTP_DATA_DIR=/data \
    UOTP_MIGRATIONS_DIR=/app/migrations
USER 10001:10001
EXPOSE 8047
ENTRYPOINT ["ultimateotp"]
CMD ["api"]

FROM python:3.13-slim

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY schema/ schema/
COPY data/entries/ data/entries/
COPY data/functions.json data/functions.json
COPY src/ src/

# Default: PostgreSQL backend, streamable-http transport
ENV CME_DB_BACKEND=postgres \
    CME_TRANSPORT=streamable-http \
    CME_HTTP_HOST=0.0.0.0 \
    CME_HTTP_PORT=8000 \
    CME_PG_HOST=postgres \
    CME_PG_PORT=5432 \
    CME_PG_USER=cme \
    CME_PG_PASSWORD=cme \
    CME_PG_DATABASE=cme

EXPOSE 8000

CMD ["uv", "run", "python", "-m", "src.server"]

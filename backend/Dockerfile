# AntiScam AI backend — container image for Cloud Run / Render.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first so the layer caches across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts

# Pre-download the ChromaDB local embedding model at build time, so the first
# advisory retrieval in production doesn't pay a ~80MB download on the hot path.
RUN python -c "from app.rag.vector_store import get_collection; get_collection()" || true

# Cloud Run and Render inject $PORT. Default to 8080 for local `docker run`.
ENV PORT=8080
EXPOSE 8080

# Shell form so ${PORT} expands. One worker: the fraud graph is in-process state,
# and multiple workers would each hold a divergent copy (documented limitation).
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT} --workers 1

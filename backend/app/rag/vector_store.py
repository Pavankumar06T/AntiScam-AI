"""ChromaDB vector store for advisory retrieval.

Embeddings run **locally** (Chroma's bundled ONNX MiniLM). That is a deliberate
choice, not an accident: it costs zero Groq tokens, works with no API key, and
keeps retrieval available even when the LLM layer is rate-limited — which, given
the free tier's 100k tokens/day, is a live concern rather than a hypothetical.
"""

from __future__ import annotations

import logging
import threading

from app.config import BACKEND_ROOT
from app.rag.knowledge_base import ADVISORIES, Advisory, get_advisory

logger = logging.getLogger(__name__)

CHROMA_PATH = BACKEND_ROOT / "chroma_db"
COLLECTION_NAME = "scam_advisories"

_lock = threading.Lock()
_collection = None


def _build_collection():
    import chromadb

    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )

    if collection.count() == len(ADVISORIES):
        logger.info("Advisory store ready (%d documents, cached).", collection.count())
        return collection

    # Rebuild from scratch when the knowledge base has changed, so an edit to
    # knowledge_base.py can never leave a stale index behind.
    if collection.count() > 0:
        logger.info("Advisory knowledge base changed — rebuilding index.")
        client.delete_collection(COLLECTION_NAME)
        collection = client.get_or_create_collection(
            name=COLLECTION_NAME, metadata={"hnsw:space": "cosine"}
        )

    collection.add(
        ids=[a.id for a in ADVISORIES],
        documents=[f"{a.title}\n\n{a.text}" for a in ADVISORIES],
        metadatas=[
            {
                "title": a.title,
                "source": a.source,
                "scam_types": ",".join(a.scam_types),
                "red_flag_categories": ",".join(a.red_flag_categories),
            }
            for a in ADVISORIES
        ],
    )
    logger.info("Advisory store built (%d documents).", collection.count())
    return collection


def get_collection():
    global _collection
    with _lock:
        if _collection is None:
            _collection = _build_collection()
        return _collection


def retrieve(
    query: str,
    *,
    scam_type: str | None = None,
    n_results: int = 3,
) -> list[Advisory]:
    """Retrieve advisories relevant to a query.

    Retrieval is semantic, but we bias toward advisories tagged for this scam type:
    a digital-arrest victim needs the 'digital arrest is not real' advisory even if
    the transcript's wording happens to sit closer to a generic one in embedding
    space. Tags encode editorial intent that cosine distance does not.
    """
    collection = get_collection()

    result = collection.query(
        query_texts=[query],
        n_results=min(n_results + 3, len(ADVISORIES)),
    )
    ids: list[str] = (result.get("ids") or [[]])[0]

    retrieved = [a for a in (get_advisory(i) for i in ids) if a is not None]

    if scam_type:
        def rank(a: Advisory) -> int:
            return 0 if scam_type in a.scam_types else 1

        retrieved.sort(key=rank)

    return retrieved[:n_results]


def reset_store() -> None:
    """Drop the cached handle. Used by tests."""
    global _collection
    with _lock:
        _collection = None

"""Text -> vector. One interface, two implementations.

hash (default)
    Feature-hashing embedder: lower-cased, lightly stemmed words are hashed into
    a 384-dimensional vector with sub-linear term weights, then L2-normalized.
    Needs no model download, is fully deterministic and runs offline, so the demo
    and the tests always work. It captures LEXICAL overlap, not meaning: a query
    must share vocabulary with a document to match it.

sentence-transformers (optional)
    Real semantic embeddings from all-MiniLM-L6-v2 (also 384 dimensions).
    Enable with `pip install sentence-transformers` and
    EMBEDDING_PROVIDER=sentence-transformers, then re-run `python -m rag.ingestion`.
"""
from __future__ import annotations

import hashlib
import math
import re
from abc import ABC, abstractmethod
from collections import Counter
from functools import lru_cache

from backend.config import get_settings
from database.models import EMBEDDING_DIM

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    "a an and are as at be been by can for from has have in into is it its may must not of on or "
    "such that the their then there these this to was when which who will with without".split()
)


class EmbeddingError(RuntimeError):
    pass


class Embedder(ABC):
    #: stored with every chunk so a provider switch without re-ingestion is detected
    name: str
    #: cosine similarity below which a chunk is considered unrelated to the query
    min_similarity: float

    @abstractmethod
    def embed(self, texts: list[str]) -> list[list[float]]:
        ...

    def embed_one(self, text: str) -> list[float]:
        return self.embed([text])[0]


def _stem(token: str) -> str:
    """Very light suffix stripping so 'commands'/'command' and 'executes'/'executed' match."""
    for suffix in ("ing", "ed", "es", "s"):
        if token.endswith(suffix) and len(token) - len(suffix) >= 3:
            return token[: -len(suffix)]
    return token


class HashingEmbedder(Embedder):
    name = f"hashing-v2-{EMBEDDING_DIM}"
    # Chosen by probing this knowledge base: real findings score >= 0.40 against
    # their own topic, unrelated queries stay below 0.25. Re-check if the
    # knowledge base grows.
    min_similarity = 0.25

    @staticmethod
    def _features(text: str) -> list[str]:
        return [_stem(t) for t in _TOKEN_RE.findall(text.lower()) if t not in _STOPWORDS and len(t) > 1]

    @staticmethod
    def _bucket(feature: str) -> tuple[int, float]:
        # blake2b (not Python's hash()) so vectors are identical across processes.
        digest = int.from_bytes(hashlib.blake2b(feature.encode(), digest_size=8).digest(), "big")
        return digest % EMBEDDING_DIM, 1.0 if (digest >> 63) & 1 else -1.0

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = []
        for text in texts:
            vector = [0.0] * EMBEDDING_DIM
            for feature, count in Counter(self._features(text)).items():
                index, sign = self._bucket(feature)
                vector[index] += sign * (1.0 + math.log(count))
            norm = math.sqrt(sum(v * v for v in vector))
            vectors.append([v / norm for v in vector] if norm else vector)
        return vectors


class SentenceTransformerEmbedder(Embedder):
    min_similarity = 0.25

    def __init__(self, model_name: str):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise EmbeddingError(
                "EMBEDDING_PROVIDER=sentence-transformers but the package is not installed. "
                "Run: pip install sentence-transformers  (or set EMBEDDING_PROVIDER=hash)"
            ) from exc
        self.name = f"sentence-transformers/{model_name}"
        self._model = SentenceTransformer(model_name)
        dim = self._model.get_sentence_embedding_dimension()
        if dim != EMBEDDING_DIM:
            raise EmbeddingError(
                f"Model '{model_name}' produces {dim}-dimensional vectors but the "
                f"knowledge_chunks table stores {EMBEDDING_DIM}. Use a 384-dimensional model."
            )

    def embed(self, texts: list[str]) -> list[list[float]]:
        return self._model.encode(texts, normalize_embeddings=True).tolist()


@lru_cache(maxsize=2)
def _build(provider: str, model: str) -> Embedder:
    if provider == "hash":
        return HashingEmbedder()
    if provider in ("sentence-transformers", "sentence_transformers"):
        return SentenceTransformerEmbedder(model)
    raise EmbeddingError(f"Unknown EMBEDDING_PROVIDER '{provider}'. Use 'hash' or 'sentence-transformers'.")


def get_embedder() -> Embedder:
    settings = get_settings()
    return _build(settings.embedding_provider, settings.embedding_model)

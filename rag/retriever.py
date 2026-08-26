"""
FAISS-backed retrieval over the security knowledge base.

Uses cosine similarity (L2-normalized vectors + inner product index).
"""

import os
from pathlib import Path

import faiss
from sentence_transformers import SentenceTransformer

EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# MiniLM truncates past ~256 word pieces. Chunks longer than this are
# silently cut off, so we warn instead of losing content invisibly.
MAX_CHUNK_WORDS = 180

# Cosine similarity floor. Below this, a "match" is just noise and
# feeding it to the LLM actively causes hallucination.
DEFAULT_MIN_SCORE = 0.25

# Default knowledge_base/ sits next to this package, not in the CWD.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_KB_DIR = _PROJECT_ROOT / "knowledge_base"


class SecurityRAG:
    _model = None

    def __init__(self, knowledge_dir=None):
        self.knowledge_dir = Path(knowledge_dir or DEFAULT_KB_DIR)

        # Load the embedding model only once per process.
        if SecurityRAG._model is None:
            print(f"[RAG] Loading embedding model ({EMBEDDING_MODEL})...")
            SecurityRAG._model = SentenceTransformer(EMBEDDING_MODEL)
            print("[RAG] Embedding model loaded.")

        self.model = SecurityRAG._model

        self.documents = []
        self.index = None

        self._load_documents()
        self._build_index()

    def _load_documents(self):
        """Load security knowledge files and split them into chunks."""

        if not self.knowledge_dir.is_dir():
            raise FileNotFoundError(
                f"Knowledge base directory not found: {self.knowledge_dir}\n"
                f"Check that the folder exists and was copied into the image."
            )

        # sorted() so document order is identical on every machine.
        # os.listdir() order is filesystem-dependent, which makes
        # index positions non-reproducible and debugging miserable.
        for filename in sorted(os.listdir(self.knowledge_dir)):

            if not filename.endswith(".txt"):
                continue

            path = self.knowledge_dir / filename

            with open(path, "r", encoding="utf-8") as file:
                text = file.read()

            # Simple paragraph-based chunking
            chunks = [
                chunk.strip()
                for chunk in text.split("\n\n")
                if chunk.strip()
            ]

            for chunk in chunks:
                self.documents.append({
                    "source": filename,
                    "text": chunk,
                })

        print(f"[RAG] Loaded {len(self.documents)} knowledge chunks.")

        oversized = [
            doc for doc in self.documents
            if len(doc["text"].split()) > MAX_CHUNK_WORDS
        ]
        if oversized:
            print(
                f"[RAG] WARNING: {len(oversized)} chunk(s) exceed "
                f"~{MAX_CHUNK_WORDS} words and will be truncated by the "
                f"embedding model. Consider splitting them."
            )
            for doc in oversized[:5]:
                preview = doc["text"][:70].replace("\n", " ")
                print(f"[RAG]   - {doc['source']}: {preview}...")

    def _build_index(self):
        """Create embeddings and FAISS vector index."""

        # Without this the failure mode is an opaque IndexError on
        # embeddings.shape[1], which tells you nothing about the cause.
        if not self.documents:
            raise ValueError(
                f"No knowledge chunks found in '{self.knowledge_dir}'.\n"
                f"The directory exists but contains no readable .txt files."
            )

        texts = [document["text"] for document in self.documents]

        embeddings = self.model.encode(
            texts,
            convert_to_numpy=True,
            show_progress_bar=False,
        ).astype("float32")

        # Normalize vectors so inner product == cosine similarity
        faiss.normalize_L2(embeddings)

        dimension = embeddings.shape[1]

        self.index = faiss.IndexFlatIP(dimension)
        self.index.add(embeddings)

        print(f"[RAG] FAISS index created with {self.index.ntotal} vectors.")

    def search(self, query, top_k=3, min_score=DEFAULT_MIN_SCORE):
        """Retrieve the most relevant security knowledge.

        Returns [] when nothing clears min_score. Callers must handle
        the empty case rather than passing empty context to an LLM.
        """

        query_embedding = self.model.encode(
            [query],
            convert_to_numpy=True,
            show_progress_bar=False,
        ).astype("float32")

        faiss.normalize_L2(query_embedding)

        scores, indices = self.index.search(
            query_embedding,
            min(top_k, len(self.documents)),
        )

        results = []

        for score, index in zip(scores[0], indices[0]):

            # FAISS returns -1 for padding when fewer hits than top_k
            if index == -1:
                continue

            if score < min_score:
                continue

            document = self.documents[index]

            results.append({
                "score": float(score),
                "source": document["source"],
                "text": document["text"],
            })

        return results


if __name__ == "__main__":

    rag = SecurityRAG()

    for query in [
        "How do I prevent SQL injection?",
        "what is the capital of France",  # should return nothing
    ]:
        print(f"\n{'=' * 60}\nQuery: {query}\n{'=' * 60}")

        results = rag.search(query)

        if not results:
            print("No relevant knowledge found (all below threshold).")
            continue

        for result in results:
            print(f"\n[{result['score']:.3f}] {result['source']}")
            print(result["text"])
            print("-" * 60)
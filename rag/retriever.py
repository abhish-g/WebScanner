import os
import faiss
import numpy as np
from sentence_transformers import SentenceTransformer


class SecurityRAG:
    def __init__(self, knowledge_dir="knowledge_base"):
        self.knowledge_dir = knowledge_dir

        # Local embedding model
        self.model = SentenceTransformer(
            "all-MiniLM-L6-v2"
        )

        self.documents = []
        self.index = None

        self._load_documents()
        self._build_index()

    def _load_documents(self):
        """Load security knowledge files and split them into chunks."""

        for filename in os.listdir(self.knowledge_dir):

            if not filename.endswith(".txt"):
                continue

            path = os.path.join(
                self.knowledge_dir,
                filename
            )

            with open(
                path,
                "r",
                encoding="utf-8"
            ) as file:

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
                    "text": chunk
                })

        print(
            f"Loaded {len(self.documents)} knowledge chunks."
        )

    def _build_index(self):
        """Create embeddings and FAISS vector index."""

        texts = [
            document["text"]
            for document in self.documents
        ]

        embeddings = self.model.encode(
            texts,
            convert_to_numpy=True
        )

        embeddings = embeddings.astype(
            "float32"
        )

        # Normalize vectors for cosine similarity
        faiss.normalize_L2(embeddings)

        dimension = embeddings.shape[1]

        self.index = faiss.IndexFlatIP(
            dimension
        )

        self.index.add(embeddings)

        print(
            f"FAISS index created with {self.index.ntotal} vectors."
        )

    def search(self, query, top_k=3):
        """Retrieve the most relevant security knowledge."""

        query_embedding = self.model.encode(
            [query],
            convert_to_numpy=True
        )

        query_embedding = query_embedding.astype(
            "float32"
        )

        faiss.normalize_L2(query_embedding)

        scores, indices = self.index.search(
            query_embedding,
            min(top_k, len(self.documents))
        )

        results = []

        for score, index in zip(
            scores[0],
            indices[0]
        ):

            document = self.documents[index]

            results.append({
                "score": float(score),
                "source": document["source"],
                "text": document["text"]
            })

        return results


if __name__ == "__main__":

    rag = SecurityRAG()

    query = "How do I prevent SQL injection?"

    results = rag.search(query)

    print("\nRetrieved Knowledge:\n")

    for result in results:

        print(
            f"[{result['score']:.3f}] "
            f"{result['source']}"
        )

        print(result["text"])
        print("-" * 60)
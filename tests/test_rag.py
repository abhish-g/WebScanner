from rag.retriever import SecurityRAG


def test_rag_initialization():
    rag = SecurityRAG()

    assert rag.index is not None
    assert len(rag.documents) > 0
    assert rag.index.ntotal == len(rag.documents)


def test_sql_injection_retrieval():
    rag = SecurityRAG()

    results = rag.search(
        "SQL injection attack prevention",
        top_k=3
    )

    assert len(results) > 0
    assert any(
        "sql" in result["text"].lower()
        or "sql" in result["source"].lower()
        for result in results
    )


def test_xss_retrieval():
    rag = SecurityRAG()

    results = rag.search(
        "Cross Site Scripting XSS prevention",
        top_k=3
    )

    assert len(results) > 0
    assert any(
        "xss" in result["text"].lower()
        or "xss" in result["source"].lower()
        for result in results
    )


def test_prompt_injection_retrieval():
    rag = SecurityRAG()

    results = rag.search(
        "prompt injection ignore previous instructions",
        top_k=3
    )

    assert len(results) > 0
    assert any(
        "prompt" in result["text"].lower()
        or "prompt" in result["source"].lower()
        for result in results
    )


def test_rag_scores():
    rag = SecurityRAG()

    results = rag.search(
        "security attack",
        top_k=3
    )

    assert len(results) <= 3

    for result in results:
        assert "score" in result
        assert "source" in result
        assert "text" in result
        assert isinstance(result["score"], float)
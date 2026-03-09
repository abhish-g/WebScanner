# ml_to_rag_demo.py

from ml_detector.real_ml import detect_attack
from src.rag_scanner import RAGSecurityScanner

# Step 1: Fake web request
web_request = "admin' OR 1=1"

# Step 2: ML detects attack
ml_result = detect_attack(web_request)

print("ML Output:", ml_result)

# Step 3: If attack found, send to RAG
if ml_result["attack"] != "normal":
    scanner = RAGSecurityScanner(delay_between_requests=0.1)

    # Convert ML output into RAG-style payload
    payload = f"""
    Detected Web Attack:
    Type: {ml_result['attack']}
    Payload: {ml_result['payload']}
    Explain this attack and how to prevent it.
    """

    success, response, _ = scanner._make_request(payload)

    print("\nRAG Explanation:")
    print(response)
else:
    print("No attack detected")

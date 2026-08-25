import os
import time
import requests

from dotenv import load_dotenv
from ml_detector.real_ml import detect_attack
from rag.retriever import SecurityRAG


load_dotenv()


# ============================================================
# 1. WEB REQUEST
# ============================================================

web_request = "admin' OR 1=1"


# ============================================================
# 2. ML DETECTION
# ============================================================

ml_result = detect_attack(web_request)

print("\n========== ML DETECTION ==========")
print("Attack:", ml_result["attack"])
print("Confidence:", ml_result["confidence"])
print("Payload:", ml_result["payload"])


# ============================================================
# 3. RAG RETRIEVAL
# ============================================================

if ml_result["attack"] == "normal":
    print("\nNo attack detected.")
    raise SystemExit


rag = SecurityRAG()

query = f"""
Security attack type: {ml_result['attack']}
Payload: {ml_result['payload']}

Find relevant information about this security attack,
its risks, and prevention.
"""

retrieved = rag.search(query, top_k=3)

print("\n========== RETRIEVED KNOWLEDGE ==========")

context_parts = []

for result in retrieved:

    print(
        f"\n[{result['score']:.3f}] "
        f"{result['source']}"
    )

    print(result["text"])

    context_parts.append(result["text"])


context = "\n\n".join(context_parts)


# ============================================================
# 4. GROUNDED PROMPT
# ============================================================

prompt = f"""
You are a cybersecurity assistant.

A machine-learning detector identified:

Attack Type: {ml_result['attack']}
Confidence: {ml_result['confidence']}
Payload: {ml_result['payload']}

Use the retrieved security knowledge below.

--- KNOWLEDGE ---
{context}
--- END KNOWLEDGE ---

Give a concise security analysis with:

1. What the attack is
2. What the payload attempts to do
3. Potential security impact
4. Recommended prevention

Base the answer primarily on the retrieved knowledge.
"""


# ============================================================
# 5. OPENROUTER LLM
# ============================================================

api_key = os.getenv("OPENROUTER_API_KEY")
model = os.getenv("OPENROUTER_MODEL", "openrouter/free")
endpoint = os.getenv(
    "TARGET_URL",
    "https://openrouter.ai/api/v1/chat/completions"
)

if not api_key:
    print("\nERROR: OPENROUTER_API_KEY is missing.")
    raise SystemExit(1)


print("\n========== RAG + LLM EXPLANATION ==========")

start_time = time.time()

try:

    response = requests.post(
        endpoint,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        },
        json={
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": 0.1,
            "max_tokens": 300
        },
        timeout=60
    )

    response_time = time.time() - start_time

    if response.status_code == 200:

        data = response.json()

        answer = data["choices"][0]["message"]["content"]

        print(answer)

        print(
            f"\nResponse time: "
            f"{response_time:.2f}s"
        )

    else:

        print(
            f"LLM request failed "
            f"(HTTP {response.status_code})"
        )

        print(response.text)


except requests.RequestException as e:

    print("LLM request failed:")
    print(str(e))
import sys
import os

from dotenv import load_dotenv


# ============================================================
# PROJECT PATH / ENVIRONMENT
# ============================================================

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

# Load .env from project root
load_dotenv(
    os.path.join(
        PROJECT_ROOT,
        ".env"
    ),
    override=True
)

# Add project root to Python path
sys.path.insert(0, PROJECT_ROOT)


# ============================================================
# IMPORTS
# ============================================================

from flask import (
    Flask,
    jsonify,
    request,
    render_template
)

from ml_detector.real_ml import detect_attack
from rag.retriever import SecurityRAG


# ============================================================
# FLASK APP
# ============================================================

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)


# ============================================================
# HOME
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")


# ============================================================
# RAG + LLM EXPLANATION
# ============================================================

def generate_rag_explanation(ml_result):

    # --------------------------------------------------------
    # Initialize RAG
    # --------------------------------------------------------

    rag = SecurityRAG()

    # --------------------------------------------------------
    # Build semantic query
    # --------------------------------------------------------

    query = f"""
    Security attack type: {ml_result['attack']}

    Payload:
    {ml_result['payload']}

    Find relevant security information about:
    - what this attack is
    - what the payload attempts to do
    - security risks and impact
    - prevention and mitigation
    """

    # --------------------------------------------------------
    # Retrieve relevant knowledge
    # --------------------------------------------------------

    retrieved = rag.search(
        query,
        top_k=3
    )

    # --------------------------------------------------------
    # Build RAG context
    # --------------------------------------------------------

    context_parts = []

    for result in retrieved:

        context_parts.append(
            result["text"]
        )

    context = "\n\n".join(
        context_parts
    )

    # --------------------------------------------------------
    # API KEY
    # --------------------------------------------------------

    api_key = (
        os.getenv("OPENROUTER_API_KEY")
        or os.getenv("OPENAI_API_KEY")
    )

    # --------------------------------------------------------
    # MODEL
    # --------------------------------------------------------

    model = os.getenv(
        "OPENROUTER_MODEL",
        "openai/gpt-5.4"
    )

    # --------------------------------------------------------
    # API KEY CHECK
    # --------------------------------------------------------

    if not api_key:

        return (
            "LLM explanation unavailable. "
            "OPENROUTER_API_KEY is not configured."
        )

    # --------------------------------------------------------
    # LLM PROMPT
    # --------------------------------------------------------

    prompt = f"""
You are a cybersecurity assistant.

A machine-learning security detector identified:

Attack Type:
{ml_result['attack']}

Confidence:
{ml_result['confidence']:.2%}

Payload:
{ml_result['payload']}

Use the retrieved security knowledge below to explain
the detected attack.

--- RETRIEVED SECURITY KNOWLEDGE ---

{context}

--- END RETRIEVED KNOWLEDGE ---

Provide a concise security analysis using exactly these
four sections:

1. What the attack is
2. What the payload attempts to do
3. Potential security impact
4. Recommended prevention

Important instructions:

- Base the explanation primarily on the retrieved knowledge.
- Keep the explanation concise.
- Do not expose hidden reasoning.
- Do not invent facts unrelated to the retrieved knowledge.
- Use simple cybersecurity terminology.
"""

    # --------------------------------------------------------
    # OPENROUTER REQUEST
    # --------------------------------------------------------

    try:

        import requests

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",

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

                "temperature": 0.2,

                "max_tokens": 450
            },

            timeout=60
        )

        # ----------------------------------------------------
        # HTTP ERROR
        # ----------------------------------------------------

        if response.status_code != 200:

            print(
                "OpenRouter error:",
                response.status_code,
                response.text[:500]
            )

            return (
                f"LLM request failed: "
                f"{response.status_code}"
            )

        # ----------------------------------------------------
        # PARSE RESPONSE
        # ----------------------------------------------------

        data = response.json()

        explanation = (
            data["choices"][0]
            ["message"]
            ["content"]
        )

        return explanation.strip()

    except Exception as e:

        print(
            "LLM error:",
            repr(e)
        )

        return "LLM explanation failed."


# ============================================================
# SCAN API
# ============================================================

@app.route("/scan", methods=["POST"])
def scan():

    # --------------------------------------------------------
    # Check JSON
    # --------------------------------------------------------

    if not request.is_json:

        return jsonify({
            "error": "JSON body required"
        }), 400

    # --------------------------------------------------------
    # Get request data
    # --------------------------------------------------------

    data = request.get_json()

    user_input = data.get(
        "payload",
        ""
    ).strip()

    # --------------------------------------------------------
    # Validate input
    # --------------------------------------------------------

    if not user_input:

        return jsonify({
            "error": "Input missing"
        }), 400

    # ========================================================
    # ML DETECTION
    # ========================================================

    ml_result = detect_attack(
        user_input
    )

    attack = ml_result["attack"]

    confidence = float(
        ml_result["confidence"]
    )

    # ========================================================
    # SAFE REQUEST
    # ========================================================

    if attack == "normal":

        return jsonify({

            "attack": "normal",

            "confidence": confidence,

            "payload": user_input,

            "severity": "SAFE",

            "explanation": (
                "No known malicious attack "
                "pattern was detected."
            )
        })

    # ========================================================
    # SEVERITY
    # ========================================================

    severity_map = {

        "sql_injection": "CRITICAL",

        "xss": "HIGH",

        "prompt_injection": "HIGH"
    }

    severity = severity_map.get(
        attack,
        "MEDIUM"
    )

    # ========================================================
    # PREPARE ML RESULT FOR RAG
    # ========================================================

    ml_result["payload"] = user_input

    # ========================================================
    # RAG + LLM
    # ========================================================

    explanation = generate_rag_explanation(
        ml_result
    )

    # ========================================================
    # FINAL API RESPONSE
    # ========================================================

    return jsonify({

        "attack": attack,

        "confidence": confidence,

        "payload": user_input,

        "severity": severity,

        "explanation": explanation
    })


# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=8000,
        debug=True
    )
import sys
import os
from dotenv import load_dotenv

load_dotenv()
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from flask import Flask, jsonify, request, render_template
from ml_detector.real_ml import detect_attack
import requests
app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)
@app.route("/", methods=["GET"])
def home():
    return render_template("index.html")

def payloads_from_url(url: str):
    url = url.lower()
    payloads = []

    if "login" in url or "signin" in url:
        payloads += [
            "admin' OR 1=1--",
            "admin' OR '1'='1"
        ]

    if "search" in url or "query" in url:
        payloads += [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>'
        ]

    return payloads

# --------------------------------------------------
# Scan API (NO frontend change needed)
# --------------------------------------------------
@app.route("/scan", methods=["POST"])
def scan():
    if not request.is_json:
        return jsonify({"error": "JSON body required"}), 400

    data = request.get_json()
    user_input = data.get("payload", "").strip()

    if not user_input:
        return jsonify({"error": "Input missing"}), 400

    # =================================================
    # CASE 1: USER ENTERED URL
    # =================================================
    if user_input.startswith("http://") or user_input.startswith("https://"):
        payloads = payloads_from_url(user_input)
        issues = []

        for p in payloads:
            ml = detect_attack(p)
            if ml["attack"] != "normal":
                issues.append({
                    "attack": ml["attack"],
                    "confidence": float(ml["confidence"]),
                    "payload": p
                })

        # ✅ No issues found
        if not issues:
            return jsonify({
                "attack": "normal",
                "confidence": 0.1,
                "payload": user_input,
                "explanation": "No vulnerabilities detected. Website looks safe."
            })

        # 🔥 Pick most dangerous issue (UI compatible)
        top_issue = max(issues, key=lambda x: x["confidence"])

        explanation = sambanova_explain(user_input, issues)

        return jsonify({
            "attack": top_issue["attack"],
            "confidence": top_issue["confidence"],
            "payload": user_input,
            "explanation": explanation
        })

    # =================================================
    # CASE 2: USER ENTERED DIRECT PAYLOAD
    # =================================================
    ml = detect_attack(user_input)

    explanation = "No malicious behaviour detected."
    if ml["attack"] != "normal":
        explanation = sambanova_explain(user_input, [ml])

    return jsonify({
        "attack": ml["attack"],
        "confidence": float(ml["confidence"]),
        "payload": user_input,
        "explanation": explanation
    })

# --------------------------------------------------
# SambaNova LLM (clean bullet explanation)
# --------------------------------------------------
def sambanova_explain(target, issues):
    api_key = os.getenv("SAMBANOVA_API_KEY")
    if not api_key:
        return "⚠️ SambaNova API key not configured."

    attacks = ", ".join(i["attack"] for i in issues)

    prompt = f"""
You are a cybersecurity expert.

Target:
{target}

Detected attacks:
{attacks}

Explain in bullet points:
• What happened
• Risk level
• How to fix
"""

    data = {
        "model": "Meta-Llama-3.1-8B-Instruct",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 350
    }

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    try:
        r = requests.post(
            "https://api.sambanova.ai/v1/chat/completions",
            json=data,
            headers=headers,
            timeout=30
        )
        if r.status_code == 200:
            return r.json()["choices"][0]["message"]["content"]
        return f"LLM error: {r.status_code}"
    except Exception as e:
        print("LLM exception:", e)
        return "LLM explanation failed."

# --------------------------------------------------
# Run server
# --------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000, debug=True)


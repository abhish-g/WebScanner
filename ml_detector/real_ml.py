import joblib

model = joblib.load("ml_detector/model.pkl")
vectorizer = joblib.load("ml_detector/vectorizer.pkl")

def detect_attack(text: str):
    text_lower = text.lower()

    # SQL Injection
    if "or 1=1" in text_lower or "union select" in text_lower:
        return {
            "attack": "sql_injection",
            "confidence": 0.9,
            "payload": text
        }

    # XSS
    if "<script>" in text_lower or "javascript:" in text_lower:
        return {
            "attack": "xss",
            "confidence": 0.85,
            "payload": text
        }

    return {
        "attack": "normal",
        "confidence": 0.1,
        "payload": text
    }

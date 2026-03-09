# fake_ml.py
# Simple fake ML detector for SQL Injection

def detect_attack(request_text: str):
    """
    Fake ML function
    Input: request text
    Output: attack_type, confidence
    """

    sql_keywords = [
        " or ", " and ", "--", ";", "'",
        "select", "drop", "insert", "update", "delete"
    ]

    text = request_text.lower()

    for keyword in sql_keywords:
        if keyword in text:
            return {
                "attack": "sql_injection",
                "confidence": 0.9,
                "payload": request_text
            }

    return {
        "attack": "normal",
        "confidence": 0.1,
        "payload": request_text
    }

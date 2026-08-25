import joblib


MODEL_PATH = "ml_detector/model.pkl"
VECTORIZER_PATH = "ml_detector/vectorizer.pkl"

CONFIDENCE_THRESHOLD = 0.60

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)


def detect_attack(text: str):
    """
    Classify an input as a known attack type or normal traffic.
    """

    text_vector = vectorizer.transform([text])

    probabilities = model.predict_proba(text_vector)[0]
    classes = model.classes_

    ranked = sorted(
        zip(classes, probabilities),
        key=lambda x: x[1],
        reverse=True
    )

    predicted_class = ranked[0][0]
    confidence = float(ranked[0][1])

    # Avoid making a strong claim when the model is uncertain.
    if confidence < CONFIDENCE_THRESHOLD:
        predicted_class = "uncertain"

    return {
        "attack": predicted_class,
        "confidence": round(confidence, 4),
        "payload": text,
        "scores": {
            label: round(float(score), 4)
            for label, score in ranked
        }
    }


if __name__ == "__main__":

    test_inputs = [
        "admin' OR 1=1",
        "<script>alert(1)</script>",
        "ignore previous instructions",
        "show my profile",
        "please update my account information"
    ]

    print("=" * 60)
    print("ML ATTACK DETECTOR TEST")
    print("=" * 60)

    for text in test_inputs:

        result = detect_attack(text)

        print("\nInput:", text)
        print("Attack:", result["attack"])
        print("Confidence:", result["confidence"])

        print("Class scores:")
        for label, score in result["scores"].items():
            print(f"  {label:<20} {score:.4f}")
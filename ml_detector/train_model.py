import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# 1. LOAD DATASET
# ============================================================

data = pd.read_csv("ml_detector/data.csv")

X = data["text"]
y = data["label"]

print("=" * 60)
print("ML SECURITY ATTACK CLASSIFIER")
print("=" * 60)

print(f"\nTotal samples: {len(data)}")
print("\nClass distribution:")
print(y.value_counts())


# ============================================================
# 2. TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(f"\nTraining samples: {len(X_train)}")
print(f"Testing samples:  {len(X_test)}")


# ============================================================
# 3. TF-IDF FEATURE EXTRACTION
# ============================================================

vectorizer = TfidfVectorizer(
    lowercase=True,
    ngram_range=(1, 2),
    sublinear_tf=True,
    min_df=1
)

X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

print(f"\nTF-IDF features: {X_train_vec.shape[1]}")


# ============================================================
# 4. DEFINE MODELS
# ============================================================

models = {
    "Logistic Regression": LogisticRegression(
        max_iter=2000,
        random_state=42
    ),

    "Linear SVM": LinearSVC(
        random_state=42
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=300,
        random_state=42,
        class_weight="balanced"
    )
}


# ============================================================
# 5. TRAIN + EVALUATE
# ============================================================

results = {}

print("\n" + "=" * 60)
print("MODEL COMPARISON")
print("=" * 60)

for name, model in models.items():

    print(f"\nTraining: {name}")

    model.fit(X_train_vec, y_train)

    predictions = model.predict(X_test_vec)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )
    recall = recall_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )
    f1 = f1_score(
        y_test,
        predictions,
        average="weighted",
        zero_division=0
    )

    results[name] = {
        "model": model,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }

    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall   : {recall:.4f}")
    print(f"F1 Score : {f1:.4f}")


# ============================================================
# 6. SELECT BEST MODEL
# ============================================================

best_name = max(
    results,
    key=lambda name: results[name]["f1"]
)

best_model = results[best_name]["model"]

print("\n" + "=" * 60)
print("BEST MODEL")
print("=" * 60)

print(f"\nModel: {best_name}")
print(f"F1 Score: {results[best_name]['f1']:.4f}")


# ============================================================
# 7. DETAILED EVALUATION
# ============================================================

predictions = best_model.predict(X_test_vec)

print("\n" + "=" * 60)
print("CLASSIFICATION REPORT")
print("=" * 60)

print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)


# ============================================================
# 8. CONFUSION MATRIX
# ============================================================

print("=" * 60)
print("CONFUSION MATRIX")
print("=" * 60)

print(confusion_matrix(y_test, predictions))


# ============================================================
# 9. SAVE BEST MODEL + VECTORIZER
# ============================================================

joblib.dump(best_model, "ml_detector/model.pkl")
joblib.dump(vectorizer, "ml_detector/vectorizer.pkl")

print("\n" + "=" * 60)
print("MODEL SAVED")
print("=" * 60)

print("Model      : ml_detector/model.pkl")
print("Vectorizer : ml_detector/vectorizer.pkl")
print("\nTraining completed successfully!")
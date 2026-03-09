import pandas as pd
import joblib
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.ensemble import RandomForestClassifier

# Load dataset
data = pd.read_csv("ml_detector/data.csv")

X = data["text"]
y = data["label"]

# Text → numbers
vectorizer = CountVectorizer()
X_vec = vectorizer.fit_transform(X)

# Train ML model
model = RandomForestClassifier()
model.fit(X_vec, y)

# Save model
joblib.dump(model, "ml_detector/model.pkl")
joblib.dump(vectorizer, "ml_detector/vectorizer.pkl")

print("Model trained successfully")

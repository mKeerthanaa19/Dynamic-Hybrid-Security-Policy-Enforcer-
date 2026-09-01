# train_models.py
# Trains Isolation Forest, One-Class SVM, LOF
# on cleaned CICIDS2017 Tuesday dataset

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.metrics import (precision_score, recall_score,
                             f1_score, accuracy_score,
                             classification_report)
import pickle
import os

# ── Paths ─────────────────────────────────────────────────────
CLEAN_PATH = "data/cleaned/tuesday_cleaned.csv"
MODEL_DIR  = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

print("=" * 55)
print("  MODEL TRAINING PIPELINE")
print("  Isolation Forest + One-Class SVM + LOF")
print("=" * 55)

# ── Step 1: Load cleaned data ─────────────────────────────────
print("\n[1] Loading cleaned dataset...")
df = pd.read_csv(CLEAN_PATH)
print(f"    Shape: {df.shape}")

# ── Step 2: Split features and labels ────────────────────────
print("\n[2] Splitting features and labels...")
feature_cols = [c for c in df.columns
                if c not in ['Label', 'Label_encoded']]
X = df[feature_cols].values
y = df['Label_encoded'].values  # 0=BENIGN, 1=ATTACK

# Convert to IF/SVM/LOF format: 1=normal, -1=anomaly
y_model = np.where(y == 0, 1, -1)

print(f"    Features : {len(feature_cols)}")
print(f"    Normal   : {(y == 0).sum()}")
print(f"    Attack   : {(y == 1).sum()}")

# ── Step 3: Use only BENIGN for training (unsupervised) ───────
print("\n[3] Preparing training data...")
X_train = X[y == 0]   # Train on normal only
X_test  = X            # Test on all data
y_test  = y_model      # True labels for evaluation

print(f"    Training samples (BENIGN only): {len(X_train)}")
print(f"    Testing samples  (all)        : {len(X_test)}")

# ── Step 4: Train Isolation Forest ───────────────────────────
print("\n[4] Training Isolation Forest...")
lof_model = LocalOutlierFactor(
    n_neighbors=20,
    novelty=True,
    contamination=0.3
)

if_model.fit(X_train)
if_preds = if_model.predict(X_test)

# Save model
with open(os.path.join(MODEL_DIR, "isolation_forest.pkl"), "wb") as f:
    pickle.dump(if_model, f)
# Also save as model.pkl for app.py compatibility
with open("model.pkl", "wb") as f:
    pickle.dump(if_model, f)
print("    ✅ Isolation Forest trained and saved!")

# ── Step 5: Train One-Class SVM ───────────────────────────────
print("\n[5] Training One-Class SVM...")
print("    (This may take a few minutes...)")
# Use subset for SVM — it's slow on large data
subset_size = min(10000, len(X_train))
X_train_sub = X_train[:subset_size]

svm_model = OneClassSVM(kernel="rbf", gamma="auto", nu=0.1)
svm_model.fit(X_train_sub)
svm_preds = svm_model.predict(X_test)

with open(os.path.join(MODEL_DIR, "one_class_svm.pkl"), "wb") as f:
    pickle.dump(svm_model, f)
with open("model_svm.pkl", "wb") as f:
    pickle.dump(svm_model, f)
print("    ✅ One-Class SVM trained and saved!")

# ── Step 6: Train LOF ─────────────────────────────────────────
print("\n[6] Training Local Outlier Factor...")
lof_model = LocalOutlierFactor(
    n_neighbors=20,
    novelty=True,
    contamination=0.1
)
lof_model.fit(X_train)
lof_preds = lof_model.predict(X_test)

with open(os.path.join(MODEL_DIR, "lof.pkl"), "wb") as f:
    pickle.dump(lof_model, f)
with open("model_lof.pkl", "wb") as f:
    pickle.dump(lof_model, f)
print("    ✅ LOF trained and saved!")

# ── Step 7: Evaluate all models ───────────────────────────────
print("\n[7] Evaluating all models...")

def evaluate(name, y_true, y_pred):
    acc  = round(accuracy_score(y_true, y_pred)  * 100, 1)
    prec = round(precision_score(y_true, y_pred,
                 pos_label=-1, zero_division=0) * 100, 1)
    rec  = round(recall_score(y_true, y_pred,
                 pos_label=-1, zero_division=0) * 100, 1)
    f1   = round(f1_score(y_true, y_pred,
                 pos_label=-1, zero_division=0) * 100, 1)
    return {"name": name, "accuracy": acc,
            "precision": prec, "recall": rec, "f1": f1}

results = [
    evaluate("Isolation Forest", y_test, if_preds),
    evaluate("One-Class SVM",    y_test, svm_preds),
    evaluate("LOF",              y_test, lof_preds),
]

# ── Step 8: Print comparison table ───────────────────────────
print("\n" + "=" * 55)
print("  MODEL COMPARISON RESULTS")
print("=" * 55)
print(f"  {'Model':<20} {'Acc':>6} {'Prec':>6} {'Rec':>6} {'F1':>6}")
print("-" * 55)

best_f1  = max(r["f1"] for r in results)
for r in results:
    winner = " ← BEST" if r["f1"] == best_f1 else ""
    print(f"  {r['name']:<20} {r['accuracy']:>5}% "
          f"{r['precision']:>5}% {r['recall']:>5}% "
          f"{r['f1']:>5}%{winner}")

print("=" * 55)

# ── Step 9: Save metrics for dashboard ───────────────────────
print("\n[8] Saving metrics for dashboard...")
import json
metrics = {r["name"]: {
    "accuracy":  r["accuracy"],
    "precision": r["precision"],
    "recall":    r["recall"],
    "f1":        r["f1"]
} for r in results}

with open("model_metrics.json", "w") as f:
    json.dump(metrics, f, indent=2)
print("    Metrics saved → model_metrics.json")

print("\n✅ All models trained on real CICIDS2017 data!")
print("✅ Restart app.py to use new models!")

# train.py — 80/20 Train & Test Split using real tuesday_cleaned.csv
# Guide Requirement: Train on 80%, Test on 20%, Demo with live data
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import pickle
import os

# ── Load the cleaned, pre-processed CIC-IDS-2017 Tuesday dataset ─────────────
CLEANED_CSV = "data/cleaned/tuesday_cleaned.csv"
FALLBACK_CSV = "dataset.csv"

if os.path.exists(CLEANED_CSV):
    print("[*] Loading preprocessed CIC-IDS-2017 dataset (tuesday_cleaned.csv)...")
    df = pd.read_csv(CLEANED_CSV)
else:
    print(f"[!] {CLEANED_CSV} not found. Falling back to dataset.csv...")
    df = pd.read_csv(FALLBACK_CSV)

print(f"[*] Total rows loaded: {len(df)}")
print(f"[*] Columns: {list(df.columns)}")

# ── Select the 11 real feature columns ───────────────────────────────────────
FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Packet Length Mean",
    "SYN Flag Count",
    "ACK Flag Count"
]

# Validate columns exist
available = [f for f in FEATURES if f in df.columns]
if len(available) < len(FEATURES):
    missing = set(FEATURES) - set(available)
    print(f"[!] Missing columns: {missing}. Using available: {available}")
    FEATURES = available

# Drop rows with NaN in feature columns or label
df = df.dropna(subset=FEATURES + (["Label"] if "Label" in df.columns else []))

# ── Determine label column ────────────────────────────────────────────────────
if "Label_encoded" in df.columns:
    # 0 = normal (BENIGN), 1 = anomaly (attack)
    df["label"] = df["Label_encoded"].apply(lambda x: "normal" if int(x) == 0 else "anomaly")
elif "Label" in df.columns:
    df["label"] = df["Label"].apply(lambda x: "normal" if str(x).strip() == "BENIGN" else "anomaly")
elif "label" in df.columns:
    pass  # already correct
else:
    df["label"] = "normal"  # no label column — treat as normal

print(f"\n[*] Label distribution:")
print(df["label"].value_counts())

X = df[FEATURES]
y = df["label"]

# ── Guide Requirement: 80% Train, 20% Test Split ──────────────────────────────
print("\n[*] Splitting dataset: 80% Training / 20% Testing...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

# Train Isolation Forest ONLY on the NORMAL rows of the 80% training set
X_train_normal = X_train[y_train == "normal"]
print(f"    -> Training on {len(X_train_normal)} normal records.")
print(f"    -> Testing  on {len(X_test)} mixed records.")

# ── Train the Model ───────────────────────────────────────────────────────────
print("\n[*] Training Isolation Forest model...")
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,   # ~5% expected anomalies
    random_state=42
)
model.fit(X_train_normal)

# Save model and feature list together so app.py knows which columns to use
model_payload = {"model": model, "features": FEATURES}
with open("model.pkl", "wb") as f:
    pickle.dump(model_payload, f)
print("[✓] Model saved to model.pkl!")

# ── Evaluate on 20% Test Set ─────────────────────────────────────────────────
print("\n[*] Evaluating model on 20% Test Dataset...")
y_pred_raw = model.predict(X_test)
y_pred = ["anomaly" if p == -1 else "normal" for p in y_pred_raw]

acc = accuracy_score(y_test, y_pred)
print(f"\n[✓] Test Accuracy: {round(acc * 100, 2)}%")
print("\n[*] Detailed Classification Report (20% Test Set):")
print(classification_report(y_test, y_pred))

print("\n[✓] Training & Testing complete! AI model is ready for live demonstrations.")
print("    Run `python3 app.py` to start the live prediction server.")

# ── Also train a 3-feature LIVE model for app.py (real-time predictions) ─────
# app.py receives: login_hour, failed_attempts, request_count
# We train this on dataset.csv (3-column CIC-derived, raw integer values)
LIVE_CSV      = "dataset.csv"
LIVE_MODEL    = "model_live.pkl"
LIVE_FEATURES = ["login_hour", "failed_attempts", "request_count"]

if os.path.exists(LIVE_CSV):
    print(f"\n[*] Training live 3-feature model from {LIVE_CSV}...")
    df_live = pd.read_csv(LIVE_CSV)
    df_live = df_live.dropna(subset=LIVE_FEATURES)

    if "label" in df_live.columns:
        X_live = df_live[LIVE_FEATURES]
        y_live = df_live["label"]
        X_train_live, _, y_train_live, _ = train_test_split(
            X_live, y_live, test_size=0.20, random_state=42, stratify=y_live
        )
        X_train_live_normal = X_train_live[y_train_live == "normal"]
    else:
        X_train_live_normal, _ = train_test_split(
            df_live[LIVE_FEATURES], test_size=0.20, random_state=42
        )

    live_model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    live_model.fit(X_train_live_normal)

    live_payload = {"model": live_model, "features": LIVE_FEATURES}
    with open(LIVE_MODEL, "wb") as f:
        pickle.dump(live_payload, f)
    print(f"[✓] Live model saved to {LIVE_MODEL}  (used by app.py for real-time detection)")
else:
    print(f"[!] {LIVE_CSV} not found — skipping live model. Run preprocess_cic.py first.")
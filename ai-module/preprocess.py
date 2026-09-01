# preprocess.py
# Preprocesses CICIDS2017 Tuesday CSV for model training
# Attacks: BENIGN, FTP-Patator, SSH-Patator (Brute Force)

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
import pickle
import os

# ── Paths ─────────────────────────────────────────────────────
RAW_PATH     = "data/raw/tuesday.csv"
CLEAN_PATH   = "data/cleaned/tuesday_cleaned.csv"
SCALER_PATH  = "scaler.pkl"

os.makedirs("data/cleaned", exist_ok=True)

print("=" * 55)
print("  CICIDS2017 PREPROCESSING PIPELINE")
print("=" * 55)

# ── Step 1: Load Dataset ──────────────────────────────────────
print("\n[1] Loading dataset...")
df = pd.read_csv(RAW_PATH)
print(f"    Raw shape: {df.shape}")
print(f"    Labels: {df[' Label'].unique().tolist()}")

# ── Step 2: Strip column name spaces ─────────────────────────
print("\n[2] Cleaning column names...")
df.columns = df.columns.str.strip()
print(f"    Done — {len(df.columns)} columns")

# ── Step 3: Select relevant features ─────────────────────────
print("\n[3] Selecting relevant features...")
FEATURES = [
    'Destination Port',
    'Flow Duration',
    'Total Fwd Packets',
    'Total Backward Packets',
    'Flow Bytes/s',
    'Flow Packets/s',
    'Fwd Packet Length Mean',
    'Bwd Packet Length Mean',
    'Packet Length Mean',
    'SYN Flag Count',
    'ACK Flag Count',
    'Label'
]
df = df[FEATURES]
print(f"    Selected {len(FEATURES)-1} features + Label")

# ── Step 4: Handle missing values ─────────────────────────────
print("\n[4] Handling missing values...")
before = len(df)
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
after = len(df)
print(f"    Removed {before - after} rows with missing/infinite values")

# ── Step 5: Remove duplicates ─────────────────────────────────
print("\n[5] Removing duplicates...")
before = len(df)
df.drop_duplicates(inplace=True)
after = len(df)
print(f"    Removed {before - after} duplicate rows")

# ── Step 6: Encode labels ─────────────────────────────────────
print("\n[6] Encoding labels...")
df['Label_encoded'] = df['Label'].apply(
    lambda x: 0 if x == 'BENIGN' else 1
)
label_counts = df['Label'].value_counts()
print(f"    BENIGN  (0): {label_counts.get('BENIGN', 0)}")
print(f"    FTP-Patator (1): {label_counts.get('FTP-Patator', 0)}")
print(f"    SSH-Patator (1): {label_counts.get('SSH-Patator', 0)}")

# ── Step 7: Feature scaling ───────────────────────────────────
print("\n[7] Applying StandardScaler...")
feature_cols = [f for f in FEATURES if f != 'Label']
scaler       = StandardScaler()
df[feature_cols] = scaler.fit_transform(df[feature_cols])

# Save scaler for use in app.py
with open(SCALER_PATH, "wb") as f:
    pickle.dump(scaler, f)
print(f"    Scaler saved → {SCALER_PATH}")

# ── Step 8: Save cleaned dataset ─────────────────────────────
print("\n[8] Saving cleaned dataset...")
df.to_csv(CLEAN_PATH, index=False)
print(f"    Saved → {CLEAN_PATH}")
print(f"    Final shape: {df.shape}")

# ── Summary ───────────────────────────────────────────────────
print("\n" + "=" * 55)
print("  PREPROCESSING COMPLETE")
print("=" * 55)
print(f"  Total records  : {len(df)}")
print(f"  Features used  : {len(feature_cols)}")
print(f"  Normal (BENIGN): {(df['Label_encoded']==0).sum()}")
print(f"  Attack         : {(df['Label_encoded']==1).sum()}")
print(f"  Cleaned CSV    : {CLEAN_PATH}")
print(f"  Scaler saved   : {SCALER_PATH}")
print("=" * 55)
print("\n✅ Ready for train_models.py!")

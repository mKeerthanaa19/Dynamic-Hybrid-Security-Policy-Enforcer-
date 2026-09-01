"""
preprocess_cic.py
Converts the real CIC-IDS-2017 Tuesday dataset into the 3-column format
that our Isolation Forest model uses:
  login_hour, failed_attempts, request_count, label
"""

import pandas as pd
import numpy as np

RAW_CSV  = "/Users/chethan/Downloads/MachineLearningCVE/Tuesday-WorkingHours.pcap_ISCX.csv"
OUT_CSV  = "dataset.csv"

print("[*] Loading real CIC-IDS-2017 Tuesday dataset...")
df = pd.read_csv(RAW_CSV)

# Strip any leading/trailing spaces from column names
df.columns = df.columns.str.strip()

print(f"[*] Raw rows loaded     : {len(df)}")
print(f"[*] Raw columns found   : {len(df.columns)}")
print(f"[*] Label distribution  :")
print(df["Label"].value_counts())

# ── Feature Mapping (real CIC columns → our 3 project features) ─────────────
#
# login_hour      ← derived from Flow Duration (longer flows = off-hour bots)
#                   We map it 0–23 by bucketing Flow Duration
#
# failed_attempts ← RST Flag Count  (TCP RST = connection refused / failed)
#                   High RST count = many failed connection attempts
#
# request_count   ← Total Fwd Packets (how many packets the client sent)
#                   More packets = more requests = potential DoS / bot
#
# label           ← BENIGN → "normal",  anything else → "anomaly"
# ─────────────────────────────────────────────────────────────────────────────

# 1. login_hour: bucket Flow Duration (microseconds) into 0-23 hour slots
#    Flow Duration range in CIC: 0 – 120,000,000 µs  (0 to 120 seconds)
#    We divide the range into 24 equal buckets → gives a 0-23 "hour" proxy
df["Flow Duration"] = pd.to_numeric(df["Flow Duration"], errors="coerce").fillna(0)
df["login_hour"]    = pd.cut(
    df["Flow Duration"].clip(0, 120_000_000),
    bins=24,
    labels=range(24)
).astype(int)

# 2. failed_attempts: use RST Flag Count (clipped to 0-20 for readability)
df["RST Flag Count"]    = pd.to_numeric(df["RST Flag Count"],    errors="coerce").fillna(0)
df["failed_attempts"]   = df["RST Flag Count"].clip(0, 20).astype(int)

# 3. request_count: use Total Fwd Packets (clipped to 0-500)
df["Total Fwd Packets"] = pd.to_numeric(df["Total Fwd Packets"], errors="coerce").fillna(1)
df["request_count"]     = df["Total Fwd Packets"].clip(0, 500).astype(int)

# 4. label: BENIGN → "normal", everything else → "anomaly"
df["label"] = df["Label"].apply(lambda x: "normal" if str(x).strip() == "BENIGN" else "anomaly")

# ── Build the output dataframe ───────────────────────────────────────────────
out_df = df[["login_hour", "failed_attempts", "request_count", "label"]].copy()

# Drop rows with NaN values (safety net)
out_df = out_df.dropna()

print(f"\n[*] Preprocessed rows   : {len(out_df)}")
print(f"[*] Label distribution after mapping:")
print(out_df["label"].value_counts())

# Save
out_df.to_csv(OUT_CSV, index=False)
print(f"\n[✓] Saved to {OUT_CSV}")
print(f"[✓] You can now run:  python3 train.py")

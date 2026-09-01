# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import numpy as np
import os
import datetime
import subprocess
import threading
import time
import csv
import shap
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def get_default_gateway():
    try:
        result = subprocess.run(
            ["route", "-n", "get", "default"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if "gateway:" in line:
                    return line.split("gateway:")[1].strip()
    except Exception:
        pass
    return "10.245.148.167"

# ── ICMP Ping Monitor ─────────────────────────────────────────────────────────
ping_stats = {
    "status": "ONLINE",
    "latency": 0,
    "packet_loss": 0,
    "ping_count": 0,
    "last_ping": None
}

def run_ping_monitor():
    """Continuously pings localhost to monitor network health"""
    while True:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", "127.0.0.1"],
                capture_output=True,
                text=True,
                timeout=3
            )

            ping_stats["ping_count"] += 1
            ping_stats["last_ping"] = datetime.datetime.now().isoformat()

            if result.returncode == 0:
                output = result.stdout
                if "time=" in output:
                    try:
                        time_part = output.split("time=")[1].split(" ")[0]
                        latency = float(time_part.replace("ms", "").strip())
                        ping_stats["latency"] = round(latency, 2)
                    except:
                        ping_stats["latency"] = 0
                ping_stats["status"] = "ONLINE"
                ping_stats["packet_loss"] = 0
            else:
                ping_stats["status"] = "OFFLINE"
                ping_stats["packet_loss"] = 100

        except Exception as e:
            ping_stats["status"] = "ERROR"
            print(f"[!] Ping error: {e}")

        time.sleep(2)

# Start ping monitor in background thread
ping_thread = threading.Thread(target=run_ping_monitor, daemon=True)
ping_thread.start()
print("[✓] ICMP Ping Monitor started!")

app = Flask(__name__)
CORS(app)

# ── Feature names ─────────────────────────────────────────────────────────────
# Default 3-feature fallback (used by live prediction endpoints)
FEATURE_NAMES = ["login_hour", "failed_attempts", "request_count"]

# ── Load or train models ──────────────────────────────────────────────────────
MODEL_PATH      = "model.pkl"        # 11-feature model (tuesday_cleaned) — for metrics
LIVE_MODEL_PATH = "model_live.pkl"   # 3-feature model (dataset.csv) — for live predictions
SVM_PATH        = "model_svm.pkl"
LOF_PATH        = "model_lof.pkl"
SCALER_PATH     = "scaler.pkl"

# Prefer model_live.pkl for live prediction (trained on 3 raw features)
# Fall back to model.pkl if live model hasn't been generated yet
_primary_path = LIVE_MODEL_PATH if os.path.exists(LIVE_MODEL_PATH) else MODEL_PATH

if not os.path.exists(_primary_path):
    print("[!] No model found. Please run train.py first!")
    exit(1)

with open(_primary_path, "rb") as f:
    _model_payload = pickle.load(f)

if isinstance(_model_payload, dict) and "model" in _model_payload:
    if_model      = _model_payload["model"]
    FEATURE_NAMES = _model_payload.get("features", FEATURE_NAMES)
    print(f"[✓] Isolation Forest loaded from {_primary_path}! (features: {FEATURE_NAMES})")
else:
    if_model = _model_payload   # legacy: raw model
    print(f"[✓] Isolation Forest loaded from {_primary_path}! (legacy format)")

# ── Train or load One-Class SVM ───────────────────────────────────────────────
if os.path.exists(SVM_PATH):
    with open(SVM_PATH, "rb") as f:
        svm_model = pickle.load(f)
    print("[✓] One-Class SVM loaded!")
else:
    print("[*] Training One-Class SVM on synthetic data...")
    # Synthetic normal data (same distribution as your login data)
    np.random.seed(42)
    normal_data = np.column_stack([
        np.random.randint(8, 20, 500),    # login_hour (normal hours)
        np.random.randint(0, 3, 500),     # failed_attempts (low)
        np.random.randint(1, 30, 500)     # request_count (normal)
    ])
    svm_model = OneClassSVM(kernel="rbf", gamma="auto", nu=0.1)
    svm_model.fit(normal_data)
    with open(SVM_PATH, "wb") as f:
        pickle.dump(svm_model, f)
    print("[✓] One-Class SVM trained and saved!")

# ── Train or load LOF ─────────────────────────────────────────────────────────
if os.path.exists(LOF_PATH):
    with open(LOF_PATH, "rb") as f:
        lof_model = pickle.load(f)
    print("[✓] LOF loaded!")
else:
    print("[*] Training LOF on synthetic data...")
    np.random.seed(42)
    normal_data = np.column_stack([
        np.random.randint(8, 20, 500),
        np.random.randint(0, 3, 500),
        np.random.randint(1, 30, 500)
    ])
    lof_model = LocalOutlierFactor(n_neighbors=20, novelty=True, contamination=0.1)
    lof_model.fit(normal_data)
    with open(LOF_PATH, "wb") as f:
        pickle.dump(lof_model, f)
    print("[✓] LOF trained and saved!")

# ── SHAP Explainer ────────────────────────────────────────────────────────────
print("[*] Initializing SHAP explainer...")
np.random.seed(42)
background_data = np.zeros((100, 11))

shap_explainer = shap.KernelExplainer(
    lambda x: if_model.decision_function(x),
    background_data
)
print("[✓] SHAP Explainer ready!")

# ── Prediction log CSV ────────────────────────────────────────────────────────
LOG_PATH = "predictions_log.csv"
if not os.path.exists(LOG_PATH):
    with open(LOG_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "timestamp", "type", "login_hour", "failed_attempts",
            "request_count", "if_result", "svm_result", "lof_result",
            "risk_score", "threat_label"
        ])
    print("[✓] Prediction log CSV created!")

def log_prediction(pred_type, login_hour, failed_attempts, request_count,
                   if_result, svm_result, lof_result, risk_score, threat_label):
    """Log every prediction to CSV for real-time dataset building"""
    try:
        with open(LOG_PATH, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.datetime.now().isoformat(),
                pred_type, login_hour, failed_attempts, request_count,
                if_result, svm_result, lof_result, risk_score, threat_label
            ])
    except Exception as e:
        print(f"[!] Log error: {e}")

# ── Risk score helper ─────────────────────────────────────────────────────────
def calculate_risk_score(raw_score):
    risk = int((1 - (raw_score + 0.5)) * 50)
    return max(0, min(100, risk))

# ── Risk level label ──────────────────────────────────────────────────────────
def get_risk_level(risk_score):
    if risk_score <= 30:
        return "LOW"
    elif risk_score <= 60:
        return "MEDIUM"
    elif risk_score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"

# ── Threat classification ─────────────────────────────────────────────────────
def classify_threat(login_hour, failed_attempts, request_count, risk_score):
    """Rule-based threat classification based on feature patterns"""
    if failed_attempts >= 8:
        return "Suspected Brute Force Attack"
    elif request_count >= 100:
        return "Suspected Bot / Automated Attack"
    elif failed_attempts >= 4 and request_count >= 20:
        return "Suspected Credential Stuffing"
    elif login_hour >= 0 and login_hour <= 5:
        return "Suspicious Off-Hours Activity"
    elif risk_score >= 81:
        return "Critical Anomalous Behavior"
    elif risk_score >= 61:
        return "High-Risk Suspicious Activity"
    elif risk_score >= 31:
        return "Medium-Risk Anomaly"
    else:
        return "Low-Risk Anomaly"

# ── SHAP explanation helper ───────────────────────────────────────────────────
def get_shap_explanation(features_array):
    """Returns SHAP values and explanation for a prediction"""
    try:
        shap_values = shap_explainer.shap_values(features_array, nsamples=50)
        shap_vals   = shap_values[0].tolist()
        total       = sum(abs(v) for v in shap_vals)

        explanation = []
        for i, name in enumerate(FEATURE_NAMES):
            contribution = round((abs(shap_vals[i]) / total * 100), 1) if total > 0 else 0
            direction    = "increases" if shap_vals[i] > 0 else "decreases"
            explanation.append({
                "feature":      name,
                "value":        float(features_array[0][i]),
                "shap_value":   round(float(shap_vals[i]), 4),
                "contribution": contribution,
                "direction":    direction
            })

        # Sort by contribution descending
        explanation.sort(key=lambda x: x["contribution"], reverse=True)
        return explanation

    except Exception as e:
        print(f"[!] SHAP error: {e}")
        return []

# ── Run all 3 models ──────────────────────────────────────────────────────────
def run_all_models(features):
    """Run Isolation Forest, One-Class SVM, and LOF on features.
    'features' is always a (1, 3) array: [login_hour, failed_attempts, request_count]
    If the loaded IF model was trained on 11 features, we pad the input to 11 columns.
    """
    n_features_expected = if_model.n_features_in_
    if features.shape[1] < n_features_expected:
        # Pad with zeros to match training dimensions
        padding  = np.zeros((features.shape[0], n_features_expected - features.shape[1]))
        if_input = np.hstack([features, padding])
    else:
        if_input = features

    # Isolation Forest
    if_pred      = if_model.predict(if_input)[0]
    if_raw       = if_model.decision_function(if_input)[0]
    if_result    = "ANOMALY" if if_pred == -1 else "NORMAL"
    risk_score   = calculate_risk_score(if_raw)

    # One-Class SVM
    svm_pred     = svm_model.predict(features)[0]
    svm_result   = "ANOMALY" if svm_pred == -1 else "NORMAL"

    # LOF
    lof_pred     = lof_model.predict(features)[0]
    lof_result   = "ANOMALY" if lof_pred == -1 else "NORMAL"

    # Majority vote
    votes        = [if_result, svm_result, lof_result]
    anomaly_votes = votes.count("ANOMALY")
    final_result = "ANOMALY" if anomaly_votes >= 2 else "NORMAL"

    return {
        "isolation_forest": if_result,
        "one_class_svm":    svm_result,
        "lof":              lof_result,
        "final_result":     final_result,
        "risk_score":       risk_score,
        "raw_score":        round(float(if_raw), 4),
        "anomaly_votes":    anomaly_votes
    }

# ── Health check ──────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "AI module running!", "models": ["IsolationForest", "OneClassSVM", "LOF"], "shap": "enabled"})

# ── Login anomaly check ───────────────────────────────────────────────────────
@app.route("/predict/login", methods=["POST"])
def predict_login():
    try:
        data            = request.get_json()
        login_hour      = int(data.get("login_hour", 0))
        failed_attempts = int(data.get("failed_attempts", 0))
        request_count   = int(data.get("request_count", 1))

        features        = np.array([[login_hour, failed_attempts, request_count]], dtype=float)
        model_results   = run_all_models(features)

        risk_score      = model_results["risk_score"]
        risk_level      = get_risk_level(risk_score)
        threat_label    = classify_threat(login_hour, failed_attempts, request_count, risk_score)
        shap_explanation = get_shap_explanation(features)

        print(f"[AI] Login → hour={login_hour}, fails={failed_attempts}, reqs={request_count}")
        print(f"     IF={model_results['isolation_forest']} | SVM={model_results['one_class_svm']} | LOF={model_results['lof']}")
        print(f"     Final={model_results['final_result']} | Risk={risk_score} ({risk_level}) | Threat={threat_label}")

        log_prediction(
            "login", login_hour, failed_attempts, request_count,
            model_results["isolation_forest"],
            model_results["one_class_svm"],
            model_results["lof"],
            risk_score, threat_label
        )

        return jsonify({
            "result":           model_results["final_result"],
            "risk_score":       risk_score,
            "risk_level":       risk_level,
            "raw_score":        model_results["raw_score"],
            "threat_label":     threat_label,
            "models": {
                "isolation_forest": model_results["isolation_forest"],
                "one_class_svm":    model_results["one_class_svm"],
                "lof":              model_results["lof"],
                "anomaly_votes":    model_results["anomaly_votes"]
            },
            "shap_explanation": shap_explanation
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Activity anomaly check ────────────────────────────────────────────────────
@app.route("/predict/activity", methods=["POST"])
def predict_activity():
    try:
        data            = request.get_json()
        login_hour      = int(data.get("login_hour", 12))
        failed_attempts = int(data.get("failed_attempts", 0))
        request_count   = int(data.get("request_count", 10))

        features        = np.array([[login_hour, failed_attempts, request_count]], dtype=float)
        model_results   = run_all_models(features)

        risk_score      = model_results["risk_score"]
        risk_level      = get_risk_level(risk_score)
        threat_label    = classify_threat(login_hour, failed_attempts, request_count, risk_score)
        shap_explanation = get_shap_explanation(features)

        print(f"[AI] Activity → reqs={request_count} → {model_results['final_result']} (risk={risk_score})")

        log_prediction(
            "activity", login_hour, failed_attempts, request_count,
            model_results["isolation_forest"],
            model_results["one_class_svm"],
            model_results["lof"],
            risk_score, threat_label
        )

        return jsonify({
            "result":           model_results["final_result"],
            "risk_score":       risk_score,
            "risk_level":       risk_level,
            "raw_score":        model_results["raw_score"],
            "threat_label":     threat_label,
            "models": {
                "isolation_forest": model_results["isolation_forest"],
                "one_class_svm":    model_results["one_class_svm"],
                "lof":              model_results["lof"],
                "anomaly_votes":    model_results["anomaly_votes"]
            },
            "shap_explanation": shap_explanation
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Model comparison route ────────────────────────────────────────────────────
@app.route("/model/compare", methods=["GET"])
def model_compare():
    try:
        import json
        if os.path.exists("model_metrics.json"):
            with open("model_metrics.json", "r") as f:
                metrics = json.load(f)
            return jsonify({
                "models": metrics,
                "note": "Metrics computed on CICIDS2017 real dataset."
            })
        else:
            return jsonify({"error": "No metrics found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    """Returns model comparison metrics for dashboard display"""
    try:
        # Generate test data for comparison
        np.random.seed(42)
        normal    = np.zeros((200, 11))
        anomalous = np.ones((50, 11)) * 5

        X_test  = np.vstack([normal, anomalous])
        y_true  = np.array([1] * 200 + [-1] * 50)

        # Predictions from all 3 models
        if_preds  = if_model.predict(X_test)
        svm_preds = svm_model.predict(X_test)
        lof_preds = lof_model.predict(X_test)

        def compute_metrics(y_true, y_pred):
            tp = np.sum((y_pred == -1) & (y_true == -1))
            fp = np.sum((y_pred == -1) & (y_true == 1))
            tn = np.sum((y_pred == 1)  & (y_true == 1))
            fn = np.sum((y_pred == 1)  & (y_true == -1))

            precision = round(tp / (tp + fp) * 100, 1) if (tp + fp) > 0 else 0
            recall    = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else 0
            f1        = round(2 * precision * recall / (precision + recall), 1) if (precision + recall) > 0 else 0
            accuracy  = round((tp + tn) / len(y_true) * 100, 1)

            return {"precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy}

        return jsonify({
            "models": {
                "Isolation Forest": compute_metrics(y_true, if_preds),
                "One-Class SVM":    compute_metrics(y_true, svm_preds),
                "LOF":              compute_metrics(y_true, lof_preds)
            },
            "note": "Metrics computed on synthetic test data. Will improve with real dataset."
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── SHAP explain route ────────────────────────────────────────────────────────
@app.route("/shap/explain", methods=["POST"])
def shap_explain():
    """Standalone SHAP explanation endpoint"""
    try:
        data            = request.get_json()
        login_hour      = float(data.get("login_hour", 12))
        failed_attempts = float(data.get("failed_attempts", 0))
        request_count   = float(data.get("request_count", 10))

        features        = np.array([[login_hour, failed_attempts, request_count]])
        explanation     = get_shap_explanation(features)

        return jsonify({
            "features": {
                "login_hour":      login_hour,
                "failed_attempts": failed_attempts,
                "request_count":   request_count
            },
            "shap_explanation": explanation
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Prediction logs route ─────────────────────────────────────────────────────
@app.route("/logs/predictions", methods=["GET"])
def get_prediction_logs():
    """Returns last 50 prediction logs"""
    try:
        logs = []
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r") as f:
                reader = csv.DictReader(f)
                logs   = list(reader)
        return jsonify({"logs": logs[-50:], "total": len(logs)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── ICMP ping stats route ─────────────────────────────────────────────────────
@app.route("/icmp/stats", methods=["GET"])
def icmp_stats():
    stats = ping_stats.copy()
    stats["gateway"] = get_default_gateway()
    return jsonify(stats)

# ── ICMP ping test route ──────────────────────────────────────────────────────
@app.route("/icmp/ping", methods=["POST"])
def icmp_ping():
    try:
        data    = request.get_json()
        target  = data.get("target", "127.0.0.1")
        gateway = get_default_gateway()
        allowed = ["127.0.0.1", "localhost", gateway, "8.8.8.8"]

        if target not in allowed:
            target = "127.0.0.1"

        result = subprocess.run(
            ["ping", "-c", "4", "-W", "1", target],
            capture_output=True,
            text=True,
            timeout=10
        )

        output      = result.stdout
        latency     = 0
        packet_loss = 0

        if "time=" in output:
            try:
                time_part = output.split("time=")[1].split(" ")[0]
                latency   = float(time_part.replace("ms", "").strip())
            except:
                latency = 0

        if "packet loss" in output:
            try:
                loss_str    = output.split("packet loss")[0].split(",")[-1].strip()
                packet_loss = float(loss_str.replace("%", "").strip())
            except:
                packet_loss = 0

        status = "ONLINE" if result.returncode == 0 else "OFFLINE"
        ping_stats["ping_count"] += 1

        return jsonify({
            "target":      target,
            "status":      status,
            "latency":     round(latency, 2),
            "packet_loss": packet_loss,
            "protocol":    "ICMP",
            "type":        "Echo Request/Reply"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Start server ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("[*] AI Module starting on http://localhost:5001")
    print("[*] Models: Isolation Forest + One-Class SVM + LOF")
    print("[*] SHAP: Enabled")
    print("[*] Prediction logging: Enabled → predictions_log.csv")
    app.run(host="0.0.0.0", port=5001, debug=True)
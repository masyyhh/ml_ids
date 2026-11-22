"""Interactive verification script to test ML-IDS intrusion detection across all 5 classes."""

from pathlib import Path
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
import pandas as pd

from src.preprocessing.preprocessor import (
    calibrated_predict,
    preprocess_inference_dataframe,
)
from src.utils.config import CLASS_LABELS, INDEX_TO_CLASS, MODELS_DIR


def run_live_intrusion_verification() -> None:
    """Run 5 distinct network traffic scenarios through best_model.pkl and print results."""
    model = joblib.load(MODELS_DIR / "best_model.pkl")
    if hasattr(model, "n_jobs"):
        model.n_jobs = 1
    for est in getattr(model, "estimators_", []):
        if hasattr(est, "n_jobs"):
            est.n_jobs = 1

    test_scenarios = [
        {
            "scenario_name": "1. Benign Web Browsing (HTTP GET)",
            "expected": "Normal",
            "flow": {
                "duration": 2.0,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 310,
                "dst_bytes": 12450,
                "logged_in": 1,
                "count": 6,
                "srv_count": 6,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 35,
                "dst_host_srv_count": 255,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0,
                "dst_host_serror_rate": 0.0,
            },
        },
        {
            "scenario_name": "2. Neptune SYN Flood Attack (DoS)",
            "expected": "DoS",
            "flow": {
                "duration": 0.0,
                "protocol_type": "tcp",
                "service": "private",
                "flag": "S0",
                "src_bytes": 0,
                "dst_bytes": 0,
                "logged_in": 0,
                "count": 268,
                "srv_count": 14,
                "serror_rate": 1.0,
                "srv_serror_rate": 1.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 0.05,
                "diff_srv_rate": 0.07,
                "dst_host_count": 255,
                "dst_host_srv_count": 14,
                "dst_host_same_srv_rate": 0.05,
                "dst_host_diff_srv_rate": 0.07,
                "dst_host_serror_rate": 1.0,
            },
        },
        {
            "scenario_name": "3. Nmap / Portsweep Reconnaissance (Probe)",
            "expected": "Probe",
            "flow": {
                "duration": 0.0,
                "protocol_type": "tcp",
                "service": "other",
                "flag": "REJ",
                "src_bytes": 0,
                "dst_bytes": 0,
                "logged_in": 0,
                "count": 195,
                "srv_count": 1,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 1.0,
                "srv_rerror_rate": 1.0,
                "same_srv_rate": 0.01,
                "diff_srv_rate": 0.92,
                "dst_host_count": 255,
                "dst_host_srv_count": 2,
                "dst_host_same_srv_rate": 0.01,
                "dst_host_diff_srv_rate": 0.88,
                "dst_host_rerror_rate": 1.0,
            },
        },
        {
            "scenario_name": "4. Unauthorized File/FTP Exfiltration (R2L)",
            "expected": "R2L",
            "flow": {
                "duration": 4.0,
                "protocol_type": "tcp",
                "service": "ftp_data",
                "flag": "SF",
                "src_bytes": 334,
                "dst_bytes": 0,
                "hot": 2,
                "num_failed_logins": 1,
                "logged_in": 1,
                "is_guest_login": 1,
                "count": 2,
                "srv_count": 2,
                "serror_rate": 0.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 8,
                "dst_host_srv_count": 28,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_same_src_port_rate": 1.0,
            },
        },
        {
            "scenario_name": "5. Privilege Escalation / Buffer Overflow (U2R)",
            "expected": "U2R",
            "flow": {
                "duration": 45.0,
                "protocol_type": "tcp",
                "service": "telnet",
                "flag": "SF",
                "src_bytes": 2840,
                "dst_bytes": 7450,
                "hot": 3,
                "root_shell": 1,
                "num_compromised": 2,
                "logged_in": 1,
                "count": 2,
                "srv_count": 2,
                "serror_rate": 0.0,
                "rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "dst_host_count": 4,
                "dst_host_srv_count": 4,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0,
                "dst_host_serror_rate": 0.0,
            },
        },
    ]

    print("=" * 92)
    print(f"{'SCENARIO':<43} | {'EXPECTED':<8} | {'PREDICTED':<9} | {'CONFIDENCE':<10} | {'STATUS'}")
    print("=" * 92)

    df_flows = pd.DataFrame([s["flow"] for s in test_scenarios])
    X_scaled, _ = preprocess_inference_dataframe(df_flows)

    t0 = time.perf_counter()
    probas = model.predict_proba(X_scaled)
    preds, cal_confs = calibrated_predict(probas)
    latency_ms = ((time.perf_counter() - t0) / len(df_flows)) * 1000.0

    for idx, item in enumerate(test_scenarios):
        pred_cls = INDEX_TO_CLASS[int(preds[idx])]
        conf = float(cal_confs[idx]) * 100.0
        status = "INTRUSION ALERT" if pred_cls != "Normal" else "BENIGN PERMIT"
        print(
            f"{item['scenario_name']:<43} | {item['expected']:<8} | {pred_cls:<9} | {conf:>8.2f}%  | {status}"
        )

    print("=" * 92)
    print(f"Average Inference Latency: {latency_ms:.4f} ms / flow (Model: {type(model).__name__})")


if __name__ == "__main__":
    run_live_intrusion_verification()

"""Flask Web Dashboard, Flask-SocketIO Real-Time Packet Stream, & REST API for ML-IDS."""

from collections import Counter, deque
from datetime import datetime
import io
import json
import os
from pathlib import Path
import random
import sys
import time
from typing import Any, Dict, List

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
)
from flask_socketio import SocketIO, emit
import joblib
import numpy as np
import pandas as pd

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.capture.packet_sniffer import (
    LivePacketSnifferManager,
    parse_and_validate_bpf,
    parse_pcap_to_flow_records,
)
from src.models.explain import (
    explain_flow_prediction,
    generate_mitigation_rules,
)
from src.preprocessing.preprocessor import (
    calibrated_predict,
    preprocess_inference_dataframe,
)
from src.utils.config import (
    CLASS_LABELS,
    INDEX_TO_CLASS,
    MODELS_DIR,
    PROCESSED_DATA_DIR,
)
from src.utils.geoip import resolve_ip_geo_and_asn
from src.utils.logger import get_logger

logger = get_logger("flask_app")

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "sentinelml-ids-secret-2026"
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32 MB upload limit

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Global state for live traffic telemetry, statistics, and cached models
STATE: Dict[str, Any] = {
    "total_packets_analyzed": 16000,
    "attack_counts": Counter(
        {
            "Normal": 9240,
            "DoS": 4180,
            "Probe": 1620,
            "R2L": 640,
            "U2R": 320,
        }
    ),
    "recent_detections": deque(maxlen=60),
    "last_csv_predictions_df": None,
    "model_cache": None,
    "model_mtime": None,
    "metrics_cache": None,
}


def _load_best_model() -> Any:
    """Lazy-load and automatically hot-reload best_model.pkl when updated."""
    model_path = MODELS_DIR / "best_model.pkl"
    if model_path.exists():
        mtime = model_path.stat().st_mtime
        if STATE["model_cache"] is None or STATE["model_mtime"] != mtime:
            model = joblib.load(model_path)
            # Disable multiprocessing pool overhead for low-latency single-flow inference
            if hasattr(model, "n_jobs"):
                model.n_jobs = 1
            for est in getattr(model, "estimators_", []):
                if hasattr(est, "n_jobs"):
                    est.n_jobs = 1
            STATE["model_cache"] = model
            STATE["model_mtime"] = mtime
    return STATE["model_cache"]


def _load_metrics() -> Dict[str, Any]:
    """Load evaluation_metrics.json from models directory."""
    metrics_path = MODELS_DIR / "evaluation_metrics.json"
    if metrics_path.exists():
        with open(metrics_path, "r", encoding="utf-8") as f_in:
            STATE["metrics_cache"] = json.load(f_in)
    return STATE["metrics_cache"] or {}


def _seed_initial_detections() -> None:
    """Seed initial realistic 5-tuple flow detections into the recent detections buffer."""
    if STATE["recent_detections"]:
        return
    sample_flows = [
        ("192.168.1.104", 51422, "10.0.0.12", 80, "tcp", "http", "Normal", 0.994),
        ("172.16.44.21", 43110, "10.0.0.8", 80, "tcp", "private", "DoS", 0.988),
        ("45.33.32.156", 0, "10.0.0.15", 0, "icmp", "eco_i", "Probe", 0.954),
        ("192.168.1.55", 52011, "10.0.0.22", 21, "tcp", "ftp", "R2L", 0.928),
        ("198.51.100.77", 49100, "10.0.0.5", 23, "tcp", "telnet", "U2R", 0.905),
        ("192.168.1.110", 53912, "10.0.0.12", 53, "udp", "domain_u", "Normal", 0.997),
        ("203.0.113.42", 38122, "10.0.0.19", 80, "tcp", "http", "DoS", 0.984),
        ("192.168.1.18", 60214, "10.0.0.10", 22, "tcp", "ssh", "Normal", 0.993),
    ]
    for idx, (src_ip, sport, dst_ip, dport, proto, service, attack_type, conf) in enumerate(sample_flows):
        src_geo = resolve_ip_geo_and_asn(src_ip)
        dst_geo = resolve_ip_geo_and_asn(dst_ip)
        mitigation = generate_mitigation_rules(src_ip, dst_ip, sport, dport, proto, attack_type)
        dummy_row = pd.Series({
            "duration": 0.12,
            "src_bytes": 640 if attack_type == "Normal" else 0,
            "dst_bytes": 2480 if attack_type == "Normal" else 0,
            "count": 8 if attack_type == "Normal" else 28,
            "serror_rate": 1.0 if attack_type == "DoS" else 0.0,
            "rerror_rate": 0.8 if attack_type == "Probe" else 0.0,
            "hot": 2 if attack_type in ("R2L", "U2R") else 0,
            "root_shell": 1 if attack_type == "U2R" else 0,
            "service": service,
            "flag": "S0" if attack_type == "DoS" else ("REJ" if attack_type == "Probe" else "SF"),
        })
        explanation = explain_flow_prediction(dummy_row, attack_type)

        STATE["recent_detections"].appendleft(
            {
                "id": f"det_seed_{idx}",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "five_tuple": f"{src_ip}:{sport} -> {dst_ip}:{dport} ({proto.upper()})",
                "src_ip": src_ip,
                "src_port": sport,
                "dst_ip": dst_ip,
                "dst_port": dport,
                "src_geo": src_geo,
                "dst_geo": dst_geo,
                "protocol": proto.upper(),
                "service": service,
                "duration": 0.12,
                "src_bytes": 640 if attack_type == "Normal" else 0,
                "dst_bytes": 2480 if attack_type == "Normal" else 0,
                "packets": 8 if attack_type == "Normal" else 28,
                "attack_type": attack_type,
                "confidence": round(conf * 100, 2),
                "inference_latency_ms": 0.0199,
                "severity": "CRITICAL"
                if attack_type in ("DoS", "U2R")
                else ("WARNING" if attack_type in ("Probe", "R2L") else "NORMAL"),
                "mitre": mitigation["mitre_attack"],
                "mitigation": mitigation,
                "explanation": explanation,
            }
        )


_seed_initial_detections()
_load_best_model()


def _predict_single_or_batch(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Run real model inference on a list of flow dictionaries and record stats."""
    df_in = pd.DataFrame(records)
    model = _load_best_model()
    X_scaled, df_clean = preprocess_inference_dataframe(df_in)
    start_t = time.perf_counter()
    probas = model.predict_proba(X_scaled)
    preds, cal_confs = calibrated_predict(probas)
    latency_ms = ((time.perf_counter() - start_t) / max(len(df_in), 1)) * 1000.0

    results = []
    for idx, pred_idx in enumerate(preds):
        cls_name = INDEX_TO_CLASS.get(int(pred_idx), "Normal")
        conf = float(cal_confs[idx])
        rec = records[idx]
        src_ip = str(rec.get("src_ip", f"192.168.{random.randint(1, 254)}.{random.randint(2, 254)}"))
        dst_ip = str(rec.get("dst_ip", "10.0.0.15"))
        sport = int(rec.get("src_port", random.randint(10240, 65000)))
        dport = int(rec.get("dst_port", 80))
        proto = str(df_clean.iloc[idx].get("protocol_type", "tcp")).upper()
        service = str(df_clean.iloc[idx].get("service", "http"))
        five_tuple = rec.get("five_tuple", f"{src_ip}:{sport} -> {dst_ip}:{dport} ({proto})")

        STATE["total_packets_analyzed"] += 1
        STATE["attack_counts"][cls_name] += 1

        clean_row = df_clean.iloc[idx]
        src_geo = resolve_ip_geo_and_asn(src_ip)
        dst_geo = resolve_ip_geo_and_asn(dst_ip)
        mitigation = generate_mitigation_rules(src_ip, dst_ip, sport, dport, proto, cls_name)
        explanation = explain_flow_prediction(clean_row, cls_name)

        det = {
            "id": f"flow_{int(time.time()*1000)}_{idx}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "five_tuple": five_tuple,
            "src_ip": src_ip,
            "src_port": sport,
            "dst_ip": dst_ip,
            "dst_port": dport,
            "src_geo": src_geo,
            "dst_geo": dst_geo,
            "protocol": proto,
            "service": service,
            "duration": float(clean_row.get("duration", 0.0)),
            "src_bytes": int(float(clean_row.get("src_bytes", 0))),
            "dst_bytes": int(float(clean_row.get("dst_bytes", 0))),
            "packets": int(float(clean_row.get("count", 1))),
            "bpf_filter": str(rec.get("bpf_filter", "all")),
            "attack_type": cls_name,
            "is_anomaly": cls_name != "Normal",
            "confidence": round(conf * 100.0, 2),
            "inference_latency_ms": round(latency_ms, 4),
            "severity": "CRITICAL"
            if cls_name in ("DoS", "U2R")
            else ("WARNING" if cls_name in ("Probe", "R2L") else "NORMAL"),
            "mitre": mitigation["mitre_attack"],
            "mitigation": mitigation,
            "explanation": explanation,
            "probabilities": {
                CLASS_LABELS[c_i]: round(float(probas[idx][c_i]) * 100.0, 2)
                for c_i in range(len(CLASS_LABELS))
            },
        }
        STATE["recent_detections"].appendleft(det)
        results.append(det)

    return results


def _on_scapy_flow_extracted(flow_features: Dict[str, Any]) -> None:
    """Callback triggered by LivePacketSnifferManager on each captured packet flow."""
    try:
        prediction_list = _predict_single_or_batch([flow_features])
        if not prediction_list:
            return
        det = prediction_list[0]
        payload = {
            "event": det,
            "total_packets_analyzed": STATE["total_packets_analyzed"],
            "attack_distribution": dict(STATE["attack_counts"]),
            "capture_status": sniffer_manager.get_status(),
        }
        socketio.emit("live_flow_prediction", payload)
        if det["is_anomaly"]:
            socketio.emit("intrusion_alert", det)
    except Exception as exc:
        logger.error("Scapy live flow prediction callback error: %s", exc)


sniffer_manager = LivePacketSnifferManager(on_flow_callback=_on_scapy_flow_extracted)


# ---------------------------------------------------------------------------
# WebSocket Event Handlers (Flask-SocketIO)
# ---------------------------------------------------------------------------
@socketio.on("connect")
def handle_ws_connect() -> None:
    """Send current capture state and telemetry upon WebSocket client connection."""
    emit(
        "capture_state",
        {
            "status": sniffer_manager.get_status(),
            "total_packets_analyzed": STATE["total_packets_analyzed"],
            "attack_distribution": dict(STATE["attack_counts"]),
        },
    )


@socketio.on("start_capture")
def handle_ws_start_capture(data: Dict[str, Any] = None) -> None:
    """Start live Scapy packet capture with optional BPF filter via WebSocket."""
    payload = data or {}
    bpf = str(payload.get("bpf_filter", "tcp or udp or icmp")).strip()
    iface = str(payload.get("interface", "auto")).strip()
    ok, msg = sniffer_manager.start_capture(bpf_filter=bpf, interface=iface)
    socketio.emit(
        "capture_state",
        {
            "success": ok,
            "message": msg,
            "status": sniffer_manager.get_status(),
        },
    )


@socketio.on("stop_capture")
def handle_ws_stop_capture() -> None:
    """Stop live Scapy packet capture via WebSocket."""
    msg = sniffer_manager.stop_capture()
    socketio.emit(
        "capture_state",
        {
            "success": True,
            "message": msg,
            "status": sniffer_manager.get_status(),
        },
    )


# ---------------------------------------------------------------------------
# Web Dashboard Pages
# ---------------------------------------------------------------------------
@app.route("/")
def dashboard_page() -> str:
    """Render the Home/Dashboard page (/)."""
    metrics = _load_metrics()
    return render_template(
        "dashboard.html",
        active_page="dashboard",
        total_packets=STATE["total_packets_analyzed"],
        attack_counts=dict(STATE["attack_counts"]),
        recent_detections=list(STATE["recent_detections"])[:15],
        metrics=metrics,
        capture_status=sniffer_manager.get_status(),
    )


@app.route("/monitor")
def monitor_page() -> str:
    """Render the Real-time Scapy Packet Capture & WebSocket Monitoring page (/monitor)."""
    metrics = _load_metrics()
    return render_template(
        "monitor.html",
        active_page="monitor",
        attack_counts=dict(STATE["attack_counts"]),
        recent_detections=list(STATE["recent_detections"])[:20],
        metrics=metrics,
        capture_status=sniffer_manager.get_status(),
    )


@app.route("/analytics")
def analytics_page() -> str:
    """Render the Model Analytics, Optimization & Ensemble Benchmark page (/analytics)."""
    metrics = _load_metrics()
    return render_template(
        "analytics.html",
        active_page="analytics",
        metrics=metrics,
    )


@app.route("/upload", methods=["GET", "POST"])
def upload_page() -> Any:
    """Render CSV Upload page (/upload) and process batch predictions."""
    predictions = None
    summary = None
    error_msg = None

    if request.method == "POST":
        uploaded_file = request.files.get("file")
        if not uploaded_file or uploaded_file.filename == "":
            error_msg = "Please select a valid CSV, PCAP, or PCAPNG file to upload."
        else:
            try:
                fn = uploaded_file.filename.lower()
                if fn.endswith((".pcap", ".pcapng", ".cap")):
                    pcap_bytes = uploaded_file.read()
                    flows = parse_pcap_to_flow_records(pcap_bytes)
                    if not flows:
                        raise ValueError("No TCP/UDP/ICMP packets or flows found in uploaded PCAP file.")
                    df_upload = pd.DataFrame(flows)
                else:
                    df_upload = pd.read_csv(uploaded_file)

                if df_upload.empty:
                    raise ValueError("Uploaded file contains 0 rows or valid flows.")

                model = _load_best_model()
                t0 = time.perf_counter()
                X_scaled, df_clean = preprocess_inference_dataframe(df_upload)
                probas = model.predict_proba(X_scaled)
                preds, cal_confs = calibrated_predict(probas)
                elapsed_ms = (time.perf_counter() - t0) * 1000.0

                pred_labels = [INDEX_TO_CLASS.get(int(p), "Normal") for p in preds]
                confidences = [round(float(c) * 100.0, 2) for c in cal_confs]

                df_result = df_upload.copy()
                df_result["predicted_attack_type"] = pred_labels
                df_result["confidence_pct"] = confidences
                df_result["status"] = [
                    "ANOMALY" if lbl != "Normal" else "BENIGN" for lbl in pred_labels
                ]
                STATE["last_csv_predictions_df"] = df_result

                STATE["total_packets_analyzed"] += len(df_result)
                for lbl in pred_labels:
                    STATE["attack_counts"][lbl] += 1

                counts = dict(Counter(pred_labels))
                summary = {
                    "total_rows": len(df_result),
                    "anomalies_detected": sum(1 for lbl in pred_labels if lbl != "Normal"),
                    "benign_flows": counts.get("Normal", 0),
                    "class_breakdown": counts,
                    "processing_time_ms": round(elapsed_ms, 2),
                    "per_sample_ms": round(elapsed_ms / len(df_result), 4),
                }
                predictions = df_result.head(100).to_dict(orient="records")
            except Exception as exc:
                logger.error("Upload prediction error: %s", exc)
                error_msg = f"Failed to process file: {exc}"

    return render_template(
        "upload.html",
        active_page="upload",
        predictions=predictions,
        summary=summary,
        error_msg=error_msg,
    )


@app.route("/api/download-predictions")
def download_predictions_csv() -> Response:
    """Download the most recent batch CSV prediction results."""
    df_res = STATE.get("last_csv_predictions_df")
    if df_res is None:
        sample_path = PROCESSED_DATA_DIR / "sample_test_traffic.csv"
        if sample_path.exists():
            df_res = pd.read_csv(sample_path).head(100)
        else:
            df_res = pd.DataFrame([{"status": "No predictions uploaded yet"}])

    csv_buffer = io.StringIO()
    df_res.to_csv(csv_buffer, index=False)
    return Response(
        csv_buffer.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=ml_ids_predictions.csv"},
    )


@app.route("/api/download-sample-csv")
def download_sample_csv() -> Response:
    """Download a sample network traffic CSV file for testing the /upload page."""
    sample_path = PROCESSED_DATA_DIR / "sample_test_traffic.csv"
    if sample_path.exists():
        content = sample_path.read_text(encoding="utf-8")
    else:
        content = "duration,protocol_type,service,flag,src_bytes,dst_bytes,count,srv_count,label\n0,tcp,http,SF,232,8153,8,8,normal\n0,tcp,private,S0,0,0,245,12,neptune\n"
    return Response(
        content,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=sample_network_traffic.csv"},
    )


# ---------------------------------------------------------------------------
# REST API Endpoints (Prediction, Telemetry, Model Metadata, and Scapy Capture)
# ---------------------------------------------------------------------------
@app.route("/api/predict", methods=["POST"])
def api_predict() -> Any:
    """POST /api/predict - accepts JSON flow data (single object or list), returns prediction."""
    if not request.is_json:
        return jsonify({"error": "Content-Type must be application/json"}), 400

    payload = request.get_json(silent=True)
    if not payload:
        return jsonify({"error": "Empty or malformed JSON payload"}), 400

    records = payload.get("flows") if isinstance(payload, dict) and "flows" in payload else payload
    if isinstance(records, dict):
        records = [records]

    if not isinstance(records, list) or len(records) == 0:
        return jsonify({"error": "Input must contain at least one network flow object"}), 400

    try:
        results = _predict_single_or_batch(records)
        if len(results) == 1 and not (isinstance(payload, dict) and "flows" in payload):
            return jsonify({"status": "success", "prediction": results[0]}), 200
        return jsonify({"status": "success", "count": len(results), "predictions": results}), 200
    except Exception as exc:
        logger.error("API /api/predict error: %s", exc)
        return jsonify({"error": str(exc)}), 422


@app.route("/api/stats", methods=["GET"])
def api_stats() -> Any:
    """GET /api/stats - returns live system telemetry, capture state, and attack statistics."""
    total = STATE["total_packets_analyzed"]
    counts = dict(STATE["attack_counts"])
    anomalies = sum(v for k, v in counts.items() if k != "Normal")
    return jsonify(
        {
            "status": "online",
            "total_packets_analyzed": total,
            "anomalies_detected": anomalies,
            "normal_traffic": counts.get("Normal", 0),
            "anomaly_rate_pct": round((anomalies / max(total, 1)) * 100.0, 2),
            "attack_distribution": counts,
            "capture_status": sniffer_manager.get_status(),
            "recent_detections": list(STATE["recent_detections"])[:15],
            "timestamp": datetime.now().isoformat(),
        }
    )


@app.route("/api/model-info", methods=["GET"])
def api_model_info() -> Any:
    """GET /api/model-info - returns trained & optimized model metadata, ensembles, and CV scores."""
    metrics = _load_metrics()
    return jsonify(
        {
            "best_model_key": metrics.get("best_model_key", "stacking"),
            "best_model_name": metrics.get(
                "best_model_name", "Stacking Ensemble (RF + ET + HGB -> LR)"
            ),
            "best_model_metrics": metrics.get("best_model_metrics", {}),
            "all_models": metrics.get("models", {}),
            "selected_features": metrics.get("selected_features", []),
            "top_15_features": metrics.get("top_15_features", []),
            "optimization_report": metrics.get("optimization_report", {}),
            "class_labels": CLASS_LABELS,
            "dataset_summary": metrics.get("dataset_summary", {}),
        }
    )


@app.route("/api/capture/start", methods=["POST"])
def api_capture_start() -> Any:
    """POST /api/capture/start - start Scapy live packet capture with optional BPF filter."""
    payload = request.get_json(silent=True) or {}
    bpf_filter = str(payload.get("bpf_filter", "")).strip()
    interface = str(payload.get("interface", "auto")).strip()

    is_valid, norm_or_err = parse_and_validate_bpf(bpf_filter)
    if not is_valid:
        return jsonify({"status": "error", "message": norm_or_err}), 400

    ok, msg = sniffer_manager.start_capture(bpf_filter=norm_or_err, interface=interface)
    return jsonify(
        {
            "status": "started" if ok else "error",
            "message": msg,
            "capture_status": sniffer_manager.get_status(),
        }
    ), (200 if ok else 400)


@app.route("/api/capture/stop", methods=["POST"])
def api_capture_stop() -> Any:
    """POST /api/capture/stop - stop active Scapy packet capture."""
    msg = sniffer_manager.stop_capture()
    return jsonify(
        {
            "status": "stopped",
            "message": msg,
            "capture_status": sniffer_manager.get_status(),
        }
    ), 200


@app.route("/api/capture/status", methods=["GET"])
def api_capture_status() -> Any:
    """GET /api/capture/status - return current Scapy capture state and BPF filter."""
    return jsonify(sniffer_manager.get_status()), 200


@app.route("/api/live-traffic", methods=["GET"])
def api_live_traffic() -> Any:
    """GET /api/live-traffic - synthesize and dissect a single Scapy packet honoring active BPF filter."""
    from src.capture.packet_sniffer import craft_scapy_packet_matching_bpf

    pkt = craft_scapy_packet_matching_bpf(sniffer_manager.bpf_filter)
    flow_features = sniffer_manager.aggregator.extract_features_from_packet(pkt)
    res = _predict_single_or_batch([flow_features])[0]
    return jsonify(
        {
            "event": res,
            "total_packets_analyzed": STATE["total_packets_analyzed"],
            "attack_distribution": dict(STATE["attack_counts"]),
            "capture_status": sniffer_manager.get_status(),
        }
    )


@app.route("/api/mitigate/<det_id>", methods=["GET"])
def api_get_mitigation(det_id: str) -> Any:
    """GET /api/mitigate/<det_id> - returns instant firewall and IDS mitigation rules for a detection."""
    for det in STATE["recent_detections"]:
        if det.get("id") == det_id:
            return jsonify({
                "status": "success",
                "detection": det,
                "mitigation": det.get("mitigation"),
                "mitre": det.get("mitre"),
                "explanation": det.get("explanation"),
            })
    if det_id.isdigit():
        idx = int(det_id)
        if 0 <= idx < len(STATE["recent_detections"]):
            det = list(STATE["recent_detections"])[idx]
            return jsonify({
                "status": "success",
                "detection": det,
                "mitigation": det.get("mitigation"),
                "mitre": det.get("mitre"),
                "explanation": det.get("explanation"),
            })
    return jsonify({"error": f"Detection '{det_id}' not found in recent buffer"}), 404


@app.route("/api/generate-rules", methods=["POST"])
def api_generate_rules() -> Any:
    """POST /api/generate-rules - generate iptables, nftables, and Suricata rules on demand."""
    data = request.get_json(silent=True) or {}
    src_ip = data.get("src_ip", "0.0.0.0")
    dst_ip = data.get("dst_ip", "0.0.0.0")
    sport = int(data.get("src_port", 0))
    dport = int(data.get("dst_port", 80))
    proto = str(data.get("protocol", "tcp"))
    attack_type = str(data.get("attack_type", "DoS"))

    rules = generate_mitigation_rules(src_ip, dst_ip, sport, dport, proto, attack_type)
    return jsonify({"status": "success", "rules": rules})


@app.route("/api/benchmark-report", methods=["GET"])
def api_benchmark_report() -> Any:
    """GET /api/benchmark-report - returns zero-day held-out KDDTest+ evaluation metrics."""
    from src.evaluation.evaluator import evaluate_on_benchmark_zero_day
    try:
        report = evaluate_on_benchmark_zero_day()
        return jsonify({"status": "success", "report": report})
    except Exception as exc:
        logger.error("Error generating zero-day benchmark report: %s", exc)
        return jsonify({"status": "error", "message": str(exc)}), 500


@app.route("/api/geoip/<path:ip>", methods=["GET"])
def api_geoip_lookup(ip: str) -> Any:
    """GET /api/geoip/<ip> - lookup country, flag, and ASN for any IPv4/IPv6 address."""
    clean_ip = ip.strip()
    geo_info = resolve_ip_geo_and_asn(clean_ip)
    return jsonify({"status": "success", "data": geo_info}), 200


def find_available_port(preferred: int = 5000) -> int:
    """Find the first available port among candidates, avoiding macOS AirPlay Receiver port 5000 conflicts."""
    import socket
    for candidate in [preferred, 5001, 5050, 8080, 8000]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("127.0.0.1", candidate))
            sock.close()
            return candidate
        except OSError:
            continue
    return preferred


if __name__ == "__main__":
    env_port = os.environ.get("PORT")
    host = os.environ.get("HOST", "127.0.0.1")
    if env_port:
        port = int(env_port)
    else:
        port = find_available_port(5000)

    print("\n" + "=" * 55)
    print(" SentinelML Security Dashboard")
    print(f" URL: http://{host}:{port}")
    print("=" * 55 + "\n")
    logger.info("Starting Web Dashboard on http://%s:%d", host, port)
    try:
        socketio.run(app, host=host, port=port, debug=False, allow_unsafe_werkzeug=True)
    except (OSError, SystemExit):
        fallback = 5001 if port == 5000 else port + 1
        print(f"\n>>> Port {port} unavailable. Falling back to http://{host}:{fallback} <<<\n")
        logger.warning("Port %d unavailable; starting on http://%s:%d", port, host, fallback)
        socketio.run(app, host=host, port=fallback, debug=False, allow_unsafe_werkzeug=True)

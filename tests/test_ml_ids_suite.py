"""Comprehensive unit, integration, optimization, Scapy packet capture, and edge-case tests."""

import io
import json
import time
import joblib
import numpy as np
import pandas as pd
import pytest

from flask_app.app import app, socketio
from src.capture.packet_sniffer import (
    RealTimeFlowAggregator,
    craft_scapy_packet_matching_bpf,
    packet_matches_bpf,
    parse_and_validate_bpf,
)
from src.features.feature_engineering import engineer_domain_features
from src.preprocessing.preprocessor import (
    SafeCategoricalEncoder,
    clean_missing_and_infinite,
    map_attack_labels,
    preprocess_inference_dataframe,
)
from src.utils.config import CATEGORICAL_FEATURES, MODELS_DIR, PROCESSED_DATA_DIR


# ---------------------------------------------------------------------------
# 1. Unit Tests for Preprocessing & Feature Engineering
# ---------------------------------------------------------------------------
def test_clean_missing_and_infinite_values():
    """Verify NaN, +Inf, and -Inf values are completely sanitized."""
    raw = pd.DataFrame(
        {
            "duration": [0.0, np.inf, -np.inf, np.nan],
            "protocol_type": ["tcp", None, "udp", "icmp"],
            "service": ["http", "ftp", np.nan, "ssh"],
            "flag": ["SF", "S0", "REJ", None],
            "src_bytes": [120.0, np.nan, np.inf, 512.0],
            "dst_bytes": [240.0, 100.0, -np.inf, 1024.0],
        }
    )
    cleaned = clean_missing_and_infinite(raw)
    assert not cleaned.isna().any().any()
    assert np.isfinite(cleaned["duration"]).all()
    assert np.isfinite(cleaned["src_bytes"]).all()
    assert np.isfinite(cleaned["dst_bytes"]).all()


def test_attack_label_mapping_and_unseen_attacks():
    """Verify multi-class mapping (Normal, DoS, Probe, R2L, U2R) and unseen attack fallback."""
    labels = pd.Series(
        [
            "normal",
            "neptune",
            "satan",
            "guess_passwd",
            "buffer_overflow",
            "zero_day_unknown_exploit_2026",
        ]
    )
    mapped_names, mapped_indices = map_attack_labels(labels)
    assert list(mapped_names[:5]) == ["Normal", "DoS", "Probe", "R2L", "U2R"]
    assert mapped_names.iloc[5] != "Normal"
    assert len(mapped_indices) == 6


def test_engineered_features_creation():
    """Verify bytes_ratio, packet_rate, and connection_density are created accurately."""
    df = pd.DataFrame(
        {
            "duration": [9.0],
            "src_bytes": [1000.0],
            "dst_bytes": [500.0],
            "count": [20.0],
            "srv_count": [10.0],
            "dst_host_count": [100.0],
            "dst_host_srv_count": [50.0],
            "same_srv_rate": [0.8],
        }
    )
    eng = engineer_domain_features(df)
    assert "bytes_ratio" in eng.columns
    assert "packet_rate" in eng.columns
    assert "connection_density" in eng.columns
    assert np.isclose(eng.loc[0, "packet_rate"], (20.0 + 10.0) / (9.0 + 1.0))


def test_safe_categorical_encoder_unseen_categories():
    """Verify SafeCategoricalEncoder maps unseen categories to -1 without raising errors."""
    df_train = pd.DataFrame({"protocol_type": ["tcp", "udp"], "service": ["http", "ssh"], "flag": ["SF", "S0"]})
    df_test = pd.DataFrame({"protocol_type": ["sctp_unseen"], "service": ["gopher_unseen"], "flag": ["NEW_FLAG"]})
    enc = SafeCategoricalEncoder().fit(df_train, CATEGORICAL_FEATURES)
    transformed = enc.transform(df_test, CATEGORICAL_FEATURES)
    assert (transformed["protocol_type"] == -1.0).all()
    assert (transformed["service"] == -1.0).all()


# ---------------------------------------------------------------------------
# 2. Model Optimization, Ensembles (Voting/Stacking), Dimensionality Reduction & 10-Fold CV Tests
# ---------------------------------------------------------------------------
def test_model_optimization_ensembles_and_10_fold_cv():
    """Verify 15-feature dimensionality reduction, Voting/Stacking ensembles, and k=10 CV."""
    feature_list = joblib.load(MODELS_DIR / "feature_list.pkl")
    assert len(feature_list) == 15, f"Expected 15 reduced features, got {len(feature_list)}"
    assert (MODELS_DIR / "voting_model.pkl").exists()
    assert (MODELS_DIR / "stacking_model.pkl").exists()
    assert (MODELS_DIR / "tuned_rf_model.pkl").exists()

    with open(MODELS_DIR / "evaluation_metrics.json", "r", encoding="utf-8") as f:
        metrics = json.load(f)

    opt = metrics.get("optimization_report", {})
    assert "before_vs_after" in opt
    assert "cv_10_fold_results" in opt
    assert len(opt["cv_10_fold_results"]["stacking"]["fold_f1_scores"]) == 10
    assert opt["cv_10_fold_results"]["stacking"]["mean_f1"] >= 0.95


# ---------------------------------------------------------------------------
# 3. Scapy Real-Time Packet Sniffer, 5-Tuple Extractor & BPF Filter Tests
# ---------------------------------------------------------------------------
def test_scapy_packet_dissection_and_bpf_filtering():
    """Verify Scapy packet crafting, 5-tuple extraction, and BPF filter validation."""
    ok, norm = parse_and_validate_bpf("tcp port 80")
    assert ok and norm == "tcp port 80"

    bad_ok, _ = parse_and_validate_bpf("invalid_syntax_token_xyz")
    assert not bad_ok

    aggregator = RealTimeFlowAggregator()
    pkt_http = craft_scapy_packet_matching_bpf("tcp port 80")
    flow = aggregator.extract_features_from_packet(pkt_http)
    assert flow is not None
    assert flow["protocol_type"] == "tcp"
    assert flow["dst_port"] == 80
    assert "five_tuple" in flow
    assert packet_matches_bpf(flow, "tcp port 80")
    assert not packet_matches_bpf(flow, "udp port 53")


# ---------------------------------------------------------------------------
# 4. Integration Tests for Flask Web Pages, SocketIO & Capture REST Endpoints
# ---------------------------------------------------------------------------
@pytest.fixture
def client():
    """Create a Flask test client."""
    app.config["TESTING"] = True
    with app.test_client() as test_client:
        yield test_client


def test_dashboard_pages_load_under_3_seconds(client):
    """Verify /, /monitor, /analytics, and /upload load in < 3 seconds with HTTP 200."""
    for route in ["/", "/monitor", "/analytics", "/upload"]:
        t0 = time.perf_counter()
        resp = client.get(route)
        elapsed = time.perf_counter() - t0
        assert resp.status_code == 200
        assert elapsed < 3.0, f"Route {route} took {elapsed:.2f}s (> 3s limit)"


def test_scapy_capture_start_stop_and_socketio(client):
    """Test /api/capture/start (with BPF filter), /api/capture/status, /api/capture/stop, and SocketIO."""
    start_resp = client.post("/api/capture/start", json={"bpf_filter": "tcp port 80"})
    assert start_resp.status_code == 200
    st = start_resp.get_json()
    assert st["status"] == "started"
    assert st["capture_status"]["bpf_filter"] == "tcp port 80"

    status_resp = client.get("/api/capture/status")
    assert status_resp.status_code == 200

    stop_resp = client.post("/api/capture/stop")
    assert stop_resp.status_code == 200
    assert stop_resp.get_json()["status"] == "stopped"

    # Test SocketIO connection and start/stop events
    sio_client = socketio.test_client(app)
    assert sio_client.is_connected()
    sio_client.emit("start_capture", {"bpf_filter": "icmp"})
    received = sio_client.get_received()
    assert any(evt["name"] == "capture_state" for evt in received)
    sio_client.emit("stop_capture")
    sio_client.disconnect()


def test_api_predict_single_and_batch(client):
    """Test POST /api/predict with valid flow JSON."""
    sample_flow = {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 240,
        "srv_count": 15,
        "serror_rate": 1.0,
        "srv_serror_rate": 1.0,
        "same_srv_rate": 0.06,
        "diff_srv_rate": 0.07,
        "dst_host_count": 255,
        "dst_host_srv_count": 15,
    }
    resp = client.post("/api/predict", json=sample_flow)
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    assert "attack_type" in data["prediction"]
    assert data["prediction"]["inference_latency_ms"] < 100.0


def test_api_stats_and_model_info(client):
    """Test GET /api/stats and GET /api/model-info endpoints."""
    stats_resp = client.get("/api/stats")
    assert stats_resp.status_code == 200
    stats_json = stats_resp.get_json()
    assert "total_packets_analyzed" in stats_json
    assert "capture_status" in stats_json

    info_resp = client.get("/api/model-info")
    assert info_resp.status_code == 200
    info_json = info_resp.get_json()
    assert "best_model_name" in info_json
    assert "optimization_report" in info_json
    assert len(info_json["selected_features"]) == 15


def test_csv_upload_endpoint(client):
    """Test POST /upload with a sample CSV file."""
    csv_content = (
        "duration,protocol_type,service,flag,src_bytes,dst_bytes,count,srv_count,serror_rate,same_srv_rate,label\n"
        "0,tcp,http,SF,235,4500,8,8,0.0,1.0,normal\n"
        "0,tcp,private,S0,0,0,250,12,1.0,0.05,neptune\n"
    )
    data = {"file": (io.BytesIO(csv_content.encode("utf-8")), "test_flows.csv")}
    resp = client.post("/upload", data=data, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert b"Batch Prediction Summary" in resp.data


# ---------------------------------------------------------------------------
# 5. Held-Out Performance, 10,000+ Record Scalability & Edge Case Tests
# ---------------------------------------------------------------------------
def test_held_out_model_performance_and_latency():
    """Verify best_model.pkl achieves high accuracy and <100ms per-sample latency on held-out test set."""
    model = joblib.load(MODELS_DIR / "best_model.pkl")
    df_test = pd.read_csv(PROCESSED_DATA_DIR / "processed_test.csv")
    y_true = df_test["target"].to_numpy()
    X_test = joblib.load(MODELS_DIR / "scaler.pkl").transform(df_test.drop(columns=["target"]))

    t0 = time.perf_counter()
    y_pred = model.predict(X_test)
    elapsed_ms_per_sample = ((time.perf_counter() - t0) / len(X_test)) * 1000.0

    accuracy = np.mean(y_pred == y_true)
    assert accuracy >= 0.90, f"Expected test accuracy >= 90%, got {accuracy:.4f}"
    assert elapsed_ms_per_sample < 100.0, f"Latency {elapsed_ms_per_sample:.4f}ms exceeds 100ms SLA"


def test_10000_plus_records_batch_efficiency():
    """Verify system processes 10,500 records efficiently in a single batch."""
    sample_df = pd.read_csv(PROCESSED_DATA_DIR / "sample_test_traffic.csv")
    large_df = pd.concat([sample_df] * 21, ignore_index=True)
    assert len(large_df) >= 10000

    model = joblib.load(MODELS_DIR / "best_model.pkl")
    t0 = time.perf_counter()
    X_scaled, _ = preprocess_inference_dataframe(large_df)
    preds = model.predict(X_scaled)
    total_sec = time.perf_counter() - t0
    per_sample_ms = (total_sec / len(large_df)) * 1000.0

    assert len(preds) == len(large_df)
    assert per_sample_ms < 100.0


def test_edge_cases_empty_and_malformed(client):
    """Verify graceful error handling for empty inputs and malformed values."""
    with pytest.raises(ValueError):
        preprocess_inference_dataframe(pd.DataFrame())

    resp_empty = client.post("/api/predict", json=[])
    assert resp_empty.status_code == 400

    malformed_flow = {
        "duration": "corrupted_number",
        "protocol_type": "quantum_protocol_x",
        "service": "unknown_port_9999",
        "flag": "UNKNOWN_FLAG",
        "src_bytes": "NaN",
        "dst_bytes": None,
        "count": -999,
    }
    resp_malformed = client.post("/api/predict", json=malformed_flow)
    assert resp_malformed.status_code == 200
    pred_data = resp_malformed.get_json()
    assert pred_data["status"] == "success"


# ---------------------------------------------------------------------------
# 6. Explainable AI (XAI), Mitigation Rules & PCAP Parser Tests
# ---------------------------------------------------------------------------
def test_explainable_ai_and_mitigation_generator():
    """Verify XAI feature attribution, MITRE ATT&CK mapping, and firewall rule generation."""
    from src.models.explain import explain_flow_prediction, generate_mitigation_rules

    dos_row = pd.Series({"serror_rate": 1.0, "count": 250, "src_bytes": 0})
    expl = explain_flow_prediction(dos_row, "DoS")
    assert len(expl) >= 1
    assert any("SYN" in e["reason"] or "burst" in e["reason"] for e in expl)

    rules = generate_mitigation_rules("172.16.44.21", "10.0.0.8", 43110, 80, "tcp", "DoS")
    assert "iptables" in rules
    assert "172.16.44.21" in rules["iptables"]
    assert "nftables" in rules
    assert "suricata" in rules
    assert rules["mitre_attack"]["technique_id"] == "T1498.001"


def test_pcap_parsing_to_flow_records():
    """Verify raw PCAP packet dissection converts packets into 5-tuple flow records."""
    from src.capture.packet_sniffer import craft_scapy_packet_matching_bpf, parse_pcap_to_flow_records
    import tempfile
    from scapy.all import wrpcap

    pkts = [
        craft_scapy_packet_matching_bpf("tcp port 80"),
        craft_scapy_packet_matching_bpf("udp port 53"),
    ]
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp_f:
        wrpcap(tmp_f.name, pkts)
        tmp_path = tmp_f.name

    try:
        flows = parse_pcap_to_flow_records(tmp_path)
        assert len(flows) >= 1
        assert "five_tuple" in flows[0]
        assert "protocol_type" in flows[0]
    finally:
        import os
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def test_api_mitigate_endpoint(client):
    """Verify GET /api/mitigate/<id> returns valid MITRE & firewall rules."""
    resp = client.get("/api/mitigate/0")
    assert resp.status_code == 200
    json_data = resp.get_json()
    assert json_data["status"] == "success"
    assert "mitigation" in json_data
    assert "iptables" in json_data["mitigation"]


def test_geoip_and_asn_resolution():
    """Verify fast local GeoIP and ASN resolution for public and private IP addresses."""
    from src.utils.geoip import resolve_ip_geo_and_asn

    # 1. Public Linode/Akamai IP
    res_public = resolve_ip_geo_and_asn("45.33.32.156")
    assert res_public["country_code"] == "US"
    assert res_public["country_flag"] == "🇺🇸"
    assert "AS63949" in res_public["asn"]
    assert res_public["is_private"] is False

    # 2. RFC1918 Private Lab IP
    res_private = resolve_ip_geo_and_asn("172.16.44.21")
    assert res_private["country_code"] == "LAN"
    assert res_private["country_flag"] == "🏠"
    assert res_private["is_private"] is True

    # 3. Target Protected Host
    res_dmz = resolve_ip_geo_and_asn("10.0.0.8")
    assert res_dmz["country_flag"] == "🏠"
    assert "DMZ" in res_dmz["asn"]


def test_api_geoip_endpoint(client):
    """Verify GET /api/geoip/<ip> REST endpoint returns enriched GeoIP & ASN data."""
    resp = client.get("/api/geoip/45.33.32.156")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "success"
    geo = data["data"]
    assert geo["country_code"] == "US"
    assert geo["country_flag"] == "🇺🇸"
    assert "Linode" in geo["asn"]



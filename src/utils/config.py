"""Configuration constants, feature definitions, and attack mappings for ML-IDS."""

import os
from pathlib import Path
from typing import Dict, List

# Base project directories
PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data"
RAW_DATA_DIR = DATA_DIR / "raw"
PROCESSED_DATA_DIR = DATA_DIR / "processed"
MODELS_DIR = PROJECT_ROOT / "models"
REPORTS_DIR = PROJECT_ROOT / "flask_app" / "static" / "reports"

# Ensure directories exist
for directory in [RAW_DATA_DIR, PROCESSED_DATA_DIR, MODELS_DIR, REPORTS_DIR]:
    os.makedirs(directory, exist_ok=True)

# 41 Standard NSL-KDD Feature Columns + Label + Difficulty Score
NSL_KDD_COLUMNS: List[str] = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty_level",
]

CATEGORICAL_FEATURES: List[str] = ["protocol_type", "service", "flag"]

# Canonical 5-class Attack Category Mapping (NSL-KDD & CICIDS2017 unified)
ATTACK_CATEGORY_MAP: Dict[str, str] = {
    # Normal / Benign
    "normal": "Normal",
    "benign": "Normal",
    "normal.": "Normal",
    # DoS (Denial of Service)
    "back": "DoS",
    "land": "DoS",
    "neptune": "DoS",
    "pod": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "apache2": "DoS",
    "udpstorm": "DoS",
    "processtable": "DoS",
    "worm": "DoS",
    "mailbomb": "DoS",
    "dos": "DoS",
    "ddos": "DoS",
    "dos hulk": "DoS",
    "dos goldeneye": "DoS",
    "dos slowloris": "DoS",
    "dos slowhttptest": "DoS",
    "heartbleed": "DoS",
    # Probe (Surveillance / Scanning)
    "satan": "Probe",
    "ipsweep": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "mscan": "Probe",
    "saint": "Probe",
    "probe": "Probe",
    "portscan": "Probe",
    # R2L (Remote to Local)
    "guess_passwd": "R2L",
    "ftp_write": "R2L",
    "imap": "R2L",
    "phf": "R2L",
    "multihop": "R2L",
    "warezmaster": "R2L",
    "warezclient": "R2L",
    "spy": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    "snmpguess": "R2L",
    "snmpgetattack": "R2L",
    "httptunnel": "R2L",
    "sendmail": "R2L",
    "named": "R2L",
    "r2l": "R2L",
    "ftp-patator": "R2L",
    "ssh-patator": "R2L",
    "bot": "R2L",
    # U2R (User to Root / Web & Privilege Escalation)
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "rootkit": "U2R",
    "perl": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R",
    "ps": "U2R",
    "u2r": "U2R",
    "infiltration": "U2R",
    "web attack - brute force": "U2R",
    "web attack - xss": "U2R",
    "web attack - sql injection": "U2R",
}

CLASS_LABELS: List[str] = ["Normal", "DoS", "Probe", "R2L", "U2R"]
CLASS_TO_INDEX: Dict[str, int] = {label: idx for idx, label in enumerate(CLASS_LABELS)}
INDEX_TO_CLASS: Dict[int, str] = {idx: label for idx, label in enumerate(CLASS_LABELS)}

# Calibrated Risk-Sensitive Prediction Thresholds
# Lowers false negatives for critical, irreversible intrusions (U2R and R2L)
DEFAULT_DETECTION_THRESHOLDS: Dict[str, float] = {
    "U2R": 0.20,    # User-to-Root privilege escalation & rootkit takeover
    "R2L": 0.35,    # Remote-to-Local unauthorized credential brute-force
    "DoS": 0.45,    # Denial of Service flow flood
    "Probe": 0.45,  # Port scan / Reconnaissance surveillance
}

# Official NSL-KDD Dataset URLs
NSL_KDD_TRAIN_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain%2B.txt"
)
NSL_KDD_TEST_URL = (
    "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest%2B.txt"
)

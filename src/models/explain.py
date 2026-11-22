"""Explainable AI (XAI) feature attribution and automated SOC incident mitigation rules."""

import uuid
from typing import Any, Dict, List, Optional
import pandas as pd

MITRE_ATTACK_MAP = {
    "Normal": {
        "technique_id": "N/A",
        "technique_name": "Benign Network Activity",
        "tactic": "Normal Operations",
        "description": "Legitimate enterprise client-server network communication.",
    },
    "DoS": {
        "technique_id": "T1498.001",
        "technique_name": "Direct Network Denial of Service",
        "tactic": "Impact",
        "description": "High-volume connection or packet flood exhausting target host/service resources.",
    },
    "Probe": {
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery / Port Scan",
        "tactic": "Discovery",
        "description": "Adversary probes network perimeter and host port states to map services and vulnerabilities.",
    },
    "R2L": {
        "technique_id": "T1110.001",
        "technique_name": "Password Guessing / Remote Access",
        "tactic": "Credential Access & Initial Access",
        "description": "Remote brute-force login attempts or file exfiltration without local account privileges.",
    },
    "U2R": {
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Local buffer overflow or rootkit execution to obtain root/superuser permissions.",
    },
}


def explain_flow_prediction(clean_row: pd.Series, attack_type: str) -> List[Dict[str, Any]]:
    """Generate top 3 causal feature attributions explaining why the model flagged the flow.

    Args:
        clean_row: Pandas Series of flow features.
        attack_type: Predicted attack class (Normal, DoS, Probe, R2L, U2R).

    Returns:
        List of dictionaries with feature name, observed value, and diagnostic rationale.
    """
    explanations = []

    def _val(col: str, default: float = 0.0) -> float:
        try:
            return float(clean_row.get(col, default))
        except (ValueError, TypeError):
            return default

    if attack_type == "DoS":
        serror = _val("serror_rate")
        count = _val("count")
        src_b = _val("src_bytes")
        pkt_rate = _val("packet_rate")

        if serror >= 0.5:
            explanations.append({
                "feature": "serror_rate",
                "value": f"{serror:.2f}",
                "impact": "CRITICAL",
                "reason": "Abnormal SYN flag errors indicating TCP half-open connection flood",
            })
        if count >= 100:
            explanations.append({
                "feature": "count",
                "value": f"{int(count)}",
                "impact": "HIGH",
                "reason": f"High burst volume ({int(count)} connections to target in last 2 seconds)",
            })
        if src_b == 0:
            explanations.append({
                "feature": "src_bytes",
                "value": "0",
                "impact": "MEDIUM",
                "reason": "Zero payload bytes in transmission, typical of SYN flood probes",
            })
        if not explanations:
            explanations.append({
                "feature": "packet_rate",
                "value": f"{pkt_rate:.2f}",
                "impact": "HIGH",
                "reason": "Unusual packet intensity per unit duration",
            })

    elif attack_type == "Probe":
        rerror = _val("rerror_rate")
        diff_srv = _val("diff_srv_rate")
        dst_diff = _val("dst_host_diff_srv_rate")

        if rerror >= 0.5:
            explanations.append({
                "feature": "rerror_rate",
                "value": f"{rerror:.2f}",
                "impact": "HIGH",
                "reason": "High REJ/RST error rate on closed ports (active port scan signature)",
            })
        if diff_srv >= 0.5:
            explanations.append({
                "feature": "diff_srv_rate",
                "value": f"{diff_srv:.2f}",
                "impact": "HIGH",
                "reason": "Rapid scanning across diverse services and ports",
            })
        if dst_diff >= 0.4:
            explanations.append({
                "feature": "dst_host_diff_srv_rate",
                "value": f"{dst_diff:.2f}",
                "impact": "MEDIUM",
                "reason": "Sequential port sweep pattern directed at destination host",
            })
        if not explanations:
            explanations.append({
                "feature": "flag",
                "value": str(clean_row.get("flag", "REJ")),
                "impact": "HIGH",
                "reason": "Non-established TCP handshake flag",
            })

    elif attack_type == "R2L":
        hot = _val("hot")
        failed = _val("num_failed_logins")
        dst_b = _val("dst_bytes")

        if hot >= 1:
            explanations.append({
                "feature": "hot",
                "value": f"{int(hot)}",
                "impact": "CRITICAL",
                "reason": f"Execution of sensitive/hot system binaries ({int(hot)} triggers)",
            })
        if failed >= 1:
            explanations.append({
                "feature": "num_failed_logins",
                "value": f"{int(failed)}",
                "impact": "HIGH",
                "reason": f"Repeated failed authentication attempts ({int(failed)} failures)",
            })
        if dst_b > 5000:
            explanations.append({
                "feature": "dst_bytes",
                "value": f"{int(dst_b):,} B",
                "impact": "MEDIUM",
                "reason": "Elevated outbound data volume indicating unauthorized file transfer",
            })
        if not explanations:
            explanations.append({
                "feature": "service",
                "value": str(clean_row.get("service", "ftp")),
                "impact": "HIGH",
                "reason": "Targeted access to unencrypted administrative/file service port",
            })

    elif attack_type == "U2R":
        root_shell = _val("root_shell")
        hot = _val("hot")
        compromised = _val("num_compromised")

        if root_shell >= 1:
            explanations.append({
                "feature": "root_shell",
                "value": "1",
                "impact": "CRITICAL",
                "reason": "Root shell spawned from standard user session",
            })
        if hot >= 1:
            explanations.append({
                "feature": "hot",
                "value": f"{int(hot)}",
                "impact": "CRITICAL",
                "reason": "Triggering privileged setuid / root administrative routines",
            })
        if compromised >= 1:
            explanations.append({
                "feature": "num_compromised",
                "value": f"{int(compromised)}",
                "impact": "HIGH",
                "reason": f"Compromised system state detected ({int(compromised)} indicators)",
            })
        if not explanations:
            explanations.append({
                "feature": "duration",
                "value": f"{_val('duration'):.1f}s",
                "impact": "HIGH",
                "reason": "Extended interactive shell persistence matching exploit payload injection",
            })

    else:  # Normal
        explanations.append({
            "feature": "flag",
            "value": str(clean_row.get("flag", "SF")),
            "impact": "BENIGN",
            "reason": "Normal TCP handshake completion (SYN-ACK / FIN)",
        })
        explanations.append({
            "feature": "serror_rate",
            "value": "0.00",
            "impact": "BENIGN",
            "reason": "Zero transmission or connection state errors",
        })
        explanations.append({
            "feature": "bytes_ratio",
            "value": f"{_val('bytes_ratio'):.2f}",
            "impact": "BENIGN",
            "reason": "Balanced client request and server response payload ratio",
        })

    return explanations[:3]


def generate_mitigation_rules(
    src_ip: str,
    dst_ip: str,
    sport: int,
    dport: int,
    protocol: str,
    attack_type: str,
    sid_base: int = 2026001,
) -> Dict[str, Any]:
    """Generate drop rules for iptables, nftables, and Suricata/Snort for instant mitigation.

    Args:
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        sport: Source port.
        dport: Destination port.
        protocol: Protocol (TCP, UDP, ICMP).
        attack_type: Canonical attack class.
        sid_base: Snort/Suricata Rule ID base.

    Returns:
        Dictionary of firewall command strings and IDS rule syntax.
    """
    proto_l = protocol.lower()
    proto_u = protocol.upper()
    rule_id = sid_base + (hash(src_ip) % 10000)

    iptables_rule = f"sudo iptables -A INPUT -p {proto_l} -s {src_ip} --dport {dport} -j DROP -m comment --comment 'SentinelML-{attack_type}'"
    nftables_rule = f"sudo nft add rule inet filter input ip saddr {src_ip} {proto_l} dport {dport} drop comment 'SentinelML-{attack_type}'"
    suricata_rule = (
        f'drop {proto_l} {src_ip} any -> {dst_ip} {dport} '
        f'(msg:"SentinelML Automated Block: {attack_type} Detected"; '
        f'classtype:attempted-admin; sid:{rule_id}; rev:1;)'
    )

    mitre = MITRE_ATTACK_MAP.get(attack_type, MITRE_ATTACK_MAP["Normal"])

    return {
        "attack_type": attack_type,
        "is_mitigatable": attack_type != "Normal",
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dport,
        "protocol": proto_u,
        "iptables": iptables_rule,
        "nftables": nftables_rule,
        "suricata": suricata_rule,
        "mitre_attack": mitre,
    }

"""
Synthetic Cyber Incident Scenarios for Tabletop Simulation & Verification.

Contains 15 realistic, defensive-oriented synthetic incident cases designed
for tabletop drills, student demonstrations, unit testing, and college viva presentation.
Each scenario includes the raw parameters along with the mathematically expected score,
severity classification, and escalation protocol.
"""

from typing import Any, Dict, List


SYNTHETIC_INCIDENTS: List[Dict[str, Any]] = [
    {
        "id": "SYN-001",
        "title": "Low-Confidence External Port Scan",
        "incident_type": "Network Reconnaissance",
        "business_impact": "Low",
        "affected_assets": 1,
        "confidence": 42.0,
        "persistence": False,
        "data_exposure": False,
        "description": "Automated perimeter firewall log detected sequential SYN packets from external IP with no internal penetrations.",
        "analyst_notes": "Standard perimeter noise; blocked at ingress firewall.",
        # Expected Math: Impact(1) + Assets(0) + Conf(0) + Pers(0) + Exposure(0) = 1
        "expected_score": 1,
        "expected_severity": "LOW",
        "expected_escalation": "Normal Monitoring",
    },
    {
        "id": "SYN-002",
        "title": "Phishing Email Campaign with Zero Payload Clicks",
        "incident_type": "Phishing Campaign",
        "business_impact": "Low",
        "affected_assets": 2,
        "confidence": 65.0,
        "persistence": False,
        "data_exposure": False,
        "description": "Mass spoofed email delivered to 2 marketing staff mailboxes. Both recipients reported the email without opening links.",
        "analyst_notes": "Mail filter quarantined related message hashes.",
        # Expected Math: Impact(1) + Assets(0) + Conf(1) + Pers(0) + Exposure(0) = 2
        "expected_score": 2,
        "expected_severity": "LOW",
        "expected_escalation": "Normal Monitoring",
    },
    {
        "id": "SYN-003",
        "title": "Suspicious Scheduled Task on Workstation",
        "incident_type": "Suspicious Execution",
        "business_impact": "Low",
        "affected_assets": 1,
        "confidence": 68.0,
        "persistence": True,
        "data_exposure": False,
        "description": "EDR sensor flagged an unusual cron entry scheduled to run an unverified shell script at system startup.",
        "analyst_notes": "Workstation isolated pending forensic inspection.",
        # Expected Math: Impact(1) + Assets(0) + Conf(1) + Pers(2) + Exposure(0) = 4
        "expected_score": 4,
        "expected_severity": "MEDIUM",
        "expected_escalation": "Security Analyst Review",
    },
    {
        "id": "SYN-004",
        "title": "Marketing Web Server Content Defacement",
        "incident_type": "Unauthorized Modification",
        "business_impact": "Medium",
        "affected_assets": 1,
        "confidence": 94.0,
        "persistence": False,
        "data_exposure": False,
        "description": "Public-facing WordPress marketing blog homepage was altered with unauthorized activist slogans.",
        "analyst_notes": "Content reverted from Git backup; plugin vulnerability under patch review.",
        # Expected Math: Impact(2) + Assets(0) + Conf(3) + Pers(0) + Exposure(0) = 5
        "expected_score": 5,
        "expected_severity": "MEDIUM",
        "expected_escalation": "Security Analyst Review",
    },
    {
        "id": "SYN-005",
        "title": "Lost BitLocker-Encrypted Corporate Laptop",
        "incident_type": "Asset Loss",
        "business_impact": "Low",
        "affected_assets": 1,
        "confidence": 98.0,
        "persistence": False,
        "data_exposure": False,
        "description": "Employee reported company laptop mislaid at airport transit lounge. Drive is fully encrypted with TPM BitLocker.",
        "analyst_notes": "Remote wipe instruction queued in MDM; credentials revoked.",
        # Expected Math: Impact(1) + Assets(0) + Conf(3) + Pers(0) + Exposure(0) = 4
        "expected_score": 4,
        "expected_severity": "MEDIUM",
        "expected_escalation": "Security Analyst Review",
    },
    {
        "id": "SYN-006",
        "title": "DDoS Flurry on Customer Portal Gateway",
        "incident_type": "Denial of Service",
        "business_impact": "Medium",
        "affected_assets": 4,
        "confidence": 88.0,
        "persistence": False,
        "data_exposure": False,
        "description": "Volumetric HTTP flood targeting customer authentication reverse proxies causing sporadic timeouts.",
        "analyst_notes": "Cloudflare rate-limiting and geo-blocking rule activated.",
        # Expected Math: Impact(2) + Assets(1) + Conf(2) + Pers(0) + Exposure(0) = 5
        "expected_score": 5,
        "expected_severity": "MEDIUM",
        "expected_escalation": "Security Analyst Review",
    },
    {
        "id": "SYN-007",
        "title": "Internal Credential Stuffing on Single Sign-On",
        "incident_type": "Credential Stuffing",
        "business_impact": "Medium",
        "affected_assets": 15,
        "confidence": 78.0,
        "persistence": False,
        "data_exposure": False,
        "description": "Anomalous authentication bursts targeting 15 employee accounts from rotating residential proxies.",
        "analyst_notes": "MFA prevented successful unauthorized logins; account passwords reset.",
        # Expected Math: Impact(2) + Assets(2) + Conf(2) + Pers(0) + Exposure(0) = 6
        "expected_score": 6,
        "expected_severity": "HIGH",
        "expected_escalation": "Incident Response Team",
    },
    {
        "id": "SYN-008",
        "title": "Unauthorized Cryptomining Container in Dev Cluster",
        "incident_type": "Malicious Cryptomining",
        "business_impact": "Medium",
        "affected_assets": 8,
        "confidence": 82.0,
        "persistence": True,
        "data_exposure": False,
        "description": "Kubernetes cluster CPU utilization spiked to 98% due to unauthorized Monero mining container deployed in sandbox namespace.",
        "analyst_notes": "Namespace quarantined; kubeconfig RBAC audited.",
        # Expected Math: Impact(2) + Assets(1) + Conf(2) + Pers(2) + Exposure(0) = 7
        "expected_score": 7,
        "expected_severity": "HIGH",
        "expected_escalation": "Incident Response Team",
    },
    {
        "id": "SYN-009",
        "title": "Unauthenticated RCE Zero-Day Alert on Edge Routers",
        "incident_type": "Vulnerability Exposure",
        "business_impact": "Critical",
        "affected_assets": 28,
        "confidence": 45.0,
        "persistence": False,
        "data_exposure": False,
        "description": "CISA alert published for active exploitation of edge gateway hardware firmware across the industry.",
        "analyst_notes": "Firmware hotfix staging underway across 28 edge devices.",
        # Expected Math: Impact(4) + Assets(3) + Conf(0) + Pers(0) + Exposure(0) = 7
        "expected_score": 7,
        "expected_severity": "HIGH",
        "expected_escalation": "Incident Response Team",
    },
    {
        "id": "SYN-010",
        "title": "Insider Data Exfiltration to Personal Cloud Storage",
        "incident_type": "Insider Threat",
        "business_impact": "High",
        "affected_assets": 2,
        "confidence": 85.0,
        "persistence": False,
        "data_exposure": True,
        "description": "Resigning employee observed uploading 1.4 GB archive of proprietary engineering CAD drawings to Mega.nz.",
        "analyst_notes": "DLP trigger confirmed archive contents; account locked and HR/Legal alerted.",
        # Expected Math: Impact(3) + Assets(0) + Conf(2) + Pers(0) + Exposure(3) = 8
        "expected_score": 8,
        "expected_severity": "HIGH",
        "expected_escalation": "Incident Response Team",
    },
    {
        "id": "SYN-011",
        "title": "Active Directory Kerberoasting & Lateral Movement",
        "incident_type": "Privilege Escalation",
        "business_impact": "High",
        "affected_assets": 18,
        "confidence": 88.0,
        "persistence": True,
        "data_exposure": False,
        "description": "SOC detected ticket-granting service (TGS) extraction targeting service accounts with subsequent WMI execution on 18 servers.",
        "analyst_notes": "Tier-0 domain controller isolated from secondary forest.",
        # Expected Math: Impact(3) + Assets(2) + Conf(2) + Pers(2) + Exposure(0) = 9
        "expected_score": 9,
        "expected_severity": "CRITICAL",
        "expected_escalation": "Immediate Escalation",
    },
    {
        "id": "SYN-012",
        "title": "Public S3 Storage Bucket Containing Customer PII",
        "incident_type": "Data Exposure",
        "business_impact": "High",
        "affected_assets": 1,
        "confidence": 95.0,
        "persistence": False,
        "data_exposure": True,
        "description": "Misconfigured cloud storage bucket discovered accessible to the internet containing 45,000 KYC records.",
        "analyst_notes": "Bucket ACL locked down to private; access logs being parsed for unauthorized downloads.",
        # Expected Math: Impact(3) + Assets(0) + Conf(3) + Pers(0) + Exposure(3) = 9
        "expected_score": 9,
        "expected_severity": "CRITICAL",
        "expected_escalation": "Immediate Escalation",
    },
    {
        "id": "SYN-013",
        "title": "C2 Beaconing with Persistent Scheduled Service",
        "incident_type": "Command & Control",
        "business_impact": "High",
        "affected_assets": 7,
        "confidence": 92.0,
        "persistence": True,
        "data_exposure": True,
        "description": "Encrypted Cobalt Strike DNS tunneling detected between finance workstations and foreign dynamic DNS host.",
        "analyst_notes": "Network firewall blocked outbound DNS port 53 to foreign resolvers.",
        # Expected Math: Impact(3) + Assets(1) + Conf(3) + Pers(2) + Exposure(3) = 12
        "expected_score": 12,
        "expected_severity": "CRITICAL",
        "expected_escalation": "Immediate Escalation",
    },
    {
        "id": "SYN-014",
        "title": "Compromised CI/CD Pipeline & Supply Chain Artifact",
        "incident_type": "Supply Chain Attack",
        "business_impact": "Critical",
        "affected_assets": 32,
        "confidence": 86.0,
        "persistence": True,
        "data_exposure": False,
        "description": "Malicious code injected into automated build server Docker images pushed to 32 container hosts.",
        "analyst_notes": "Build runner revoked; container registry images rolled back.",
        # Expected Math: Impact(4) + Assets(3) + Conf(2) + Pers(2) + Exposure(0) = 11
        "expected_score": 11,
        "expected_severity": "CRITICAL",
        "expected_escalation": "Immediate Escalation",
    },
    {
        "id": "SYN-015",
        "title": "Enterprise Ransomware Outbreak with Exfiltration",
        "incident_type": "Ransomware Outbreak",
        "business_impact": "Critical",
        "affected_assets": 45,
        "confidence": 98.0,
        "persistence": True,
        "data_exposure": True,
        "description": "LockBit-variant ransomware encrypted 45 hypervisors with proof-of-exfiltration uploaded to dark web leak blog.",
        "analyst_notes": "Major incident declared. Disaster recovery cold backups initiated.",
        # Expected Math: Impact(4) + Assets(3) + Conf(3) + Pers(2) + Exposure(3) = 15
        "expected_score": 15,
        "expected_severity": "CRITICAL",
        "expected_escalation": "Immediate Escalation",
    },
]


def get_all_scenarios() -> List[Dict[str, Any]]:
    """Returns all 15 synthetic tabletop test scenarios."""
    return SYNTHETIC_INCIDENTS


def get_scenario_by_id(scenario_id: str) -> Dict[str, Any]:
    """Retrieves a single synthetic scenario by its SYN-ID."""
    for s in SYNTHETIC_INCIDENTS:
        if s["id"] == scenario_id:
            return s
    raise KeyError(f"Scenario ID '{scenario_id}' not found.")

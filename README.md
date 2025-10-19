# 🛡️ Vox-Kami — Defensive VoIP Monitoring, Detection & Forensics Platform

## 📖 Overview

**Vox-Kami** is an isolated, reproducible **VoIP defense and forensics platform** designed to capture, detect, and investigate VoIP (SIP/RTP) attacks **within a controlled lab environment**.
It focuses on **defensive monitoring, anomaly detection, and forensic reconstruction** — enabling analysts to **detect, investigate, and remediate** simulated VoIP hijack or tamper attempts.

> ⚠️ **Ethical Notice:**
> All experiments are conducted **only within lab-owned or consenting endpoints**.
> No real-world interception or unauthorized monitoring is performed.

---

## 🎯 Project Objectives

* Develop a **real-time VoIP defense system** capable of detecting registration hijacks and RTP tampering.
* Enable **forensic reconstruction and transcription** of authorized VoIP calls.
* Provide **incident timelines, alerts, and playbooks** to support investigation and remediation.
* Showcase **hands-on network forensics, SIEM integration, and VoIP attack detection** capabilities.

---

## ⚙️ Functional Architecture

### 1. 🕵️ Network Sniffing

* Capture SIP/RTP traffic on lab VLANs or mirrored interfaces.
* Parse and extract:

  * SIP messages: `REGISTER`, `INVITE`, `200 OK`, etc.
  * RTP metadata: SSRC, sequence numbers, timestamps, codecs.
* Store structured metadata (call-ids, endpoints, timestamps) in a searchable datastore (Elasticsearch).

### 2. 🚨 Simulated Attack Detection *(Lab Only)*

* Perform **controlled simulations** of SIP hijack/spoof events using test phones or softphones.
* Detect:

  * Suspicious registrations (unexpected IPs, rapid re-registers, Contact header mismatches).
  * RTP tampering anomalies (SSRC changes, abnormal payloads, jitter, codec mismatches).
* Correlate and raise automated **alerts** in SIEM dashboards for analyst triage.

### 3. 🔍 Call Analysis (With Consent)

* Reconstruct RTP audio streams from PCAPs.
* Convert audio to standard formats (`.wav`, `.mp3`) via `ffmpeg` or `sox`.
* Run **speech-to-text transcription** using open-source models (e.g., **Whisper**).
* Extract and normalize:

  * SIP headers: `From`, `To`, `P-Asserted-Identity`.
  * Transport and signaling metadata (IP, ASN, GeoIP for lab-simulated IPs).
* Generate **tamper-evidence metrics**: packet loss, jitter, sequence gaps, codec anomalies.

### 4. 🧠 Alerting, Triage & Playbooks

* Integrate with **Elasticsearch/Kibana** or **Splunk** for:

  * Alert generation and prioritization.
  * Context enrichment (GeoIP, ASN, device inventory).
  * Analyst triage and visualization.
* Include **incident response playbooks**:

  1. Validate alert
  2. Collect evidence (PCAPs, logs)
  3. Contain (block IPs, quarantine accounts)
  4. Remediate (rotate SIP credentials, enforce SRTP/TLS)
  5. Report findings

---

## ✅ Expected Outcomes

1. **Real-time Detection:**
   Detect and flag suspicious SIP registration or RTP tampering behaviors within the lab.

2. **Audio Reconstruction & Transcription:**
   Reconstruct authorized VoIP calls, extract audio streams, and generate transcripts.

3. **Forensic Timelines & Attribution:**
   Correlate SIP and RTP events to produce incident timelines and identify root causes (e.g., misconfigurations, replay attempts, credential guessing).

4. **Complete Blue-Team Workflow Demonstration:**
   From detection → investigation → containment → remediation → reporting.

---

## 🧩 Tech Stack

| Component             | Technology                                                         |
| --------------------- | ------------------------------------------------------------------ |
| **VoIP Testbed**      | Asterisk / Kamailio / FreeSWITCH + Softphones (Linphone, Zoiper)   |
| **Capture & Parsing** | `tshark`, `Zeek` (SIP/RTP scripts), `Homer`                        |
| **IDS/Detection**     | `Suricata` (VoIP rules) + custom `Python`/`Zeek` detection scripts |
| **Storage & SIEM**    | `Elasticsearch`, `Kibana`, or `Splunk`                             |
| **Forensics & Media** | `rtpbreak`, `rtpdump`, `ffmpeg`, `sox`                             |
| **Speech-to-Text**    | OpenAI Whisper or local STT models                                 |
| **Automation**        | `Ansible` / `Docker Compose` for reproducible lab setup            |
| **Enrichment**        | GeoIP / ASN lookups, local device inventory                        |
| **Visualization**     | `Kibana`, `Grafana`, `NetworkX`, `Gephi`                           |

---

## 🧠 System Workflow

```
[ Softphones / Asterisk Lab ] 
          ↓
 [ Packet Capture (tshark/Zeek) ]
          ↓
 [ Detection (Suricata + Python Scripts) ]
          ↓
 [ Event Storage (Elasticsearch/Splunk) ]
          ↓
 [ Dashboards & Alerts (Kibana/Grafana) ]
          ↓
 [ Forensic Tools (Audio Extraction + STT) ]
          ↓
 [ Analyst Playbooks (Triage → Contain → Report) ]
```

## Folder Structure
```
VOIP-Project/
│
├── README.md                  # Overview, goals, instructions
├── inventory.md               # VM/container details (IPs, roles, OS)
│
├── docs/                      # Documentation and project notes
│   └── project_plan.md        # Detailed plan, phase-wise tasks
│
├── configs/                   # Configuration files for each VM/container
│   ├── sip_server/            # SIP server configs (Asterisk, Kamailio, etc.)
│   ├── siem/                  # SIEM configs (ELK, Wazuh, etc.)
│   ├── packet_capture/        # tcpdump, Wireshark configs, filters
│   └── clients/               # Test client configs (softphones, SIP clients)
│
├── scripts/                   # Automation scripts
│   ├── setup_sip.sh           # Install/setup SIP server
│   ├── setup_siem.sh          # Install/setup SIEM
│   └── packet_capture.sh      # Capture network traffic
│
├── captures/                  # Stored network capture files
│   └── raw_pcap/              # Raw .pcap files from tests
│
└── logs/                      # Logs collected during tests
    └── siem_logs/             # Logs collected by SIEM server

```

## Folder Structure
- `docs/` → Documentation and notes
- `configs/` → Configuration files for each node
- `scripts/` → Automation scripts
- `captures/` → Network capture files
- `logs/` → Logs from SIEM or testing
- `inventory.md` → VM/container inventory

> ⚠️ **Important TIP:**
> Include a .gitkeep file in empty directories so Git tracks them.

## 📦 Deliverables

* 🗂️ **GitHub Repository** containing:

  * Lab deployment scripts (`Docker Compose` / `Ansible`)
  * Detection and parsing scripts (Zeek, Suricata, Python)
  * Sanitized PCAP samples and reconstructed call data
  * Forensics and STT scripts
  * SIEM dashboards and visualization templates
  * Incident report & investigation playbook
  * 🎥 **Demo video:** Alert → Investigation → Remediation workflow

---

## 👥 Target Audience

* **Blue Team / SOC Analysts** — interested in VoIP anomaly detection and forensics.
* **Network Security Engineers** — seeking practical VoIP defense techniques.
* **VoIP Administrators** — validating detection and response capabilities.
* **Recruiters / Hiring Managers** — evaluating hands-on network forensics expertise.

---

## 🧰 Example Use Cases

* Detect SIP registration hijack attempts during controlled simulations.
* Identify RTP stream manipulation or injection in test calls.
* Reconstruct and transcribe authorized test calls for forensic validation.
* Visualize call flows and incident timelines in Kibana or Gephi.

---

## 🚀 Future Enhancements

* Expand to include **TLS/SRTP enforcement automation**.
* Integrate **machine learning models** for anomaly scoring.
* Add **voice biometric attribution** for authorized call validation.
* Build an **interactive incident response dashboard** for analysts.

---

## 🛡️ Team Classification

**Blue Team / Network Security & Forensics Project**
Focus: Passive monitoring, detection engineering, incident response, and VoIP attack remediation in a legal, isolated test environment.

---

## 📚 References

* [Zeek VoIP Analysis Scripts](https://docs.zeek.org/en/current/script-reference/protocols/sip.html)
* [Suricata VoIP Ruleset](https://suricata.io/)
* [Whisper Speech-to-Text Model](https://github.com/openai/whisper)
* [HOMER VoIP Capture Framework](https://www.sipcapture.org/)

---

**Author(s):** *Kishoreraj*
**License:** MIT (for educational and research use only)

---

# Architecture Specification: Autonomous Network Sentinel (NetGuard-Agent)

## 1. Executive Summary
**NetGuard-Agent** is an end-to-end autonomous network security framework designed to ingest packet flow telemetry, isolate anomalies using unsupervised machine learning clustering, and execute programmatically enforced mitigation actions using an LLM-driven agent architecture with explicit policy playbooks.

---

## 2. System Architecture Blueprint

```
+-----------------------------------------------------------------------------------+
|                                 1. Telemetry Ingestion Layer                       |
|  +---------------------------+       +-----------------------------------------+  |
|  | Hugging Face Dataset      |  -->  | Data Preprocessing & Feature Pipeline   |  |
|  | (e.g., abmallick/network) |       | (Scaling, One-Hot, Sliding Window)      |  |
|  +---------------------------+       +-----------------------------------------+  |
+--------------------------------------------------|--------------------------------+
                                                   v
+-----------------------------------------------------------------------------------+
|                                 2. Detection Engine                                |
|  +-----------------------------------------------------------------------------+  |
|  | Unsupervised Clustering Model (DBSCAN / Isolation Forest / K-Means)         |  |
|  | Outliers flagged as suspicious network anomalies                             |  |
|  +-----------------------------------------------------------------------------+  |
+--------------------------------------------------|--------------------------------+
                                                   v
+-----------------------------------------------------------------------------------+
|                                 3. Agentic Mitigation Layer                        |
|  +-----------------------------------------------------------------------------+  |
|  | LangGraph / AG2 Threat Agent                                                |  |
|  |  - Threat Triage & Pattern Classification                                   |  |
|  |  - Policy Mapping & Playbook Engine                                         |  |
|  |    * Playbook A: Port Scan -> Temporary IP Block                            |  |
|  |    * Playbook B: DDoS Flood -> Rate Limit / AWS Security Group              |  |
|  |    * Playbook C: Outbound Anomalies -> Container / Host Isolation           |  |
|  |  - Programmatic Subprocess / SDK Action Execution                           |  |
|  +-----------------------------------------------------------------------------+  |
+--------------------------------------------------|--------------------------------+
                                                   v
+-----------------------------------------------------------------------------------+
|                                 4. Operations & Monitoring                         |
|  +-----------------------------------------------------------------------------+  |
|  | Streamlit Monitoring Dashboard                                              |  |
|  | Real-time cluster visualization & Agent Action Logs                         |  |
|  +-----------------------------------------------------------------------------+  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Detailed Component Specifications

### 3.1 Telemetry Ingestion Layer
* **Data Source:** Hugging Face `datasets` (`abmallick/network-traffic-anomaly`).
* **Pipeline Responsibilities:** Feature Extraction (Source IP, Port, Protocol, Packet Length, Rate) and Normalization (`StandardScaler`).

### 3.2 Unsupervised Anomaly Detection Engine
* **Model Selection:** `DBSCAN` or `IsolationForest`.
* **Logic:** Legitimate traffic forms dense clusters; outliers falling in sparse regions or returned as noise (`-1`) trigger agent triage.

### 3.3 Agentic Mitigation & Policy Engine
* **Orchestrator:** `LangGraph` state graph.
* **Playbook Mapping Matrix:**
  * **Port Scan / Reconnaissance:** Triggers `SecurityPlaybooks.temporary_ip_block()` via local firewall.
  * **High-Volume Flood:** Triggers `SecurityPlaybooks.rate_limit_or_cloud_block()` via `iptables` rate-limiting or AWS EC2 `boto3` security groups.
  * **Suspicious Outbound Traffic:** Triggers `SecurityPlaybooks.isolate_host_or_container()` via Docker network disconnects.

### 3.4 Monitoring & Dashboard Layer
* **UI Engine:** Streamlit & Plotly interactive plots.
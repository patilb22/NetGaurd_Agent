# NetGuard-Agent implementation reflections

## Project summary

NetGuard-Agent is a Python demonstration pipeline for network-flow telemetry: ingest and normalize flows, identify outliers with unsupervised learning, assess selected anomalies, map assessments to mitigation playbooks, and present the workflow in Streamlit. This document records the implemented behavior, screenshot-backed runs, and known limitations. The updated guide describes OpenAI structured output as its example; because this project is being run without an OpenAI key, the implementation uses a local Ollama model instead.

## Implementation by layer

### 1. Telemetry ingestion and preprocessing

`src/netguard/ingestion.py` streams the Hugging Face `abmallick/network-traffic-anomaly` dataset and materializes a bounded sample. It reads source Parquet shards separately to accommodate schema drift, selects configured network-flow numeric features (falling back to safe numeric candidates), converts invalid/infinite values to missing, fills missing values, and scales the feature matrix with `StandardScaler`. Raw columns remain available for triage context. The CLI and Streamlit app both call the reusable ingestion functions.

### 2. Anomaly detection

`src/netguard/detection.py` applies DBSCAN to scaled features; label `-1` is treated as a noise point. The dashboard exposes sample size, `eps`, and `min_samples`, and reports flow count, cluster count, anomaly count, and anomaly rate. DBSCAN outliers are statistical candidates, not confirmed attacks.

### 3. Structured local LLM triage and policy mapping

`src/netguard/agent.py` defines a Pydantic `ThreatAssessment` with five categories (`PORT_SCAN`, `HIGH_VOLUME_FLOOD`, `SUSPICIOUS_OUTBOUND`, `BENIGN_OUTLIER`, `UNKNOWN_ANOMALY`), confidence in `[0, 1]`, rationale, and a constrained playbook ID. A validator enforces the classification-to-playbook mapping. The structured-output chain uses `ChatOllama`, defaulting to `llama3.1:8b`; `NETGUARD_OLLAMA_MODEL` can select another local model. No OpenAI API key is required, but Ollama and the selected model must be installed and running.

The agent derives destination-port counts by source, converts integer-encoded IPv4 values when possible, and infers direction only for private/global endpoint pairs. It also calculates sample-based 99th-percentile packet thresholds when the required columns exist. These rules enrich the prompt; the LLM supplies the assessment. `agent_app` remains a non-HITL triage-and-preview graph for CLI use, while `hitl_agent_app` pauses for an operator decision before execution.

### 4. Policies, playbooks, and HITL controls

`src/netguard/policies.py` maps `PORT_SCAN` to PB-001 temporary source block, `HIGH_VOLUME_FLOOD` to PB-002 rate limit or AWS security-group ingress response, `SUSPICIOUS_OUTBOUND` to PB-003 container isolation, and benign/unknown outcomes to PB-000 log-only.

`src/netguard/playbooks.py` validates IPv4 and Docker targets, uses argument-list subprocess calls with `shell=False`, bounds command durations, and marks firewall rules so rollback can remove the matching rule. Actual host changes require both an approved graph decision and `NETGUARD_ENABLE_PLAYBOOK_EXECUTION=1`; the dashboard defaults to previews. Executable firewall playbooks are limited to Linux. AWS and Docker actions also require valid infrastructure identifiers and available tooling. Timed rollback uses an in-process scheduler, so it is not durable across process shutdowns; production use needs persistent scheduling/checkpointing and operational safeguards.

The HITL graph uses LangGraph's dynamic `interrupt` and an in-memory checkpointer. The operator reviews the structured assessment and preview, then approves or rejects. A human approval alone does not enable system changes when the explicit execution environment flag is unset. In-memory approval state lasts only while the app process remains alive.

### 5. Streamlit operations dashboard

`src/netguard/dashboard.py` provides analysis controls, interactive DBSCAN visualization, per-anomaly selection, local LLM triage, the approval/rejection gate, latest decision display, and downloadable operator decision log. It triages one selected anomaly at a time. `run_dashboard.ps1` starts the app; `run_ingestion.ps1` runs the CLI and accepts row/triage limits.

## Screenshot-backed results

The screenshots are local UI captures. Loading screens are recorded as workflow evidence only, not as completed outcomes.

| Screenshot(s) | Visible result | Interpretation |
| --- | --- | --- |
| `Screenshots/run_2000.png`, `Screenshots/run.png` | Earlier run: 2,000 flows, 13 clusters, 165 anomalies (8.25%); `eps=0.50`, `min_samples=10`. | Early DBSCAN result; noise is a candidate set, not a threat count. |
| `Screenshots/run_2000_unknown_anamoly.png` | Earlier agent output labels visible rows `UNKNOWN_ANOMALY` and logs them for review. | The previous heuristic classifier lacked enough signals for specific categories in that run. |
| `Screenshots/run_5000_eps_0.3_dash2.png` | 5,000 flows, 19 clusters, 436 anomalies (8.72%); `eps=0.30`, `min_samples=10`. | A larger sample and tighter radius produced more noise points; this is not a controlled parameter-only comparison. |
| `Screenshots/run_5000_eps_0.3_dash1.png` | Earlier category chart shows unknown and high-volume-flood outcomes among the triaged subset. | Some records met the earlier flood heuristic; chart labels are not exact enough to report counts confidently. |
| `Screenshots/run_5000_eps_0.3_dash3.png` | Sidebar shows `min_samples=15` alongside prior results. | The image does not establish that analysis was rerun at this setting. |
| `Screenshots/basic_updated_run.png`, `Screenshots/running_analysis_updated.png` | Updated dashboard configured for 2,000 rows, `eps=0.30`, `min_samples=10`; the second image is still loading. | Confirms updated UI controls and that a load was started. The loading image alone is not an outcome. |
| `Screenshots/telemetry_stats_updated.png` | Completed updated analysis: 2,000 flows, 18 clusters, 239 anomalies, 11.95%; `eps=0.30`, `min_samples=10`. | This run flags a larger fraction as DBSCAN noise than the earlier 2,000-row `eps=0.50` run. Both `eps` and implementation/run context differ, so it is not an isolated comparison. |
| `Screenshots/llm_triage_HITL_agent.png`, `Screenshots/llm_triage_HITL_agent_running.png` | Row 41 selected; local Ollama triage starts. The second image captures the model still running. | Evidence of the per-row triage interaction; the spinner is not the model's completed result. |
| `Screenshots/llm_triage_HITL_agent_approval.png` | Row 41 assessment: `BENIGN_OUTLIER`, confidence `0.8`, recommended `PB-000_LOG_ONLY`; the page offers approve/reject. | The assessment is reviewable, but its rationale cites the source label “Benign”; see label-leakage finding below. |
| `Screenshots/llm_triage_HITL_agent_output.png`, `Screenshots/netguard_hitl_decisions.csv` | The decision record has `human_approved=True`, `BENIGN_OUTLIER`, PB-000 and “LOG ONLY”; the dashboard exposes CSV download. | The operator approval/resume path completed. Because PB-000 is log-only, approval resulted in no network change; the UI also states safe demo mode is active. |

## Findings and limitations

1. The updated pipeline connects bounded ingestion, scaling, DBSCAN, structured local-model triage, policy mapping, operator approval, and a recorded decision. The screenshot evidence shows the dashboard completed analysis and completed one approval workflow.
2. In the latest 2,000-row screenshot, DBSCAN reports 239 of 2,000 rows as noise (11.95%) at `eps=0.30` and `min_samples=10`. The earlier 2,000-row run reported 165 (8.25%) at `eps=0.50`; because settings differ, this is not a controlled comparison.
3. The saved row-41 rationale explicitly says the flow “is also labeled as 'Benign'.” `build_triage_context` currently places unrecognized columns into `additional_context`, which appears to pass the dataset target label to the LLM. This is target-label leakage: the BENIGN_OUTLIER result cannot be treated as an independent assessment from telemetry alone. Exclude all ground-truth/label columns from model context before using classifications as evidence or evaluating model quality; then rerun and capture a fresh decision.
4. The latest human-approved decision is benign/log-only. It demonstrates the approval and recording path, not a mitigation command or a network change. The execution flag was disabled in the screenshot.
5. The earlier all-unknown outcomes and later heuristic flood classifications belong to the previous classifier behavior. The new local LLM can return the defined structured categories, but one benign sample does not show that all threat types are detected reliably. Evaluate on labeled holdout data while ensuring labels are never supplied as prompt context.
6. Sample-calibrated thresholds and LLM classifications are demo aids, not validated detection thresholds or a supervised model. DBSCAN parameter changes can materially alter the noise set. Selected anomalies are reviewed one at a time in the dashboard.
7. Although the guide sketches executable playbooks, the actual demo defaults to dry-run and requires explicit operator approval plus an environment opt-in for host-level execution. Before any live use, verify authorization, target selection, rollback behavior, failure handling, durable audit/checkpointing, and deployment-specific network policy.

## Run commands

From the repository root in PowerShell:

```powershell
# Run bounded CLI analysis (adjust sample and model-triage limit as needed)
.\run_ingestion.ps1 -MaxRows 5000

# Start Streamlit when dependencies are already installed
.\run_dashboard.ps1 -SkipInstall
```

The first uncached analysis needs Hugging Face connectivity. Local triage additionally needs Ollama running with the configured model available. Keep `NETGUARD_ENABLE_PLAYBOOK_EXECUTION` unset for the dry-run demo.

## Screenshot evidence index

Earlier evidence:

- `Screenshots/basic.png`
- `Screenshots/run.png`
- `Screenshots/run_2000.png`
- `Screenshots/run_2000_unknown_anamoly.png` (filename spelling preserved)
- `Screenshots/run_5000_eps_0.3_run.png`
- `Screenshots/run_5000_eps_0.3_dash1.png`
- `Screenshots/run_5000_eps_0.3_dash2.png`
- `Screenshots/run_5000_eps_0.3_dash3.png`

Updated dashboard and HITL evidence (2026-10-26):

- `Screenshots/basic_updated_run.png`
- `Screenshots/running_analysis_updated.png` (loading capture)
- `Screenshots/telemetry_stats_updated.png`
- `Screenshots/llm_triage_HITL_agent.png`
- `Screenshots/llm_triage_HITL_agent_running.png` (loading capture)
- `Screenshots/llm_triage_HITL_agent_approval.png`
- `Screenshots/llm_triage_HITL_agent_output.png`
- `Screenshots/netguard_hitl_decisions.csv`

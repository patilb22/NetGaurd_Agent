"""LLM-powered structured triage and dry-run policy previews."""

from __future__ import annotations

import math
import ipaddress
import os
from functools import lru_cache
from typing import Any, Literal, TypedDict

import numpy as np
import pandas as pd
from langchain_core.prompts import ChatPromptTemplate
from langchain_ollama import ChatOllama
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt
from pydantic import BaseModel, Field, model_validator

from src.netguard.playbooks import dispatch_playbook, execute_approved_playbook
from src.netguard.policies import ThreatType


class ThreatAssessment(BaseModel):
    """Validated classification and recommendation from the triage model."""

    threat_classification: Literal[
        "PORT_SCAN",
        "HIGH_VOLUME_FLOOD",
        "SUSPICIOUS_OUTBOUND",
        "BENIGN_OUTLIER",
        "UNKNOWN_ANOMALY",
    ] = Field(description="The best-supported category for this anomalous flow.")
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(
        description=(
            "Brief evidence-based explanation citing telemetry fields. Do not "
            "invent missing values or provide hidden chain-of-thought."
        )
    )
    recommended_playbook: Literal[
        "PB-001_TEMPORARY_IP_BLOCK",
        "PB-002_RATE_LIMIT",
        "PB-003_CONTAINER_ISOLATION",
        "PB-000_LOG_ONLY",
    ]

    @model_validator(mode="after")
    def playbook_matches_classification(self) -> "ThreatAssessment":
        expected = {
            "PORT_SCAN": "PB-001_TEMPORARY_IP_BLOCK",
            "HIGH_VOLUME_FLOOD": "PB-002_RATE_LIMIT",
            "SUSPICIOUS_OUTBOUND": "PB-003_CONTAINER_ISOLATION",
            "BENIGN_OUTLIER": "PB-000_LOG_ONLY",
            "UNKNOWN_ANOMALY": "PB-000_LOG_ONLY",
        }[self.threat_classification]
        if self.recommended_playbook != expected:
            raise ValueError(
                "recommended_playbook must match threat_classification"
            )
        return self


class AgentState(TypedDict, total=False):
    """State passed between LLM triage and policy preview nodes."""

    anomaly_data: dict[str, Any]
    anomaly_index: int
    threat_classification: str
    action_taken: str
    assessment: dict[str, Any]
    human_approved: bool
    approval_note: str
    execution_result: str
    packet_rate_threshold: float
    packet_count_threshold: float


TRIAGE_PROMPT = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            """You are a network security operations analyst. Classify the supplied
network-flow outlier using only the provided telemetry. Return one of the
allowed categories and its matching playbook identifier.

Use these indicators as guidance, not as proof by themselves:
- PORT_SCAN: more than 20 unique destination ports, especially with small packets.
- HIGH_VOLUME_FLOOD: packet rate above 1,000 packets/sec or a strong packet/byte burst.
- SUSPICIOUS_OUTBOUND: long-lived outbound traffic to a public external address.
- BENIGN_OUTLIER: statistical outlier with telemetry that supports normal activity
  and no clear malicious marker.
- UNKNOWN_ANOMALY: evidence is insufficient, conflicting, or required fields are
  missing. Do not infer direction or malicious intent from an IP alone.

Map PORT_SCAN to PB-001_TEMPORARY_IP_BLOCK, HIGH_VOLUME_FLOOD to
PB-002_RATE_LIMIT, SUSPICIOUS_OUTBOUND to PB-003_CONTAINER_ISOLATION, and both
BENIGN_OUTLIER and UNKNOWN_ANOMALY to PB-000_LOG_ONLY. Give a concise explanation
based on observed fields; do not invent telemetry.""",
        ),
        (
            "human",
            """Network flow telemetry context:
Source IP: {src_ip}
Destination IP: {dst_ip}
Destination port: {dst_port}
Unique destination ports for source: {unique_dst_ports}
Flow duration (ms): {flow_duration}
Packet count: {packet_count}
Packet rate (packets/sec): {packet_rate}
Direction: {direction}
Outlier distance/score: {outlier_score}
Additional telemetry: {additional_context}""",
        ),
    ]
)


@lru_cache(maxsize=1)
def create_llm_triage_chain():
    """Create a cached structured-output chain backed by local Ollama."""
    model_name = os.getenv("NETGUARD_OLLAMA_MODEL", "llama3.1:8b")
    try:
        llm = ChatOllama(model=model_name, temperature=0)
    except Exception as exc:
        raise RuntimeError(
            f"Could not initialize Ollama model {model_name!r}. Start Ollama and "
            "confirm that model is available with `ollama list`."
        ) from exc
    return TRIAGE_PROMPT | llm.with_structured_output(ThreatAssessment)


def _first_value(data: dict[str, Any], *keys: str, default: str = "not available") -> Any:
    for key in keys:
        value = data.get(key)
        if value is not None and not (isinstance(value, float) and math.isnan(value)):
            return value
    return default


def build_triage_context(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize dataset-specific telemetry names to the prompt's field names."""
    known = {
        "src_ip", "src ip", "source_ip", "source ip", "dst_ip", "dst ip",
        "destination_ip", "destination ip", "dst_port", "dst port",
        "destination_port", "destination port", "dst_port_count",
        "unique_dst_ports", "unique destination ports", "flow_duration",
        "flow duration", "packet_count", "total_fwd_packets", "tot fwd pkts",
        "total_bwd_packets", "tot bwd pkts", "packet_rate",
        "flow_packets_per_sec", "flow pkts/s", "direction", "outlier_score",
    }
    packet_count = _first_value(data, "packet_count", default=None)
    if packet_count is None:
        packet_count = _number_from(
            data, "total_fwd_packets", "Tot Fwd Pkts"
        ) + _number_from(data, "total_bwd_packets", "Tot Bwd Pkts")
    additional = {
        str(key): value
        for key, value in data.items()
        if str(key).strip().casefold() not in known and not str(key).startswith("__")
    }
    return {
        "src_ip": _first_value(data, "src_ip", "Src IP", "source_ip", "Source IP"),
        "dst_ip": _first_value(data, "dst_ip", "Dst IP", "destination_ip", "Destination IP"),
        "dst_port": _first_value(data, "dst_port", "Dst Port", "destination_port", "Destination Port"),
        "unique_dst_ports": _first_value(
            data, "dst_port_count", "unique_dst_ports", "unique_dst_port_count"
        ),
        "flow_duration": _first_value(data, "flow_duration", "Flow Duration"),
        "packet_count": packet_count,
        "packet_rate": _first_value(
            data, "packet_rate", "flow_packets_per_sec", "Flow Pkts/s"
        ),
        "direction": _first_value(data, "direction", "traffic_direction"),
        "outlier_score": _first_value(data, "outlier_score", "outlier_distance"),
        "additional_context": str(additional) if additional else "none",
    }


def _number_from(data: dict[str, Any], *keys: str) -> float:
    """Read a finite numeric signal from the first available field alias."""
    for key in keys:
        value = data.get(key)
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if math.isfinite(number):
            return number
    return 0.0


def _normalized_column_map(df: pd.DataFrame) -> dict[str, object]:
    """Map punctuation/case-insensitive names to the original DataFrame names."""
    return {
        "".join(character for character in str(column).casefold() if character.isalnum()): column
        for column in df.columns
    }


def _as_ip_address(value: object) -> str | None:
    """Parse dotted IP strings or integer-encoded IPv4 values from the dataset."""
    if value is None or pd.isna(value):
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        try:
            number = float(value)
        except (TypeError, ValueError):
            return None
        if math.isfinite(number) and number.is_integer() and 0 <= number <= 2**32 - 1:
            return str(ipaddress.IPv4Address(int(number)))
        return None


def derive_triage_signals(df: pd.DataFrame) -> pd.DataFrame:
    """Add scan, source-IP, and direction signals when raw endpoints exist.

    Destination-port counts are aggregated per source IP across the loaded
    sample. Direction is inferred only when the source is private and the
    destination is globally routable, or vice versa.
    """
    enriched = df.copy()
    columns = _normalized_column_map(enriched)
    source_column = next(
        (columns[name] for name in ("srcip", "sourceip") if name in columns),
        None,
    )
    destination_column = next(
        (columns[name] for name in ("dstip", "destinationip") if name in columns),
        None,
    )
    destination_port_column = next(
        (columns[name] for name in ("dstport", "destinationport") if name in columns),
        None,
    )

    if source_column is not None:
        enriched["src_ip"] = enriched[source_column].map(_as_ip_address)
    if source_column is not None and destination_port_column is not None:
        enriched["dst_port_count"] = enriched.groupby(source_column, dropna=True)[
            destination_port_column
        ].transform("nunique").fillna(0)

    if source_column is not None and destination_column is not None:
        source_ips = enriched[source_column].map(_as_ip_address)
        destination_ips = enriched[destination_column].map(_as_ip_address)

        def infer_direction(source: str | None, destination: str | None) -> str | None:
            if source is None or destination is None:
                return None
            source_address = ipaddress.ip_address(source)
            destination_address = ipaddress.ip_address(destination)
            if source_address.is_private and destination_address.is_global:
                return "outbound"
            if source_address.is_global and destination_address.is_private:
                return "inbound"
            return None

        enriched["direction"] = [
            infer_direction(source, destination)
            for source, destination in zip(source_ips, destination_ips)
        ]

    return enriched


def calibrate_triage_thresholds(
    df: pd.DataFrame,
    percentile: float = 0.99,
) -> dict[str, float]:
    """Derive fallback volume thresholds from unlabeled telemetry columns.

    Rate values are capped at the guide's 1000 packets/sec threshold: when
    that threshold is above the sample's 99th percentile, the percentile lets
    the demo identify unusually high rates in this dataset sample. These are
    triage heuristics, not validated production thresholds.
    """
    if not 0 < percentile < 1:
        raise ValueError("percentile must be between 0 and 1")

    thresholds: dict[str, float] = {}
    rate_columns = (
        "packet_rate",
        "flow_packets_per_sec",
        "flow_packets/s",
        "Flow Pkts/s",
    )
    rate_column = next((name for name in rate_columns if name in df.columns), None)
    if rate_column is not None:
        rates = pd.to_numeric(df[rate_column], errors="coerce").replace(
            [np.inf, -np.inf], np.nan
        ).dropna()
        if not rates.empty:
            sample_threshold = float(rates.quantile(percentile))
            if sample_threshold > 0:
                thresholds["packet_rate_threshold"] = min(1000.0, sample_threshold)

    count_columns = [
        name
        for name in (
            "total_fwd_packets",
            "total_bwd_packets",
            "Tot Fwd Pkts",
            "Tot Bwd Pkts",
        )
        if name in df.columns
    ]
    if count_columns:
        packet_counts = (
            df[count_columns]
            .apply(pd.to_numeric, errors="coerce")
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0)
            .sum(axis=1)
        )
        if not packet_counts.empty:
            count_threshold = float(packet_counts.quantile(percentile))
            if count_threshold > 0:
                thresholds["packet_count_threshold"] = count_threshold

    return thresholds


def triage_node(state: AgentState) -> dict[str, Any]:
    """Use the structured-output LLM to assess one anomalous flow."""
    data = state.get("anomaly_data") or {}
    assessment = create_llm_triage_chain().invoke(build_triage_context(data))
    assessment_data = assessment.model_dump()
    return {
        "assessment": assessment_data,
        "threat_classification": assessment_data["threat_classification"],
    }


def policy_execution_node(state: AgentState) -> dict[str, str]:
    """Preview the playbook recommended by triage; this node is dry-run only."""
    assessment = state.get("assessment") or {}
    threat = assessment.get(
        "threat_classification",
        state.get("threat_classification", ThreatType.UNKNOWN_ANOMALY.value),
    )
    anomaly_data = state.get("anomaly_data") or {}
    try:
        action = dispatch_playbook(threat, anomaly_data)
    except ValueError as exc:
        # Invalid or missing infrastructure identifiers should be visible in
        # the agent log, not cause the whole batch to stop.
        action = f"PLAYBOOK NOT RUN: invalid input: {exc}"
    return {"action_taken": action}


def approval_gate_node(state: AgentState) -> dict[str, Any]:
    """Pause the HITL graph and require an explicit operator decision."""
    assessment = state.get("assessment") or {}
    decision = interrupt(
        {
            "kind": "mitigation_approval",
            "anomaly_index": state.get("anomaly_index"),
            "assessment": assessment,
            "source_ip": (state.get("anomaly_data") or {}).get("src_ip"),
            "message": "Review the assessment and approve or reject the proposed action.",
        }
    )
    if isinstance(decision, bool):
        approved, note = decision, ""
    elif isinstance(decision, dict):
        approved = decision.get("approved") is True
        raw_note = decision.get("note", "")
        note = raw_note[:1000] if isinstance(raw_note, str) else ""
    else:
        approved, note = False, "Invalid approval response; treated as rejection."
    return {"human_approved": approved, "approval_note": note}


def safe_execution_node(state: AgentState) -> dict[str, str]:
    """Execute only the approved recommendation; playbooks default to dry-run."""
    assessment = state.get("assessment") or {}
    playbook_id = str(assessment.get("recommended_playbook", "PB-000_LOG_ONLY"))
    try:
        result = execute_approved_playbook(
            playbook_id,
            state.get("anomaly_data") or {},
            approved=state.get("human_approved") is True,
        )
    except Exception as exc:
        result = f"EXECUTION FAILED: {exc}"
    return {"execution_result": result, "action_taken": result}


def build_agent_graph():
    """Build the LLM triage -> dry-run playbook preview graph."""
    builder = StateGraph(AgentState)
    builder.add_node("triage", triage_node)
    builder.add_node("execute_policy", policy_execution_node)
    builder.add_edge(START, "triage")
    builder.add_edge("triage", "execute_policy")
    builder.add_edge("execute_policy", END)
    return builder.compile()


agent_app = build_agent_graph()


def build_hitl_agent_graph(checkpointer: InMemorySaver | None = None):
    """Build a checkpointed triage -> approval interrupt -> execution graph."""
    builder = StateGraph(AgentState)
    builder.add_node("triage", triage_node)
    builder.add_node("approval_gate", approval_gate_node)
    builder.add_node("execute_playbook", safe_execution_node)
    builder.add_edge(START, "triage")
    builder.add_edge("triage", "approval_gate")
    builder.add_edge("approval_gate", "execute_playbook")
    builder.add_edge("execute_playbook", END)
    return builder.compile(checkpointer=checkpointer or InMemorySaver())


# In-memory checkpointing persists pending approvals for this Python process.
# Use a durable database checkpointer before relying on approvals across restarts.
hitl_agent_app = build_hitl_agent_graph()


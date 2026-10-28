"""Streamlit operations dashboard with local LLM triage and HITL approval."""

from __future__ import annotations

import os
import uuid

import pandas as pd
import plotly.express as px
import streamlit as st
from langgraph.types import Command

from src.netguard.agent import derive_triage_signals, hitl_agent_app
from src.netguard.detection import detect_anomalies
from src.netguard.ingestion import load_telemetry, preprocess_telemetry
from src.netguard.playbooks import dispatch_playbook

st.set_page_config(
    page_title="NetGuard-Agent SOC",
    page_icon="🛡️",
    layout="wide",
)


@st.cache_data(show_spinner=False)
def analyze_telemetry(
    max_rows: int,
    eps: float,
    min_samples: int,
) -> tuple[pd.DataFrame, object, object, object, list[str], pd.DataFrame]:
    """Load, preprocess, detect anomalies, and prepare endpoint context."""
    df = load_telemetry(max_rows=max_rows)
    _, X_scaled, scaler = preprocess_telemetry(df)
    labels, anomaly_indices = detect_anomalies(
        X_scaled,
        eps=eps,
        min_samples=min_samples,
    )
    triage_df = derive_triage_signals(df)
    return df, X_scaled, labels, anomaly_indices, list(scaler.feature_names_in_), triage_df


def _thread_config(thread_id: str) -> dict[str, dict[str, str]]:
    return {"configurable": {"thread_id": thread_id}}


def _record_result(row_index: int, state: dict[str, object]) -> dict[str, object]:
    assessment = state.get("assessment") or {}
    return {
        "row_index": row_index,
        "threat_classification": assessment.get("threat_classification", "UNKNOWN_ANOMALY"),
        "confidence_score": assessment.get("confidence_score"),
        "reasoning": assessment.get("reasoning", ""),
        "recommended_playbook": assessment.get("recommended_playbook", "PB-000_LOG_ONLY"),
        "human_approved": state.get("human_approved", False),
        "action_taken": state.get("execution_result", ""),
    }


def main() -> None:
    st.title("NetGuard-Agent: Autonomous Security Operations Center")
    st.caption(
        "Network-flow anomaly detection, local Ollama triage, and operator-approved playbook previews."
    )

    with st.sidebar:
        st.header("Analysis settings")
        max_rows = st.number_input(
            "Rows to load",
            min_value=100,
            max_value=20_000,
            value=5_000,
            step=500,
            help="The Hugging Face dataset is streamed and sampled across its source files.",
        )
        eps = st.number_input(
            "DBSCAN eps",
            min_value=0.01,
            max_value=5.0,
            value=0.5,
            step=0.05,
            help="Maximum scaled-feature distance between neighboring samples.",
        )
        min_samples = st.number_input(
            "DBSCAN min_samples",
            min_value=2,
            max_value=100,
            value=10,
            step=1,
        )
        run_clicked = st.button(
            "Load data and analyze", type="primary", use_container_width=True
        )

    if run_clicked:
        try:
            with st.spinner("Loading telemetry and running DBSCAN..."):
                st.session_state["netguard_analysis"] = analyze_telemetry(
                    int(max_rows), float(eps), int(min_samples)
                )
                st.session_state["netguard_settings"] = (
                    int(max_rows), float(eps), int(min_samples)
                )
                st.session_state["netguard_hitl_history"] = []
                st.session_state.pop("netguard_pending_thread", None)
                st.session_state.pop("netguard_last_result", None)
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
            st.info(
                "Check the terminal for details and confirm Hugging Face is reachable."
            )

    if "netguard_analysis" not in st.session_state:
        st.info("Choose analysis settings, then click **Load data and analyze** to begin.")
        st.caption("The first run needs Hugging Face connectivity. Local triage uses Ollama; no OpenAI key is needed.")
        return

    df, X_scaled, labels, anomaly_indices, feature_names, triage_df = st.session_state[
        "netguard_analysis"
    ]
    previous_settings = st.session_state.get("netguard_settings")
    current_settings = (int(max_rows), float(eps), int(min_samples))
    if current_settings != previous_settings:
        st.warning("Settings changed. Click **Load data and analyze** to refresh these results.")

    cluster_count = len(set(labels) - {-1})
    anomaly_rate = len(anomaly_indices) / len(df) * 100 if len(df) else 0.0
    metric_cols = st.columns(4)
    metric_cols[0].metric("Flows analyzed", f"{len(df):,}")
    metric_cols[1].metric("Clusters", f"{cluster_count:,}")
    metric_cols[2].metric("Anomalies", f"{len(anomaly_indices):,}")
    metric_cols[3].metric("Anomaly rate", f"{anomaly_rate:.2f}%")

    st.header("1. Telemetry anomaly detection")
    if feature_names:
        x_col, y_col = st.columns(2)
        x_feature = x_col.selectbox("X-axis feature", feature_names, index=0)
        y_default = 1 if len(feature_names) > 1 else 0
        y_feature = y_col.selectbox("Y-axis feature", feature_names, index=y_default)

        history = st.session_state.get("netguard_hitl_history", [])
        result_by_index = {
            int(record["row_index"]): str(record["threat_classification"])
            for record in history
        }
        chart_data = pd.DataFrame(
            {
                "row_index": range(len(df)),
                "x": X_scaled[:, feature_names.index(x_feature)],
                "y": X_scaled[:, feature_names.index(y_feature)],
                "cluster_id": labels,
                "is_anomaly": labels == -1,
            }
        )
        chart_data["classification"] = [
            result_by_index.get(index, "Awaiting triage") if is_anomaly else "Clustered flow"
            for index, is_anomaly in zip(
                chart_data["row_index"], chart_data["is_anomaly"]
            )
        ]
        chart_data["cluster_id"] = chart_data["cluster_id"].map(
            lambda value: "Noise (-1)" if value == -1 else f"Cluster {value}"
        )
        cluster_names = sorted(
            (name for name in chart_data["cluster_id"].unique() if name != "Noise (-1)"),
            key=lambda name: int(name.removeprefix("Cluster ")),
        )
        cluster_colors = {
            name: px.colors.qualitative.Dark24[index % len(px.colors.qualitative.Dark24)]
            for index, name in enumerate(cluster_names)
        }
        cluster_colors["Noise (-1)"] = "#e45756"
        fig = px.scatter(
            chart_data,
            x="x",
            y="y",
            color="cluster_id",
            symbol="is_anomaly",
            hover_data=["row_index", "classification", "is_anomaly"],
            labels={"x": x_feature, "y": y_feature, "cluster_id": "DBSCAN cluster"},
            color_discrete_map=cluster_colors,
            title="Scaled flow features and DBSCAN noise points",
        )
        fig.update_layout(height=560, legend_title_text="DBSCAN cluster")
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("No numeric feature columns are available to plot.")

    st.header("2. LLM triage and human approval")
    execution_enabled = os.getenv("NETGUARD_ENABLE_PLAYBOOK_EXECUTION", "").casefold() in {
        "1", "true", "yes"
    }
    if execution_enabled:
        st.warning("Executable playbooks are enabled. Approved actions can change a Linux host.")
    else:
        st.info("Safe demo mode: approved actions show a dry-run preview; no system changes are enabled.")

    pending_thread = st.session_state.get("netguard_pending_thread")
    pending_snapshot = None
    if pending_thread:
        pending_snapshot = hitl_agent_app.get_state(_thread_config(pending_thread))

    if len(anomaly_indices) == 0:
        st.info("DBSCAN returned no anomalous flows for this sample.")
    elif pending_snapshot and pending_snapshot.next:
        pending_values = pending_snapshot.values
        pending_row_index = int(pending_values.get("anomaly_index", anomaly_indices[0]))
        st.caption(f"Pending operator review for detected anomaly row {pending_row_index}.")
        assessment = pending_values.get("assessment", {})
        anomaly_data = pending_values.get("anomaly_data", {})
        st.warning("Review this assessment before deciding whether to approve the playbook.")
        st.json(
            {
                "Threat classification": assessment.get("threat_classification"),
                "Confidence score": assessment.get("confidence_score"),
                "Reasoning": assessment.get("reasoning"),
                "Recommended playbook": assessment.get("recommended_playbook"),
            }
        )
        try:
            preview = dispatch_playbook(
                assessment.get("threat_classification", "UNKNOWN_ANOMALY"),
                anomaly_data,
            )
        except (TypeError, ValueError) as exc:
            preview = f"PLAYBOOK NOT RUN: {exc}"
        st.text_area("Playbook preview", value=preview, height=100, disabled=True)

        approve_col, reject_col = st.columns(2)
        config = _thread_config(pending_thread)
        with approve_col:
            if st.button("Approve and run playbook", type="primary", use_container_width=True):
                try:
                    final_state = hitl_agent_app.invoke(
                        Command(resume={"approved": True}), config
                    )
                    record = _record_result(pending_row_index, final_state)
                    st.session_state["netguard_hitl_history"].append(record)
                    st.session_state["netguard_last_result"] = record
                    st.session_state.pop("netguard_pending_thread", None)
                    st.rerun()
                except Exception as exc:
                    st.error(f"Could not resume approved playbook: {exc}")
        with reject_col:
            if st.button("Reject proposal", use_container_width=True):
                try:
                    final_state = hitl_agent_app.invoke(
                        Command(resume={"approved": False}), config
                    )
                    record = _record_result(pending_row_index, final_state)
                    st.session_state["netguard_hitl_history"].append(record)
                    st.session_state["netguard_last_result"] = record
                    st.session_state.pop("netguard_pending_thread", None)
                    st.rerun()
                except Exception as exc:
                    st.error(f"Could not resume rejected proposal: {exc}")
    else:
        available_indices = [int(index) for index in anomaly_indices]
        selected_row = st.selectbox(
            "Detected anomaly row to triage",
            options=available_indices,
            format_func=lambda index: f"Row {index}",
        )
        st.dataframe(
            triage_df.iloc[[selected_row]],
            use_container_width=True,
            hide_index=True,
        )
        if st.button("Run local LLM triage", type="primary"):
            thread_id = uuid.uuid4().hex
            try:
                with st.spinner(
                    f"Asking local Ollama model {os.getenv('NETGUARD_OLLAMA_MODEL', 'llama3.1:8b')} to assess row {selected_row}..."
                ):
                    hitl_agent_app.invoke(
                        {
                            "anomaly_index": int(selected_row),
                            "anomaly_data": triage_df.iloc[int(selected_row)].to_dict(),
                        },
                        _thread_config(thread_id),
                    )
                st.session_state["netguard_pending_thread"] = thread_id
                st.rerun()
            except Exception as exc:
                st.error(f"Triage failed: {exc}")
                st.info("Confirm Ollama is running and the selected model is available with `ollama list`.")

    last_result = st.session_state.get("netguard_last_result")
    if last_result:
        st.subheader("Most recent decision")
        st.write(
            f"Row {last_result['row_index']}: **{last_result['threat_classification']}** — "
            f"{last_result['action_taken']}"
        )

    history = st.session_state.get("netguard_hitl_history", [])
    if history:
        st.subheader("Operator decision log")
        st.dataframe(pd.DataFrame(history), use_container_width=True, hide_index=True)
        st.download_button(
            "Download decision log (CSV)",
            data=pd.DataFrame(history).to_csv(index=False).encode("utf-8"),
            file_name="netguard_hitl_decisions.csv",
            mime="text/csv",
        )

    st.caption(
        "Triage uses a local Ollama model. A human must approve each recommendation. "
        "System-level execution is disabled unless explicitly enabled in the environment."
    )


if __name__ == "__main__":
    main()

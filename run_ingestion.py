from src.netguard.ingestion import load_and_preprocess
from src.netguard.detection import detect_anomalies
import argparse

from src.netguard.agent import (
    agent_app,
    calibrate_triage_thresholds,
    derive_triage_signals,
)


def main(max_rows: int = 5000, max_agent_rows: int = 1):
    df, X_scaled = load_and_preprocess(max_rows=max_rows)
    labels, anomaly_indices = detect_anomalies(X_scaled)
    triage_df = derive_triage_signals(df)
    triage_thresholds = calibrate_triage_thresholds(triage_df)

    cluster_ids = set(labels) - {-1}

    print(f"Rows and columns: {df.shape}")
    print(f"Scaled feature shape: {X_scaled.shape}")
    print(f"Clusters found (excluding noise): {len(cluster_ids)}")
    print(f"Anomalies detected: {len(anomaly_indices)}")
    print(f"Anomaly row indices: {anomaly_indices[:20].tolist()}")
    if triage_thresholds:
        print(f"Sample-calibrated triage thresholds: {triage_thresholds}")

    if len(anomaly_indices) and max_agent_rows:
        print(f"\nLocal LLM triage and playbook previews (up to {max_agent_rows} anomalies):")
        for anomaly_index in anomaly_indices[:max_agent_rows]:
            row_index = int(anomaly_index)
            result = agent_app.invoke(
                {
                    "anomaly_index": row_index,
                    "anomaly_data": triage_df.iloc[row_index].to_dict(),
                    **triage_thresholds,
                }
            )
            print(
                f"Row {row_index}: {result['threat_classification']} "
                f"(confidence {result['assessment']['confidence_score']:.2f}; "
                f"playbook {result['assessment']['recommended_playbook']})"
            )
            print(f"  Rationale: {result['assessment']['reasoning']}")
            print(f"  Preview: {result['action_taken']}")
    elif len(anomaly_indices):
        print("\nLLM triage skipped (--max-agent-rows 0).")
    print("\nSample rows:")
    print(df.head())

    print("\nFirst scaled feature rows:")
    print(X_scaled[:5])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run NetGuard telemetry detection and triage.")
    parser.add_argument(
        "--max-rows",
        type=int,
        default=5000,
        help="Maximum number of streamed dataset rows to process (default: 5000).",
    )
    parser.add_argument(
        "--max-agent-rows",
        type=int,
        default=1,
        help="Maximum anomalies to send to the local LLM (default: 1).",
    )
    args = parser.parse_args()
    if args.max_agent_rows < 0:
        parser.error("--max-agent-rows must be zero or greater")
    main(max_rows=args.max_rows, max_agent_rows=args.max_agent_rows)

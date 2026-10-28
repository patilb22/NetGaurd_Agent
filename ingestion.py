"""Load and preprocess network-flow telemetry.

The Hugging Face dataset contains over 16 million rows, so ingestion streams a
bounded sample by default. Pass ``max_rows=None`` to request the full split.
"""

from __future__ import annotations

from collections.abc import Iterable
from itertools import islice
import math
import re

import numpy as np
import pandas as pd
from datasets import load_dataset
from huggingface_hub import HfApi, hf_hub_url
from sklearn.preprocessing import StandardScaler

DATASET_ID = "abmallick/network-traffic-anomaly"
DEFAULT_FEATURE_CANDIDATES = (
    "flow_duration",
    "packet_length",
    "packet_rate",
    "total_fwd_packets",
    "total_bwd_packets",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",
    "packet_length_mean",
    "packet_length_std",
    "iat_mean",
    "iat_std",
    # These may exist in some dataset revisions, but are not listed on every
    # schema published for this dataset.
    "src_port",
    "dst_port",
    # Column names in the source Parquet files (CICFlowMeter abbreviations).
    "Flow Duration",
    "Tot Fwd Pkts",
    "Tot Bwd Pkts",
    "Flow Byts/s",
    "Flow Pkts/s",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Src Port",
    "Dst Port",
    "Protocol",
)


def _load_source_shard_sample(
    dataset_id: str,
    max_rows: int | None,
) -> list[dict[str, object]] | None:
    """Read source Parquet shards independently to tolerate schema drift."""
    repo_files = HfApi().list_repo_files(repo_id=dataset_id, repo_type="dataset")
    shard_files = sorted(
        (
            filename
            for filename in repo_files
            if re.fullmatch(r"logs-parquet_part\d+\.parquet", filename)
        ),
        key=lambda filename: int(re.search(r"part(\d+)", filename).group(1)),
    )
    if not shard_files:
        return None

    per_shard_limit = (
        None if max_rows is None else math.ceil(max_rows / len(shard_files))
    )
    records: list[dict[str, object]] = []
    for filename in shard_files:
        shard = load_dataset(
            "parquet",
            data_files=hf_hub_url(
                repo_id=dataset_id,
                filename=filename,
                repo_type="dataset",
            ),
            split="train",
            streaming=True,
        )
        if per_shard_limit is not None:
            records.extend(islice(shard, per_shard_limit))
        else:
            records.extend(shard)
    return records if max_rows is None else records[:max_rows]


def load_telemetry(
    dataset_id: str = DATASET_ID,
    split: str = "train",
    max_rows: int | None = 100000,
) -> pd.DataFrame:
    """Stream a Hugging Face split into a DataFrame.

    ``max_rows`` bounds memory use for app/demo runs. Set it to ``None`` to
    iterate the complete split (which is large and can take substantial time).
    """
    if max_rows is not None and max_rows <= 0:
        raise ValueError("max_rows must be a positive integer or None")

    rows: Iterable[dict[str, object]]
    if dataset_id == DATASET_ID and split == "train":
        # The repository's Parquet files do not share an identical schema.
        # Loading the whole HF split makes datasets cast every shard to the
        # first shard's schema and fails; loading each source shard separately
        # lets pandas union their columns and fill missing values.
        shard_rows = _load_source_shard_sample(dataset_id, max_rows)
        if shard_rows is not None:
            rows = shard_rows
        else:
            dataset = load_dataset(dataset_id, split=split, streaming=True)
            if max_rows is not None:
                dataset = dataset.shuffle(seed=42, buffer_size=10_000)
            rows = dataset if max_rows is None else islice(dataset, max_rows)
    else:
        dataset = load_dataset(dataset_id, split=split, streaming=True)
        if max_rows is not None:
            dataset = dataset.shuffle(seed=42, buffer_size=10_000)
        rows = dataset if max_rows is None else islice(dataset, max_rows)
    # IterableDataset does not implement __len__, which pandas may request
    # when it receives the stream directly. Materialize only the requested
    # number of rows before building the DataFrame.
    df = pd.DataFrame.from_records(list(rows))
    if df.empty:
        raise ValueError(f"Dataset {dataset_id!r} split {split!r} returned no rows")
    return df


def select_numeric_features(
    df: pd.DataFrame,
    feature_candidates: Iterable[str] = DEFAULT_FEATURE_CANDIDATES,
) -> pd.DataFrame:
    """Return available, numeric flow features in requested candidate order."""
    selected = [name for name in feature_candidates if name in df.columns]
    if not selected:
        # Dataset revisions can rename or omit the documented feature fields.
        # In that case use the numeric telemetry columns available at runtime,
        # while preventing labels and bookkeeping fields from entering models.
        excluded = {
            "label",
            "attack_type",
            "split",
            "id",
            "index",
            "__index_level_0__",
            "flow id",
            "src ip",
            "dst ip",
        }
        selected = [
            name
            for name in df.select_dtypes(include=[np.number]).columns
            if str(name).strip().casefold() not in excluded
        ]
    if not selected:
        raise ValueError(
            "No numeric telemetry features could be identified. "
            f"Available columns: {', '.join(map(str, df.columns))}"
        )

    features = df.loc[:, selected].apply(pd.to_numeric, errors="coerce")
    # Infinite values cannot be scaled; treat them as missing measurements.
    features = features.replace([np.inf, -np.inf], np.nan)
    # Median imputation is robust to skewed flow measurements; all-null columns
    # become zero so StandardScaler still receives finite input.
    medians = features.median()
    return features.fillna(medians).fillna(0.0)


def preprocess_telemetry(
    df: pd.DataFrame,
    feature_candidates: Iterable[str] = DEFAULT_FEATURE_CANDIDATES,
) -> tuple[pd.DataFrame, np.ndarray, StandardScaler]:
    """Prepare features and fit a scaler; return raw data, scaled matrix, scaler."""
    features = select_numeric_features(df, feature_candidates)
    scaler = StandardScaler()
    scaled = scaler.fit_transform(features)
    return df, scaled, scaler


def load_and_preprocess(
    dataset_id: str = DATASET_ID,
    split: str = "train",
    max_rows: int | None = 100000,
    feature_candidates: Iterable[str] = DEFAULT_FEATURE_CANDIDATES,
) -> tuple[pd.DataFrame, np.ndarray]:
    """Convenience API matching the implementation guide's original example."""
    df = load_telemetry(dataset_id=dataset_id, split=split, max_rows=max_rows)
    raw_df, scaled, _ = preprocess_telemetry(df, feature_candidates)
    return raw_df, scaled


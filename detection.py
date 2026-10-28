"""Unsupervised anomaly detection for preprocessed network flows."""

from __future__ import annotations

import numpy as np
from sklearn.cluster import DBSCAN


def detect_anomalies(
    X_scaled: np.ndarray,
    eps: float = 0.5,
    min_samples: int = 10,
) -> tuple[np.ndarray, np.ndarray]:
    """Cluster scaled flow features and return labels and anomaly row indices.

    DBSCAN assigns ``-1`` to samples it considers noise. Those row positions
    are returned as ``anomaly_indices`` for downstream triage and inspection.
    The model is fitted only to the supplied feature matrix; dataset labels are
    neither required nor used.
    """
    if eps <= 0:
        raise ValueError("eps must be greater than 0")
    if min_samples < 1:
        raise ValueError("min_samples must be at least 1")

    features = np.asarray(X_scaled, dtype=float)
    if features.ndim != 2:
        raise ValueError(
            f"X_scaled must be a 2D array; received {features.ndim} dimensions"
        )
    if features.shape[0] == 0:
        raise ValueError("X_scaled must contain at least one row")
    if features.shape[1] == 0:
        raise ValueError("X_scaled must contain at least one feature")
    if not np.isfinite(features).all():
        raise ValueError("X_scaled contains NaN or infinite values")

    model = DBSCAN(eps=eps, min_samples=min_samples)
    labels = model.fit_predict(features)
    anomaly_indices = np.flatnonzero(labels == -1)
    return labels, anomaly_indices


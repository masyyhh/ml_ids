"""Feature engineering, correlation analysis, SelectKBest (chi2), and RF importance."""

from pathlib import Path
from typing import Any, Dict, List, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.preprocessing import MinMaxScaler

from src.utils.config import MODELS_DIR, PROCESSED_DATA_DIR
from src.utils.logger import get_logger, timer_decorator

logger = get_logger(__name__)

ENGINEERED_FEATURES: List[str] = [
    "bytes_ratio",
    "packet_rate",
    "connection_density",
]


def engineer_domain_features(df: pd.DataFrame) -> pd.DataFrame:
    """Create flow-level domain features: bytes_ratio, packet_rate, connection_density.

    Args:
        df: DataFrame containing raw or harmonized flow features.

    Returns:
        DataFrame with engineered features added.
    """
    out = df.copy()

    def _col(name: str) -> pd.Series:
        if name in out.columns:
            return pd.to_numeric(out[name], errors="coerce").fillna(0.0).clip(lower=0.0)
        return pd.Series(0.0, index=out.index, dtype=float)

    src_b = _col("src_bytes")
    dst_b = _col("dst_bytes")
    duration = _col("duration")
    count = _col("count")
    srv_count = _col("srv_count")
    dst_host_cnt = _col("dst_host_count")
    dst_host_srv_cnt = _col("dst_host_srv_count")
    same_srv = _col("same_srv_rate")

    # 1. Bytes ratio: ratio of source to destination bytes (log-stabilized)
    out["bytes_ratio"] = np.log1p(src_b) / (np.log1p(dst_b) + 1.0)

    # 2. Packet rate: connection & service packet intensity per unit duration
    out["packet_rate"] = (count + srv_count) / (duration + 1.0)

    # 3. Connection density: concentration of service connections on destination host
    out["connection_density"] = ((dst_host_srv_cnt + 1.0) / (dst_host_cnt + 1.0)) * (same_srv + 0.01)

    return out


@timer_decorator
def perform_correlation_analysis(
    X: pd.DataFrame, threshold: float = 0.95
) -> Tuple[pd.DataFrame, List[str]]:
    """Compute feature correlation matrix and identify highly collinear features.

    Args:
        X: Feature DataFrame (numeric).
        threshold: Absolute Pearson correlation threshold above which features are flagged.

    Returns:
        Tuple of (correlation_matrix DataFrame, list of high-correlation feature pairs).
    """
    corr_matrix = X.corr().fillna(0.0)
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    high_corr_features = [column for column in upper.columns if any(upper[column].abs() > threshold)]
    logger.info(
        "Correlation analysis complete: %d features analyzed, %d features have |r| > %.2f",
        X.shape[1],
        len(high_corr_features),
        threshold,
    )
    corr_matrix.to_csv(PROCESSED_DATA_DIR / "correlation_matrix.csv")
    return corr_matrix, high_corr_features


@timer_decorator
def select_features_hybrid(
    X_train: pd.DataFrame,
    y_train: np.ndarray,
    top_k: int = 25,
    random_state: int = 42,
) -> Tuple[List[str], Dict[str, Any]]:
    """Select optimal features using SelectKBest (chi2) and Random Forest importance.

    Ensures critical flow & engineered features are retained while ranking all features.

    Args:
        X_train: Training feature DataFrame.
        y_train: Training target labels (integer encoded).
        top_k: Number of top features to select.
        random_state: Random seed for reproducibility.

    Returns:
        Tuple of (selected_feature_names, selection_report_dict).
    """
    feature_names = list(X_train.columns)
    k = min(top_k, len(feature_names))

    # 1. SelectKBest with chi2 (requires non-negative values via MinMaxScaler)
    mm_scaler = MinMaxScaler()
    X_non_neg = mm_scaler.fit_transform(X_train)
    chi2_selector = SelectKBest(score_func=chi2, k=k)
    chi2_selector.fit(X_non_neg, y_train)
    chi2_scores = np.nan_to_num(chi2_selector.scores_, nan=0.0, posinf=0.0, neginf=0.0)

    # 2. Random Forest Feature Importance
    rf_selector = RandomForestClassifier(
        n_estimators=60, max_depth=14, random_state=random_state, n_jobs=-1
    )
    rf_selector.fit(X_train, y_train)
    rf_importances = rf_selector.feature_importances_

    # Normalize both scores to [0, 1] and compute hybrid rank
    chi2_norm = chi2_scores / (chi2_scores.max() + 1e-12)
    rf_norm = rf_importances / (rf_importances.max() + 1e-12)
    combined_score = 0.45 * chi2_norm + 0.55 * rf_norm

    ranking_df = pd.DataFrame(
        {
            "feature": feature_names,
            "chi2_score": np.round(chi2_scores, 4),
            "chi2_normalized": np.round(chi2_norm, 4),
            "rf_importance": np.round(rf_importances, 5),
            "combined_score": np.round(combined_score, 5),
        }
    ).sort_values("combined_score", ascending=False)

    selected_features = list(ranking_df.head(k)["feature"].values)

    # Guarantee that core flow, host compromise & engineered features are present in selected_features
    mandatory_features = [
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "bytes_ratio",
        "packet_rate",
        "connection_density",
        "hot",
        "root_shell",
    ]
    for feat in mandatory_features:
        if feat in feature_names and feat not in selected_features:
            selected_features[-1] = feat
            # Re-deduplicate preserving order
            selected_features = list(dict.fromkeys(selected_features))

    ranking_df.to_csv(PROCESSED_DATA_DIR / "feature_importance_ranking.csv", index=False)

    report = {
        "selected_features": selected_features,
        "ranking": ranking_df.to_dict(orient="records"),
        "top_15_features": ranking_df.head(15).to_dict(orient="records"),
    }

    joblib.dump(selected_features, MODELS_DIR / "feature_list.pkl")
    joblib.dump(report, MODELS_DIR / "feature_selection_report.pkl")
    logger.info("Saved %d selected features to %s", len(selected_features), MODELS_DIR / "feature_list.pkl")

    return selected_features, report

"""Data cleaning, categorical encoding, scaling, label mapping, splitting, and SMOTE."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import BorderlineSMOTE, SMOTE
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler, StandardScaler

from src.features.feature_engineering import (
    engineer_domain_features,
    perform_correlation_analysis,
    select_features_hybrid,
)
from src.preprocessing.download_data import (
    ensure_datasets,
    harmonize_cicids2017_to_nsl_schema,
)
from src.utils.config import (
    ATTACK_CATEGORY_MAP,
    CATEGORICAL_FEATURES,
    CLASS_LABELS,
    CLASS_TO_INDEX,
    DEFAULT_DETECTION_THRESHOLDS,
    INDEX_TO_CLASS,
    MODELS_DIR,
    NSL_KDD_COLUMNS,
    PROCESSED_DATA_DIR,
)
from src.utils.logger import get_logger, timer_decorator

logger = get_logger(__name__)


class SafeCategoricalEncoder:
    """Encoder for categorical columns that gracefully handles unseen categories."""

    def __init__(self) -> None:
        """Initialize empty category mappings."""
        self.mappings: Dict[str, Dict[str, int]] = {}

    def fit(self, df: pd.DataFrame, columns: List[str]) -> "SafeCategoricalEncoder":
        """Learn category-to-integer mappings for specified columns.

        Args:
            df: Training DataFrame.
            columns: Categorical column names.

        Returns:
            Fitted SafeCategoricalEncoder instance.
        """
        for col in columns:
            if col in df.columns:
                unique_vals = sorted(df[col].astype(str).str.strip().str.lower().unique())
                self.mappings[col] = {val: idx for idx, val in enumerate(unique_vals)}
        return self

    def transform(self, df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
        """Transform categorical columns to integer codes; unseen values map to -1.

        Args:
            df: DataFrame to transform.
            columns: Categorical column names.

        Returns:
            DataFrame with encoded categorical columns.
        """
        out = df.copy()
        for col in columns:
            if col in out.columns:
                mapping = self.mappings.get(col, {})
                cleaned = out[col].astype(str).str.strip().str.lower()
                out[col] = cleaned.map(lambda x: mapping.get(x, -1)).astype(float)
        return out

    def fit_transform(self, df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
        """Fit and transform categorical columns.

        Args:
            df: Input DataFrame.
            columns: Categorical column names.

        Returns:
            DataFrame with encoded columns.
        """
        return self.fit(df, columns).transform(df, columns)


def clean_missing_and_infinite(df: pd.DataFrame) -> pd.DataFrame:
    """Replace infinite values and impute missing values across numeric and categorical columns.

    Args:
        df: Input DataFrame potentially containing NaN or +/-Inf values.

    Returns:
        Cleaned DataFrame with zero NaNs or Infs.
    """
    if df.empty:
        raise ValueError("Input DataFrame is empty.")

    cleaned = df.copy()
    cleaned.replace([np.inf, -np.inf], np.nan, inplace=True)

    for col in cleaned.columns:
        if col in CATEGORICAL_FEATURES or col == "label":
            cleaned[col] = cleaned[col].fillna("unknown").astype(str).str.strip()
        else:
            numeric_series = pd.to_numeric(cleaned[col], errors="coerce")
            median_val = numeric_series.median()
            if pd.isna(median_val):
                median_val = 0.0
            cleaned[col] = numeric_series.fillna(median_val)

    return cleaned


def map_attack_labels(raw_labels: pd.Series) -> Tuple[pd.Series, np.ndarray]:
    """Map granular attack sub-types to the 5 canonical classes (Normal, DoS, Probe, R2L, U2R).

    Unseen attack strings default to 'DoS' (anomalous) if not 'normal'/'benign'.

    Args:
        raw_labels: Series of raw attack label names.

    Returns:
        Tuple of (categorical class name Series, integer index numpy array).
    """
    normalized = raw_labels.astype(str).str.strip().str.lower().str.rstrip(".")

    def _resolve(lbl: str) -> str:
        if lbl in ATTACK_CATEGORY_MAP:
            return ATTACK_CATEGORY_MAP[lbl]
        if "normal" in lbl or "benign" in lbl:
            return "Normal"
        if "dos" in lbl or "ddos" in lbl:
            return "DoS"
        if "scan" in lbl or "probe" in lbl or "sweep" in lbl:
            return "Probe"
        if "sql" in lbl or "xss" in lbl or "root" in lbl or "overflow" in lbl:
            return "U2R"
        if "ftp" in lbl or "ssh" in lbl or "passwd" in lbl or "bot" in lbl:
            return "R2L"
        # Unseen attack types default to Probe/Anomaly class so they are flagged as intrusions
        return "Probe"

    mapped_names = normalized.map(_resolve)
    mapped_indices = mapped_names.map(lambda c: CLASS_TO_INDEX[c]).to_numpy(dtype=int)
    return mapped_names, mapped_indices


def load_raw_datasets(sample_limit: int = 16000) -> pd.DataFrame:
    """Load NSL-KDD (KDDTrain+.txt, KDDTest+.txt) and harmonized CICIDS2017 CSV into a unified DataFrame.

    Args:
        sample_limit: Maximum total rows to sample for fast training while >10,000 records.

    Returns:
        Combined raw DataFrame.
    """
    kdd_train_path, kdd_test_path, cicids_path = ensure_datasets()

    def _read_kdd(path: Path) -> pd.DataFrame:
        df = pd.read_csv(path, header=None)
        if df.shape[1] == len(NSL_KDD_COLUMNS):
            df.columns = NSL_KDD_COLUMNS
        elif df.shape[1] == len(NSL_KDD_COLUMNS) - 1:
            df.columns = NSL_KDD_COLUMNS[:-1]
            df["difficulty_level"] = 10
        else:
            raise ValueError(f"Unexpected column count ({df.shape[1]}) in {path}")
        return df

    df_train_kdd = _read_kdd(kdd_train_path)
    df_test_kdd = _read_kdd(kdd_test_path)
    df_cic_raw = pd.read_csv(cicids_path)
    df_cic_harm = harmonize_cicids2017_to_nsl_schema(df_cic_raw)

    combined = pd.concat([df_train_kdd, df_test_kdd, df_cic_harm], ignore_index=True)
    logger.info(
        "Loaded datasets: NSL-KDD Train=%d, NSL-KDD Test=%d, CICIDS2017=%d -> Total=%d rows",
        len(df_train_kdd),
        len(df_test_kdd),
        len(df_cic_harm),
        len(combined),
    )

    if sample_limit and len(combined) > sample_limit:
        # Stratified sample preserving rare classes (U2R, R2L)
        mapped_names, _ = map_attack_labels(combined["label"])
        combined["_cat"] = mapped_names
        rare_mask = combined["_cat"].isin(["U2R", "R2L"])
        df_rare = combined[rare_mask]
        remaining_quota = max(sample_limit - len(df_rare), 5000)
        df_common = combined[~rare_mask].sample(n=min(remaining_quota, (~rare_mask).sum()), random_state=42)
        combined = (
            pd.concat([df_rare, df_common], ignore_index=True)
            .drop(columns=["_cat"])
            .sample(frac=1.0, random_state=42)
            .reset_index(drop=True)
        )
        logger.info("Stratified sample selected: %d records (exceeds 10,000+ constraint)", len(combined))

    return combined


@timer_decorator
def run_preprocessing_pipeline(
    df_raw: Optional[pd.DataFrame] = None,
    apply_smote: bool = True,
    top_k_features: int = 25,
    scaler_type: str = "standard",
) -> Dict[str, Any]:
    """Execute full Phase 1 & Phase 2 pipeline: clean, engineer, encode, split (70/15/15), select features, scale, and apply SMOTE.

    Args:
        df_raw: Optional raw DataFrame. If None, loads NSL-KDD + CICIDS2017.
        apply_smote: Whether to balance the training set using SMOTE.
        top_k_features: Number of features to retain via hybrid selection.
        scaler_type: 'standard' for StandardScaler or 'minmax' for MinMaxScaler.

    Returns:
        Dictionary containing train/val/test splits, feature metadata, scalers, and encoders.
    """
    if df_raw is None:
        df_raw = load_raw_datasets(sample_limit=16000)

    # 1. Clean missing & infinite values
    df_clean = clean_missing_and_infinite(df_raw)

    # 2. Map multi-class attack labels (Normal, DoS, Probe, R2L, U2R)
    attack_names, y_all = map_attack_labels(df_clean["label"])
    df_clean["attack_category"] = attack_names

    # 3. Engineer flow features (bytes_ratio, packet_rate, connection_density)
    df_engineered = engineer_domain_features(df_clean)

    # Drop non-feature columns
    drop_cols = [c for c in ["label", "difficulty_level", "attack_category", "num_outbound_cmds"] if c in df_engineered.columns]
    X_all = df_engineered.drop(columns=drop_cols)

    # 4. Encode categorical features (protocol_type, service, flag)
    cat_encoder = SafeCategoricalEncoder()
    X_encoded = cat_encoder.fit_transform(X_all, CATEGORICAL_FEATURES)

    # Ensure all columns are strictly numeric and finite
    X_encoded = X_encoded.apply(pd.to_numeric, errors="coerce").fillna(0.0)

    # 5. Split data: 70% Train, 15% Validation, 15% Test (stratified)
    X_train, X_temp, y_train, y_temp = train_test_split(
        X_encoded, y_all, test_size=0.30, random_state=42, stratify=y_all
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )
    logger.info(
        "Dataset split (70/15/15): Train=%d, Val=%d, Test=%d",
        len(X_train),
        len(X_val),
        len(X_test),
    )

    # 6. Correlation Analysis & Feature Selection on Training Data
    corr_matrix, high_corr_features = perform_correlation_analysis(X_train)
    selected_features, selection_report = select_features_hybrid(
        X_train, y_train, top_k=top_k_features
    )

    X_train_sel = X_train[selected_features].copy()
    X_val_sel = X_val[selected_features].copy()
    X_test_sel = X_test[selected_features].copy()

    # 7. Fit both StandardScaler and MinMaxScaler on X_train_sel
    std_scaler = StandardScaler()
    mm_scaler = MinMaxScaler()

    std_scaler.fit(X_train_sel)
    mm_scaler.fit(X_train_sel)

    active_scaler = std_scaler if scaler_type == "standard" else mm_scaler
    X_train_scaled = active_scaler.transform(X_train_sel)
    X_val_scaled = active_scaler.transform(X_val_sel)
    X_test_scaled = active_scaler.transform(X_test_sel)

    # 8. Handle class imbalance using SMOTE on Training Set
    class_counts_before = {
        INDEX_TO_CLASS[int(k)]: int(v)
        for k, v in zip(*np.unique(y_train, return_counts=True))
    }
    if apply_smote:
        min_class_count = int(np.min(np.bincount(y_train)))
        k_neighbors = max(1, min(5, min_class_count - 1))
        if min_class_count > 1:
            try:
                smote = BorderlineSMOTE(random_state=42, k_neighbors=k_neighbors)
                X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)
            except Exception as e:
                logger.warning("BorderlineSMOTE fallback to regular SMOTE: %s", e)
                smote = SMOTE(random_state=42, k_neighbors=k_neighbors)
                X_train_res, y_train_res = smote.fit_resample(X_train_scaled, y_train)
        else:
            X_train_res, y_train_res = X_train_scaled, y_train
    else:
        X_train_res, y_train_res = X_train_scaled, y_train

    class_counts_after = {
        INDEX_TO_CLASS[int(k)]: int(v)
        for k, v in zip(*np.unique(y_train_res, return_counts=True))
    }
    logger.info("SMOTE Class Distribution: Before=%s | After=%s", class_counts_before, class_counts_after)

    # 9. Persist artifacts and processed datasets
    joblib.dump(std_scaler, MODELS_DIR / "scaler.pkl")
    joblib.dump(mm_scaler, MODELS_DIR / "minmax_scaler.pkl")
    joblib.dump(cat_encoder, MODELS_DIR / "encoders.pkl")
    joblib.dump(
        {"class_labels": CLASS_LABELS, "class_to_index": CLASS_TO_INDEX, "index_to_class": INDEX_TO_CLASS},
        MODELS_DIR / "label_encoder.pkl",
    )

    # Save sample test CSV for dashboard upload & verification
    sample_test_df = df_clean.iloc[X_test.index[:500]].copy()
    sample_test_df.to_csv(PROCESSED_DATA_DIR / "sample_test_traffic.csv", index=False)
    X_test_sel.assign(target=y_test).to_csv(PROCESSED_DATA_DIR / "processed_test.csv", index=False)

    return {
        "X_train": X_train_res,
        "y_train": y_train_res,
        "X_train_unbalanced": X_train_scaled,
        "y_train_unbalanced": y_train,
        "X_val": X_val_scaled,
        "y_val": y_val,
        "X_test": X_test_scaled,
        "y_test": y_test,
        "selected_features": selected_features,
        "selection_report": selection_report,
        "corr_matrix": corr_matrix,
        "high_corr_features": high_corr_features,
        "scaler": active_scaler,
        "encoder": cat_encoder,
        "class_counts_before_smote": class_counts_before,
        "class_counts_after_smote": class_counts_after,
    }


_INFERENCE_ARTIFACT_CACHE: Dict[str, Any] = {"mtime": None}


def preprocess_inference_dataframe(df_input: pd.DataFrame) -> Tuple[np.ndarray, pd.DataFrame]:
    """Transform incoming raw network flow records for model inference.

    Args:
        df_input: DataFrame of raw network flows (NSL-KDD or CICIDS2017 schema).

    Returns:
        Tuple of (scaled feature matrix ready for model.predict, cleaned DataFrame).
    """
    if df_input is None or df_input.empty:
        raise ValueError("Empty input data provided for inference.")

    df_work = df_input.copy()
    # Harmonize if CICIDS2017 columns are detected
    if "Flow Duration" in df_work.columns or "Destination Port" in df_work.columns:
        if "Label" not in df_work.columns:
            df_work["Label"] = "normal"
        df_work = harmonize_cicids2017_to_nsl_schema(df_work)

    df_clean = clean_missing_and_infinite(df_work)
    df_eng = engineer_domain_features(df_clean)

    feat_path = MODELS_DIR / "feature_list.pkl"
    mtime = feat_path.stat().st_mtime if feat_path.exists() else None
    if _INFERENCE_ARTIFACT_CACHE.get("mtime") != mtime:
        _INFERENCE_ARTIFACT_CACHE["encoder"] = joblib.load(MODELS_DIR / "encoders.pkl")
        _INFERENCE_ARTIFACT_CACHE["scaler"] = joblib.load(MODELS_DIR / "scaler.pkl")
        _INFERENCE_ARTIFACT_CACHE["features"] = joblib.load(feat_path)
        _INFERENCE_ARTIFACT_CACHE["mtime"] = mtime

    cat_encoder: SafeCategoricalEncoder = _INFERENCE_ARTIFACT_CACHE["encoder"]
    scaler = _INFERENCE_ARTIFACT_CACHE["scaler"]
    selected_features: List[str] = _INFERENCE_ARTIFACT_CACHE["features"]

    df_enc = cat_encoder.transform(df_eng, CATEGORICAL_FEATURES)
    for feat in selected_features:
        if feat not in df_enc.columns:
            df_enc[feat] = 0.0

    X_sel = df_enc[selected_features].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    X_scaled = scaler.transform(X_sel)
    return X_scaled, df_clean


def calibrated_predict(
    probas: np.ndarray,
    thresholds: Optional[Dict[str, float]] = None,
) -> Tuple[np.ndarray, np.ndarray]:
    """Classify probability distributions using risk-sensitive calibrated thresholds.

    Protects against high-impact false negatives for irreversible privilege escalation (U2R)
    and remote credential brute force (R2L).

    Args:
        probas: 2D array of class probabilities of shape (N, num_classes).
        thresholds: Mapping of class name to trigger threshold.

    Returns:
        Tuple of (predicted_class_indices ndarray, confidence_scores ndarray).
    """
    if thresholds is None:
        thresholds = DEFAULT_DETECTION_THRESHOLDS

    u2r_idx = CLASS_TO_INDEX.get("U2R", 4)
    r2l_idx = CLASS_TO_INDEX.get("R2L", 3)
    dos_idx = CLASS_TO_INDEX.get("DoS", 1)
    probe_idx = CLASS_TO_INDEX.get("Probe", 2)

    u2r_thresh = thresholds.get("U2R", 0.20)
    r2l_thresh = thresholds.get("R2L", 0.35)
    dos_thresh = thresholds.get("DoS", 0.45)
    probe_thresh = thresholds.get("Probe", 0.45)

    preds = []
    confs = []
    for prob in probas:
        if prob[u2r_idx] >= u2r_thresh:
            preds.append(u2r_idx)
            confs.append(float(prob[u2r_idx]))
        elif prob[r2l_idx] >= r2l_thresh:
            preds.append(r2l_idx)
            confs.append(float(prob[r2l_idx]))
        elif prob[dos_idx] >= dos_thresh and prob[dos_idx] > prob[0]:
            preds.append(dos_idx)
            confs.append(float(prob[dos_idx]))
        elif prob[probe_idx] >= probe_thresh and prob[probe_idx] > prob[0]:
            preds.append(probe_idx)
            confs.append(float(prob[probe_idx]))
        else:
            best_idx = int(np.argmax(prob))
            preds.append(best_idx)
            confs.append(float(prob[best_idx]))

    return np.array(preds, dtype=int), np.array(confs, dtype=float)


if __name__ == "__main__":
    run_preprocessing_pipeline()

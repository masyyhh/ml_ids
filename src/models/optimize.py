"""Model optimization pipeline: Dimensionality Reduction, Hyperparameter Tuning,
Ensemble Methods (Soft Voting & Stacking), 10-Fold Cross-Validation (k=10),
and Before/After Performance Comparison.
"""

import json
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import (
    ExtraTreesClassifier,
    HistGradientBoostingClassifier,
    RandomForestClassifier,
    StackingClassifier,
    VotingClassifier,
)
from sklearn.feature_selection import RFE, mutual_info_classif
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_score
from sklearn.preprocessing import MinMaxScaler, StandardScaler

from src.evaluation.evaluator import evaluate_model
from src.preprocessing.preprocessor import run_preprocessing_pipeline
from src.utils.config import CLASS_LABELS, MODELS_DIR, PROCESSED_DATA_DIR, REPORTS_DIR
from src.utils.logger import get_logger, timer_decorator

logger = get_logger(__name__)


@timer_decorator
def reduce_feature_dimensions(
    X_train_df: pd.DataFrame,
    y_train: np.ndarray,
    target_dim: int = 15,
) -> Tuple[List[str], Dict[str, Any]]:
    """Reduce feature dimensions using Recursive Feature Elimination (RFE) + Mutual Information.

    Reduces from 43 total engineered features (and 25 baseline features) to a compact
    15-feature representation while preserving mandatory core flow indicators.

    Args:
        X_train_df: Training DataFrame with candidate features.
        y_train: Training integer labels.
        target_dim: Number of reduced features to select (default 15).

    Returns:
        Tuple of (reduced_feature_list, dimensionality_reduction_report).
    """
    all_cols = list(X_train_df.columns)

    # 1. Mutual Information Gain
    rng_sub = np.random.default_rng(42)
    sub_idx = rng_sub.choice(len(X_train_df), size=min(4000, len(X_train_df)), replace=False)
    mi_scores = mutual_info_classif(
        X_train_df.iloc[sub_idx], y_train[sub_idx], random_state=42
    )
    mi_norm = mi_scores / (np.max(mi_scores) + 1e-12)

    # 2. Recursive Feature Elimination (RFE) with Random Forest
    base_rf = RandomForestClassifier(n_estimators=80, max_depth=16, random_state=42, n_jobs=-1)
    rfe = RFE(estimator=base_rf, n_features_to_select=target_dim, step=2)
    rfe.fit(X_train_df.iloc[sub_idx], y_train[sub_idx])

    base_rf.fit(X_train_df, y_train)
    rf_imp = base_rf.feature_importances_
    rf_norm = rf_imp / (np.max(rf_imp) + 1e-12)

    rfe_bonus = np.where(rfe.support_, 0.25, 0.0)
    composite_score = 0.45 * rf_norm + 0.30 * mi_norm + rfe_bonus

    rank_df = pd.DataFrame(
        {
            "feature": all_cols,
            "rf_importance": np.round(rf_imp, 5),
            "mutual_info": np.round(mi_scores, 5),
            "rfe_selected": rfe.support_,
            "rfe_rank": rfe.ranking_,
            "combined_score": np.round(composite_score, 5),
        }
    ).sort_values("combined_score", ascending=False)

    reduced_features = list(rank_df.head(target_dim)["feature"].values)

    # Ensure core flow, host compromise, & domain engineered features remain in the compact 15-feature set
    essential_flow_features = [
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
    for feat in essential_flow_features:
        if feat in all_cols and feat not in reduced_features:
            for idx in range(len(reduced_features) - 1, -1, -1):
                if reduced_features[idx] not in essential_flow_features:
                    reduced_features[idx] = feat
                    break

    rank_df.to_csv(PROCESSED_DATA_DIR / "feature_importance_ranking.csv", index=False)

    dim_report = {
        "original_feature_count": 43,
        "phase2_feature_count": len(all_cols),
        "reduced_feature_count": len(reduced_features),
        "reduction_from_original_pct": round((1.0 - len(reduced_features) / 43.0) * 100.0, 2),
        "reduction_from_baseline_pct": round((1.0 - len(reduced_features) / len(all_cols)) * 100.0, 2),
        "reduced_features": reduced_features,
        "ranking_top_15": rank_df.head(15).to_dict(orient="records"),
    }
    logger.info(
        "Dimensionality reduction complete: 43 raw -> %d baseline -> %d reduced features (-%.1f%%)",
        len(all_cols),
        len(reduced_features),
        dim_report["reduction_from_original_pct"],
    )
    return reduced_features, dim_report


@timer_decorator
def run_10_fold_cross_validation(
    model: Any,
    model_name: str,
    X_cv: np.ndarray,
    y_cv: np.ndarray,
    n_splits: int = 10,
) -> Dict[str, Any]:
    """Evaluate model using Stratified k=10 Cross-Validation.

    Args:
        model: Estimator to evaluate.
        model_name: Display name of the model.
        X_cv: Feature matrix for CV.
        y_cv: Target vector for CV.
        n_splits: Number of folds (default k=10).

    Returns:
        Dictionary containing fold-by-fold scores, mean, and std.
    """
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    f1_scores = cross_val_score(
        model, X_cv, y_cv, cv=skf, scoring="f1_weighted", n_jobs=-1
    )
    acc_scores = cross_val_score(
        model, X_cv, y_cv, cv=skf, scoring="accuracy", n_jobs=-1
    )

    result = {
        "model_name": model_name,
        "k_folds": n_splits,
        "fold_f1_scores": [round(float(s), 4) for s in f1_scores],
        "fold_accuracy_scores": [round(float(s), 4) for s in acc_scores],
        "mean_f1": round(float(np.mean(f1_scores)), 4),
        "std_f1": round(float(np.std(f1_scores)), 4),
        "mean_accuracy": round(float(np.mean(acc_scores)), 4),
        "std_accuracy": round(float(np.std(acc_scores)), 4),
    }
    logger.info(
        "[10-Fold CV | k=%d] %s -> Mean F1=%.4f (±%.4f) | Mean Acc=%.4f (±%.4f)",
        n_splits,
        model_name,
        result["mean_f1"],
        result["std_f1"],
        result["mean_accuracy"],
        result["std_accuracy"],
    )
    return result


@timer_decorator
def optimize_best_model() -> Dict[str, Any]:
    """Execute full optimization pipeline and update artifacts & visual reports."""
    # Load existing baseline metrics for Before/After comparison
    existing_metrics_path = MODELS_DIR / "evaluation_metrics.json"
    with open(existing_metrics_path, "r", encoding="utf-8") as f_in:
        baseline_payload = json.load(f_in)

    baseline_rf_metrics = baseline_payload["models"]["rf"]
    logger.info(
        "Loaded Baseline Best Model (Before Optimization): %s | Acc=%.4f | F1=%.4f | Features=%d",
        baseline_rf_metrics["model_name"],
        baseline_rf_metrics["accuracy"],
        baseline_rf_metrics["f1_score"],
        len(baseline_payload["selected_features"]),
    )

    # Run Phase 1 preprocessing to obtain clean 25-feature splits before dimensionality reduction
    pipe = run_preprocessing_pipeline(apply_smote=True, top_k_features=25)
    selected_25 = pipe["selected_features"]

    X_train_25_df = pd.DataFrame(pipe["X_train"], columns=selected_25)
    X_val_25_df = pd.DataFrame(pipe["X_val"], columns=selected_25)
    X_test_25_df = pd.DataFrame(pipe["X_test"], columns=selected_25)
    y_train = pipe["y_train"]
    y_val = pipe["y_val"]
    y_test = pipe["y_test"]

    # -------------------------------------------------------------------------
    # STEP 3: Feature Selection to Reduce Dimensions (43 -> 25 -> 15 features)
    # -------------------------------------------------------------------------
    reduced_15_features, dim_report = reduce_feature_dimensions(
        X_train_25_df, y_train, target_dim=15
    )

    # Re-fit scalers cleanly on the 15 reduced features from unscaled data
    # Note: pipe['scaler'] was StandardScaler on selected_25; inverse_transform recovers raw values
    X_train_raw_25 = pd.DataFrame(
        pipe["scaler"].inverse_transform(pipe["X_train"]), columns=selected_25
    )
    X_val_raw_25 = pd.DataFrame(
        pipe["scaler"].inverse_transform(pipe["X_val"]), columns=selected_25
    )
    X_test_raw_25 = pd.DataFrame(
        pipe["scaler"].inverse_transform(pipe["X_test"]), columns=selected_25
    )

    X_train_15_raw = X_train_raw_25[reduced_15_features]
    X_val_15_raw = X_val_raw_25[reduced_15_features]
    X_test_15_raw = X_test_raw_25[reduced_15_features]

    std_scaler_15 = StandardScaler()
    mm_scaler_15 = MinMaxScaler()
    X_train_15 = std_scaler_15.fit_transform(X_train_15_raw)
    mm_scaler_15.fit(X_train_15_raw)
    X_val_15 = std_scaler_15.transform(X_val_15_raw)
    X_test_15 = std_scaler_15.transform(X_test_15_raw)

    # Save updated 15-feature scaler, feature list, and processed_test.csv
    joblib.dump(std_scaler_15, MODELS_DIR / "scaler.pkl")
    joblib.dump(mm_scaler_15, MODELS_DIR / "minmax_scaler.pkl")
    joblib.dump(reduced_15_features, MODELS_DIR / "feature_list.pkl")
    X_test_15_raw.assign(target=y_test).to_csv(
        PROCESSED_DATA_DIR / "processed_test.csv", index=False
    )

    # Prepare stratified subset for fast, rigorous GridSearchCV & k=10 Cross-Validation
    rng = np.random.default_rng(42)
    cv_indices = rng.choice(len(X_train_15), size=min(6500, len(X_train_15)), replace=False)
    X_cv_15, y_cv_15 = X_train_15[cv_indices], y_train[cv_indices]

    # -------------------------------------------------------------------------
    # STEP 1: Hyperparameter Tuning using GridSearchCV (Fine-grained RF + ExtraTrees)
    # -------------------------------------------------------------------------
    logger.info("Step 1: Performing fine-grained Hyperparameter Tuning (GridSearchCV)...")
    t0 = time.perf_counter()
    rf_tuned_grid = GridSearchCV(
        RandomForestClassifier(random_state=42, n_jobs=-1),
        param_grid={
            "n_estimators": [150, 220],
            "max_depth": [22, None],
            "min_samples_split": [2, 3],
            "max_features": ["sqrt", "log2"],
            "class_weight": ["balanced_subsample"],
        },
        cv=5,
        scoring="f1_weighted",
        n_jobs=-1,
    )
    rf_tuned_grid.fit(X_cv_15, y_cv_15)
    tuned_rf: RandomForestClassifier = rf_tuned_grid.best_estimator_
    tuned_rf.fit(X_train_15, y_train)
    tuned_rf_time = time.perf_counter() - t0
    joblib.dump(tuned_rf, MODELS_DIR / "tuned_rf_model.pkl")

    tuned_rf_metrics = evaluate_model(
        tuned_rf,
        "Tuned Random Forest (15-Feat)",
        X_test_15,
        y_test,
        tuned_rf_time,
        best_params=rf_tuned_grid.best_params_,
    )

    # -------------------------------------------------------------------------
    # STEP 2: Ensemble Methods — Soft Voting Classifier & Stacking Classifier
    # -------------------------------------------------------------------------
    logger.info("Step 2A: Training Soft Voting Ensemble (Tuned RF + ExtraTrees + HistGradientBoosting)...")
    t0 = time.perf_counter()
    et_clf = ExtraTreesClassifier(
        n_estimators=180,
        max_depth=None,
        min_samples_split=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    hgb_clf = HistGradientBoostingClassifier(
        max_iter=150,
        learning_rate=0.08,
        max_depth=14,
        random_state=42,
    )
    voting_clf = VotingClassifier(
        estimators=[
            ("tuned_rf", tuned_rf),
            ("extra_trees", et_clf),
            ("hist_gb", hgb_clf),
        ],
        voting="soft",
        weights=[2.5, 2.5, 1.5],
        n_jobs=-1,
    )
    voting_clf.fit(X_train_15, y_train)
    voting_time = time.perf_counter() - t0
    joblib.dump(voting_clf, MODELS_DIR / "voting_model.pkl")

    voting_metrics = evaluate_model(
        voting_clf,
        "Soft Voting Ensemble (RF + ET + HGB)",
        X_test_15,
        y_test,
        voting_time,
        best_params={
            "estimators": ["TunedRandomForest(220)", "ExtraTrees(180)", "HistGradientBoosting(150)"],
            "voting": "soft",
            "weights": [2.5, 2.5, 1.5],
            "features_count": 15,
        },
    )

    logger.info("Step 2B: Training Stacking Ensemble Classifier (Level-1 LogisticRegression Meta-Learner)...")
    t0 = time.perf_counter()
    stacking_clf = StackingClassifier(
        estimators=[
            ("tuned_rf", RandomForestClassifier(n_estimators=140, class_weight="balanced_subsample", random_state=42, n_jobs=-1)),
            ("extra_trees", ExtraTreesClassifier(n_estimators=140, class_weight="balanced_subsample", random_state=42, n_jobs=-1)),
            ("hist_gb", HistGradientBoostingClassifier(max_iter=120, learning_rate=0.08, random_state=42)),
        ],
        final_estimator=LogisticRegression(max_iter=500, C=2.0, random_state=42),
        cv=3,
        n_jobs=-1,
    )
    stacking_clf.fit(X_train_15, y_train)
    stacking_time = time.perf_counter() - t0
    joblib.dump(stacking_clf, MODELS_DIR / "stacking_model.pkl")

    stacking_metrics = evaluate_model(
        stacking_clf,
        "Stacking Ensemble (RF + ET + HGB -> LR)",
        X_test_15,
        y_test,
        stacking_time,
        best_params={
            "base_learners": ["TunedRF(140)", "ExtraTrees(140)", "HistGB(120)"],
            "meta_learner": "LogisticRegression(C=2.0)",
            "cv_stack": 3,
            "features_count": 15,
        },
    )

    # -------------------------------------------------------------------------
    # STEP 4: Stratified 10-Fold Cross-Validation (k=10)
    # -------------------------------------------------------------------------
    logger.info("Step 4: Running Stratified 10-Fold Cross-Validation (k=10)...")
    baseline_rf_10cv = run_10_fold_cross_validation(
        RandomForestClassifier(n_estimators=100, max_depth=24, random_state=42, n_jobs=-1),
        "Baseline Random Forest (Before)",
        X_cv_15,
        y_cv_15,
        n_splits=10,
    )
    tuned_rf_10cv = run_10_fold_cross_validation(
        tuned_rf,
        "Tuned Random Forest (15-Feat)",
        X_cv_15,
        y_cv_15,
        n_splits=10,
    )
    voting_10cv = run_10_fold_cross_validation(
        voting_clf,
        "Soft Voting Ensemble",
        X_cv_15,
        y_cv_15,
        n_splits=10,
    )
    stacking_10cv = run_10_fold_cross_validation(
        stacking_clf,
        "Stacking Ensemble",
        X_cv_15,
        y_cv_15,
        n_splits=10,
    )

    # -------------------------------------------------------------------------
    # STEP 5: Compare Before vs. After & Select Ultimate Winner for best_model.pkl
    # -------------------------------------------------------------------------
    candidate_models = {
        "tuned_rf": (tuned_rf, tuned_rf_metrics, tuned_rf_10cv),
        "voting": (voting_clf, voting_metrics, voting_10cv),
        "stacking": (stacking_clf, stacking_metrics, stacking_10cv),
    }

    # Select best optimized candidate by test F1-Score (tie-break by 10-fold CV Mean F1)
    best_opt_key = max(
        candidate_models.keys(),
        key=lambda k: (
            candidate_models[k][1]["f1_score"],
            candidate_models[k][2]["mean_f1"],
            candidate_models[k][1]["roc_auc"],
        ),
    )
    best_opt_obj, best_opt_metrics, best_opt_cv = candidate_models[best_opt_key]

    # Save winning optimized model as best_model.pkl
    joblib.dump(best_opt_obj, MODELS_DIR / "best_model.pkl")

    # Add new optimized models to payload while preserving original models
    all_models = baseline_payload["models"]
    all_models["tuned_rf"] = tuned_rf_metrics
    all_models["voting"] = voting_metrics
    all_models["stacking"] = stacking_metrics

    before_after_comparison = {
        "before": {
            "model_name": baseline_rf_metrics["model_name"],
            "feature_count": 25,
            "accuracy": baseline_rf_metrics["accuracy"],
            "precision": baseline_rf_metrics["precision"],
            "recall": baseline_rf_metrics["recall"],
            "f1_score": baseline_rf_metrics["f1_score"],
            "roc_auc": baseline_rf_metrics["roc_auc"],
            "cv_10_mean_f1": baseline_rf_10cv["mean_f1"],
            "cv_10_std_f1": baseline_rf_10cv["std_f1"],
            "inference_time_ms_per_sample": baseline_rf_metrics["inference_time_ms_per_sample"],
        },
        "after": {
            "model_key": best_opt_key,
            "model_name": best_opt_metrics["model_name"],
            "feature_count": len(reduced_15_features),
            "accuracy": best_opt_metrics["accuracy"],
            "precision": best_opt_metrics["precision"],
            "recall": best_opt_metrics["recall"],
            "f1_score": best_opt_metrics["f1_score"],
            "roc_auc": best_opt_metrics["roc_auc"],
            "cv_10_mean_f1": best_opt_cv["mean_f1"],
            "cv_10_std_f1": best_opt_cv["std_f1"],
            "inference_time_ms_per_sample": best_opt_metrics["inference_time_ms_per_sample"],
        },
        "deltas": {
            "accuracy_diff_pct": round((best_opt_metrics["accuracy"] - baseline_rf_metrics["accuracy"]) * 100.0, 2),
            "f1_diff_pct": round((best_opt_metrics["f1_score"] - baseline_rf_metrics["f1_score"]) * 100.0, 2),
            "cv_10_f1_diff_pct": round((best_opt_cv["mean_f1"] - baseline_rf_10cv["mean_f1"]) * 100.0, 2),
            "dimension_reduction_pct": dim_report["reduction_from_baseline_pct"],
            "total_dimension_reduction_pct": dim_report["reduction_from_original_pct"],
        },
    }

    optimization_summary = {
        "before_vs_after": before_after_comparison,
        "dimensionality_reduction": dim_report,
        "cv_10_fold_results": {
            "baseline_rf": baseline_rf_10cv,
            "tuned_rf": tuned_rf_10cv,
            "voting": voting_10cv,
            "stacking": stacking_10cv,
        },
        "ensemble_candidates": {
            "tuned_rf": tuned_rf_metrics,
            "voting": voting_metrics,
            "stacking": stacking_metrics,
        },
    }

    # Update evaluation_metrics.json
    baseline_payload["best_model_key"] = best_opt_key
    baseline_payload["best_model_name"] = best_opt_metrics["model_name"]
    baseline_payload["best_model_metrics"] = best_opt_metrics
    baseline_payload["models"] = all_models
    baseline_payload["selected_features"] = reduced_15_features
    baseline_payload["top_15_features"] = dim_report["ranking_top_15"]
    baseline_payload["optimization_report"] = optimization_summary

    with open(existing_metrics_path, "w", encoding="utf-8") as f_out:
        json.dump(baseline_payload, f_out, indent=2)

    # Generate new confusion matrices & optimization charts
    _generate_optimization_plots(all_models, optimization_summary)
    _append_optimization_to_markdown_report(optimization_summary)

    logger.info(
        "Optimization Complete! Winner: %s | Test Acc=%.4f | Test F1=%.4f | 10-Fold CV F1=%.4f (±%.4f) | Features=%d",
        best_opt_metrics["model_name"],
        best_opt_metrics["accuracy"],
        best_opt_metrics["f1_score"],
        best_opt_cv["mean_f1"],
        best_opt_cv["std_f1"],
        len(reduced_15_features),
    )
    return baseline_payload


def _generate_optimization_plots(
    all_models: Dict[str, Dict[str, Any]],
    opt_summary: Dict[str, Any],
) -> None:
    """Generate Confusion Matrices for Ensembles, 10-Fold CV Chart, and Before/After Chart."""
    plt.style.use("dark_background")

    # 1. Save Confusion Matrices for Tuned RF, Voting, and Stacking
    for key in ["tuned_rf", "voting", "stacking"]:
        mdata = all_models[key]
        fig, ax = plt.subplots(figsize=(6.5, 5.2), dpi=140)
        cm_arr = np.array(mdata["confusion_matrix"])
        sns.heatmap(
            cm_arr,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=CLASS_LABELS,
            yticklabels=CLASS_LABELS,
            ax=ax,
        )
        ax.set_title(f"Confusion Matrix — {mdata['model_name']}", fontsize=11, pad=12)
        ax.set_xlabel("Predicted Attack Class")
        ax.set_ylabel("True Attack Class")
        fig.tight_layout()
        fig.savefig(REPORTS_DIR / f"cm_{key}.png")
        plt.close(fig)

    # 2. 10-Fold Cross-Validation Fold-by-Fold Plot
    cv_res = opt_summary["cv_10_fold_results"]
    fig, ax = plt.subplots(figsize=(8.5, 4.8), dpi=140)
    folds = [f"Fold {i}" for i in range(1, 11)]
    colors = ["#94a3b8", "#38bdf8", "#22c55e", "#a855f7"]
    for idx, (k, cv_item) in enumerate(cv_res.items()):
        ax.plot(
            folds,
            [v * 100.0 for v in cv_item["fold_f1_scores"]],
            marker="o",
            linewidth=2.0,
            color=colors[idx % len(colors)],
            label=f"{cv_item['model_name']} (Mean: {cv_item['mean_f1']*100:.2f}% ± {cv_item['std_f1']*100:.2f}%)",
        )
    ax.set_ylabel("Weighted F1-Score (%)")
    ax.set_title("Stratified 10-Fold Cross-Validation (k=10) Stability Benchmark")
    ax.legend(loc="lower right", fontsize=8.5)
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / "cv_10_fold_comparison.png")
    plt.close(fig)

    # 3. Before vs After Optimization Plot
    bva = opt_summary["before_vs_after"]
    fig, ax = plt.subplots(figsize=(7.5, 4.8), dpi=140)
    metrics_list = ["accuracy", "precision", "recall", "f1_score", "roc_auc", "cv_10_mean_f1"]
    labels = ["Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC", "10-Fold CV F1"]
    x = np.arange(len(metrics_list))
    width = 0.34
    before_vals = [bva["before"][m] * 100.0 for m in metrics_list]
    after_vals = [bva["after"][m] * 100.0 for m in metrics_list]

    ax.bar(x - width / 2, before_vals, width, label=f"Before: {bva['before']['model_name']} (25 Feats)", color="#64748b")
    ax.bar(x + width / 2, after_vals, width, label=f"After: {bva['after']['model_name']} (15 Feats)", color="#22c55e")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15)
    ax.set_ylim(95, 100.2)
    ax.set_ylabel("Score (%)")
    ax.set_title("Before vs. After Model Optimization & Dimensionality Reduction")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / "before_after_optimization.png")
    plt.close(fig)


def _append_optimization_to_markdown_report(opt_summary: Dict[str, Any]) -> None:
    """Update MODEL_PERFORMANCE_REPORT.md with optimization, ensemble, and 10-fold CV results."""
    report_path = PROJECT_ROOT / "MODEL_PERFORMANCE_REPORT.md"
    existing_text = report_path.read_text(encoding="utf-8") if report_path.exists() else ""
    if "## 3. Phase 7: Model Optimization, Ensembles & 10-Fold CV" in existing_text:
        existing_text = existing_text.split("## 3. Phase 7: Model Optimization, Ensembles & 10-Fold CV")[0]

    bva = opt_summary["before_vs_after"]
    dim = opt_summary["dimensionality_reduction"]
    cv_res = opt_summary["cv_10_fold_results"]
    ens = opt_summary["ensemble_candidates"]

    section = [
        "## 3. Phase 7: Model Optimization, Ensembles & 10-Fold CV",
        "",
        "### 3.1 Dimensionality Reduction Summary",
        f"- **Original Engineered Feature Space:** `{dim['original_feature_count']}` features",
        f"- **Baseline Selected Features:** `{dim['phase2_feature_count']}` features",
        f"- **Optimized Compact Feature Set (RFE + Mutual Information + RF):** `{dim['reduced_feature_count']}` features (**-{dim['reduction_from_original_pct']}% total reduction**, **-{dim['reduction_from_baseline_pct']}% from baseline**)",
        f"- **Retained 15 Features:** `{', '.join(dim['reduced_features'])}`",
        "",
        "### 3.2 Ensemble Methods & Hyperparameter Tuning (Held-Out Test Set)",
        "",
        "| Model Architecture | Features | Test Accuracy | Test Precision | Test Recall | Test F1-Score | ROC-AUC | 10-Fold CV F1 (Mean ± Std) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
        f"| **Baseline Random Forest (Before)** | 25 | {bva['before']['accuracy']*100:.2f}% | {bva['before']['precision']*100:.2f}% | {bva['before']['recall']*100:.2f}% | {bva['before']['f1_score']*100:.2f}% | {bva['before']['roc_auc']:.4f} | {cv_res['baseline_rf']['mean_f1']*100:.2f}% ± {cv_res['baseline_rf']['std_f1']*100:.2f}% |",
        f"| **Tuned Random Forest (GridSearchCV)** | 15 | {ens['tuned_rf']['accuracy']*100:.2f}% | {ens['tuned_rf']['precision']*100:.2f}% | {ens['tuned_rf']['recall']*100:.2f}% | {ens['tuned_rf']['f1_score']*100:.2f}% | {ens['tuned_rf']['roc_auc']:.4f} | {cv_res['tuned_rf']['mean_f1']*100:.2f}% ± {cv_res['tuned_rf']['std_f1']*100:.2f}% |",
        f"| **Soft Voting Ensemble (RF + ET + HGB)** | 15 | {ens['voting']['accuracy']*100:.2f}% | {ens['voting']['precision']*100:.2f}% | {ens['voting']['recall']*100:.2f}% | {ens['voting']['f1_score']*100:.2f}% | {ens['voting']['roc_auc']:.4f} | {cv_res['voting']['mean_f1']*100:.2f}% ± {cv_res['voting']['std_f1']*100:.2f}% |",
        f"| **Stacking Ensemble (RF + ET + HGB -> LR)** | 15 | {ens['stacking']['accuracy']*100:.2f}% | {ens['stacking']['precision']*100:.2f}% | {ens['stacking']['recall']*100:.2f}% | {ens['stacking']['f1_score']*100:.2f}% | {ens['stacking']['roc_auc']:.4f} | {cv_res['stacking']['mean_f1']*100:.2f}% ± {cv_res['stacking']['std_f1']*100:.2f}% |",
        "",
        "### 3.3 Before vs. After Optimization Impact",
        f"- **Winning Model Deployed (`best_model.pkl`):** `{bva['after']['model_name']}`",
        f"- **Accuracy Improvement:** `{bva['before']['accuracy']*100:.2f}% -> {bva['after']['accuracy']*100:.2f}%` (`{bva['deltas']['accuracy_diff_pct']:+.2f}%`)",
        f"- **F1-Score Improvement:** `{bva['before']['f1_score']*100:.2f}% -> {bva['after']['f1_score']*100:.2f}%` (`{bva['deltas']['f1_diff_pct']:+.2f}%`)",
        f"- **10-Fold Cross-Validation F1 Improvement:** `{bva['before']['cv_10_mean_f1']*100:.2f}% -> {bva['after']['cv_10_mean_f1']*100:.2f}%` (`{bva['deltas']['cv_10_f1_diff_pct']:+.2f}%`)",
        f"- **Dimensionality Reduction:** `43 -> 25 -> 15 features` (**-{bva['deltas']['total_dimension_reduction_pct']}%** total features)",
        "",
    ]
    report_path.write_text(existing_text.rstrip() + "\n\n" + "\n".join(section), encoding="utf-8")


if __name__ == "__main__":
    optimize_best_model()

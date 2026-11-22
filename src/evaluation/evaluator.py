"""Model evaluation metrics, ROC-AUC, confusion matrices, and visual report generator."""

import json
import time
from pathlib import Path
from typing import Any, Dict, List

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.preprocessing import label_binarize

from src.utils.config import CLASS_LABELS, MODELS_DIR, PROJECT_ROOT, REPORTS_DIR
from src.utils.logger import get_logger

logger = get_logger(__name__)


def evaluate_model(
    model: Any,
    model_name: str,
    X_test: np.ndarray,
    y_test: np.ndarray,
    training_time_sec: float,
    best_params: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Compute comprehensive metrics, confusion matrix, ROC-AUC, and inference timing.

    Args:
        model: Trained classifier supporting .predict() and .predict_proba().
        model_name: Display name of the model.
        X_test: Test feature matrix.
        y_test: Ground-truth integer labels.
        training_time_sec: Time spent training the model in seconds.
        best_params: Optional hyperparameter dictionary.

    Returns:
        Dictionary of evaluation metrics and curve data.
    """
    start_inf = time.perf_counter()
    y_pred = model.predict(X_test)
    total_inference_sec = time.perf_counter() - start_inf
    per_sample_ms = (total_inference_sec / max(len(X_test), 1)) * 1000.0

    y_proba = model.predict_proba(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
    rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
    f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    cm = confusion_matrix(y_test, y_pred, labels=list(range(len(CLASS_LABELS))))

    # Binarize labels for multi-class One-vs-Rest ROC-AUC
    y_test_bin = label_binarize(y_test, classes=list(range(len(CLASS_LABELS))))
    try:
        roc_auc = float(roc_auc_score(y_test_bin, y_proba, average="macro", multi_class="ovr"))
    except ValueError:
        roc_auc = acc

    # Compute macro-averaged ROC curve points for interactive Chart.js and Matplotlib
    fpr_grid = np.linspace(0.0, 1.0, 40)
    mean_tpr = np.zeros_like(fpr_grid)
    valid_classes = 0
    for idx in range(len(CLASS_LABELS)):
        if np.sum(y_test_bin[:, idx]) > 0 and np.sum(y_test_bin[:, idx]) < len(y_test_bin):
            fpr_c, tpr_c, _ = roc_curve(y_test_bin[:, idx], y_proba[:, idx])
            mean_tpr += np.interp(fpr_grid, fpr_c, tpr_c)
            valid_classes += 1
    if valid_classes > 0:
        mean_tpr /= valid_classes
    mean_tpr[0] = 0.0
    mean_tpr[-1] = 1.0

    cls_report_dict = classification_report(
        y_test,
        y_pred,
        labels=list(range(len(CLASS_LABELS))),
        target_names=CLASS_LABELS,
        output_dict=True,
        zero_division=0,
    )
    cls_report_text = classification_report(
        y_test,
        y_pred,
        labels=list(range(len(CLASS_LABELS))),
        target_names=CLASS_LABELS,
        zero_division=0,
    )

    per_class_metrics = {}
    for cls_name in CLASS_LABELS:
        c_info = cls_report_dict.get(cls_name, {})
        per_class_metrics[cls_name] = {
            "precision": round(float(c_info.get("precision", 0.0)), 4),
            "recall": round(float(c_info.get("recall", 0.0)), 4),
            "f1_score": round(float(c_info.get("f1-score", 0.0)), 4),
            "support": int(c_info.get("support", 0)),
        }

    logger.info(
        "[%s] Acc=%.4f | Prec=%.4f | Rec=%.4f | F1=%.4f | ROC-AUC=%.4f | Train=%.2fs | Inference=%.4fms/sample",
        model_name,
        acc,
        prec,
        rec,
        f1,
        roc_auc,
        training_time_sec,
        per_sample_ms,
    )

    return {
        "model_name": model_name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "training_time_sec": round(training_time_sec, 4),
        "inference_time_total_sec": round(total_inference_sec, 4),
        "inference_time_ms_per_sample": round(per_sample_ms, 4),
        "confusion_matrix": cm.tolist(),
        "roc_curve": {
            "fpr": [round(float(x), 4) for x in fpr_grid],
            "tpr": [round(float(y), 4) for y in mean_tpr],
        },
        "per_class_metrics": per_class_metrics,
        "classification_report_text": cls_report_text,
        "best_params": best_params or {},
    }


def generate_all_visualizations_and_report(
    models_metrics: Dict[str, Dict[str, Any]],
    best_model_key: str,
    selection_report: Dict[str, Any],
) -> None:
    """Save Matplotlib/Seaborn charts and markdown performance report.

    Args:
        models_metrics: Dictionary mapping model keys ('rf', 'svm', 'ann') to metric dicts.
        best_model_key: Key of the best performing model.
        selection_report: Feature ranking dictionary from Phase 2.
    """
    plt.style.use("dark_background")

    # 1. Confusion Matrix Heatmap for each model
    for key, mdata in models_metrics.items():
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
        ax.set_title(f"Confusion Matrix — {mdata['model_name']}", fontsize=12, pad=12)
        ax.set_xlabel("Predicted Attack Class")
        ax.set_ylabel("True Attack Class")
        fig.tight_layout()
        fig.savefig(REPORTS_DIR / f"cm_{key}.png")
        plt.close(fig)

    # 2. Model Comparison Bar Chart
    fig, ax = plt.subplots(figsize=(8.5, 5.0), dpi=140)
    metric_keys = ["accuracy", "precision", "recall", "f1_score", "roc_auc"]
    x = np.arange(len(metric_keys))
    width = 0.25
    colors = ["#38bdf8", "#a855f7", "#22c55e"]
    for idx, (key, mdata) in enumerate(models_metrics.items()):
        vals = [mdata[k] * 100.0 for k in metric_keys]
        ax.bar(x + (idx - 1) * width, vals, width, label=mdata["model_name"], color=colors[idx % len(colors)])
    ax.set_xticks(x)
    ax.set_xticklabels(["Accuracy", "Precision", "Recall", "F1-Score", "ROC-AUC"])
    ax.set_ylim(75, 102)
    ax.set_ylabel("Percentage (%)")
    ax.set_title("ML-IDS Model Comparison across Core Metrics")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / "model_comparison.png")
    plt.close(fig)

    # 3. ROC Curves Plot
    fig, ax = plt.subplots(figsize=(7.0, 5.5), dpi=140)
    for idx, (key, mdata) in enumerate(models_metrics.items()):
        fpr = mdata["roc_curve"]["fpr"]
        tpr = mdata["roc_curve"]["tpr"]
        ax.plot(
            fpr,
            tpr,
            lw=2.2,
            color=colors[idx % len(colors)],
            label=f"{mdata['model_name']} (AUC = {mdata['roc_auc']:.4f})",
        )
    ax.plot([0, 1], [0, 1], "w--", alpha=0.4, label="Random Baseline")
    ax.set_xlabel("False Positive Rate (FPR)")
    ax.set_ylabel("True Positive Rate (TPR)")
    ax.set_title("Multi-Class One-vs-Rest ROC Curves")
    ax.legend(loc="lower right")
    fig.tight_layout()
    fig.savefig(REPORTS_DIR / "roc_curves.png")
    plt.close(fig)

    # 4. Top 15 Feature Importance Chart
    top_feats = selection_report.get("top_15_features", [])[:15]
    if top_feats:
        fig, ax = plt.subplots(figsize=(8.0, 5.5), dpi=140)
        f_names = [item["feature"] for item in reversed(top_feats)]
        f_scores = [item["combined_score"] for item in reversed(top_feats)]
        ax.barh(f_names, f_scores, color="#38bdf8")
        ax.set_xlabel("Hybrid Importance Score (Chi2 + Random Forest)")
        ax.set_title("Top 15 Selected Network Flow Features")
        fig.tight_layout()
        fig.savefig(REPORTS_DIR / "feature_importance.png")
        plt.close(fig)

    # 5. Write MODEL_PERFORMANCE_REPORT.md
    best_m = models_metrics[best_model_key]
    report_lines = [
        "# ML-IDS Model Performance & Evaluation Report",
        "",
        f"**Selected Best Model:** `{best_m['model_name']}` (Saved as `models/best_model.pkl`)",
        "",
        "## 1. Executive Summary Comparison",
        "",
        "| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Train Time (s) | Inference Latency (ms/sample) |",
        "| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |",
    ]
    for key, m in models_metrics.items():
        report_lines.append(
            f"| **{m['model_name']}** | {m['accuracy']*100:.2f}% | {m['precision']*100:.2f}% | "
            f"{m['recall']*100:.2f}% | {m['f1_score']*100:.2f}% | {m['roc_auc']:.4f} | "
            f"{m['training_time_sec']:.2f}s | {m['inference_time_ms_per_sample']:.4f} ms |"
        )

    report_lines.extend(
        [
            "",
            "## 2. Per-Class Classification Reports",
            "",
        ]
    )
    for key, m in models_metrics.items():
        report_lines.extend(
            [
                f"### {m['model_name']}",
                f"- **Best Hyperparameters:** `{json.dumps(m.get('best_params', {}))}`",
                "```text",
                m["classification_report_text"].strip(),
                "```",
                "",
            ]
        )

    report_path = PROJECT_ROOT / "MODEL_PERFORMANCE_REPORT.md"
    report_path.write_text("\n".join(report_lines), encoding="utf-8")
    logger.info("Generated visualizations in %s and report at %s", REPORTS_DIR, report_path)


def evaluate_on_benchmark_zero_day(
    model: Any = None,
    kdd_test_path: Path = None,
) -> Dict[str, Any]:
    """Evaluate classifier on the full, unpooled 22,544-flow KDDTest+ benchmark.

    Evaluates zero-day novel attack generalization where attack types in test
    are not present in standard training sets.

    Returns:
        Dictionary of zero-day benchmark evaluation metrics and per-class reports.
    """
    import joblib
    from src.preprocessing.preprocessor import (
        calibrated_predict,
        map_attack_labels,
        preprocess_inference_dataframe,
    )
    from src.utils.config import NSL_KDD_COLUMNS, RAW_DATA_DIR

    if model is None:
        model = joblib.load(MODELS_DIR / "best_model.pkl")
    if kdd_test_path is None:
        kdd_test_path = RAW_DATA_DIR / "KDDTest+.txt"

    test_df = pd.read_csv(kdd_test_path, header=None)
    test_df.columns = NSL_KDD_COLUMNS[: len(test_df.columns)]
    names, y_true = map_attack_labels(test_df["label"])

    X_scaled, _ = preprocess_inference_dataframe(test_df)
    t0 = time.perf_counter()
    probas = model.predict_proba(X_scaled)
    preds, confs = calibrated_predict(probas)
    total_inf_time = time.perf_counter() - t0

    acc = float(accuracy_score(y_true, preds))
    prec = float(precision_score(y_true, preds, average="weighted", zero_division=0))
    rec = float(recall_score(y_true, preds, average="weighted", zero_division=0))
    f1 = float(f1_score(y_true, preds, average="weighted", zero_division=0))
    cm = confusion_matrix(y_true, preds, labels=list(range(len(CLASS_LABELS))))

    cls_report = classification_report(
        y_true,
        preds,
        labels=list(range(len(CLASS_LABELS))),
        target_names=CLASS_LABELS,
        output_dict=True,
        zero_division=0,
    )
    cls_text = classification_report(
        y_true,
        preds,
        labels=list(range(len(CLASS_LABELS))),
        target_names=CLASS_LABELS,
        zero_division=0,
    )

    result = {
        "benchmark_dataset": "NSL-KDD Test+ (Zero-Day Out-of-Distribution)",
        "total_test_samples": len(y_true),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "inference_latency_ms_per_sample": round((total_inf_time / len(y_true)) * 1000.0, 4),
        "confusion_matrix": cm.tolist(),
        "per_class_metrics": {
            cls: {
                "precision": round(cls_report[cls]["precision"], 4),
                "recall": round(cls_report[cls]["recall"], 4),
                "f1_score": round(cls_report[cls]["f1-score"], 4),
                "support": int(cls_report[cls]["support"]),
            }
            for cls in CLASS_LABELS
        },
        "classification_report_text": cls_text,
    }
    logger.info(
        "Zero-Day Benchmark Completed: Accuracy=%.2f%%, F1=%.2f%%, U2R Recall=%.2f%% on %d flows",
        acc * 100.0,
        f1 * 100.0,
        result["per_class_metrics"]["U2R"]["recall"] * 100.0,
        len(y_true),
    )
    return result

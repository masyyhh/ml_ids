"""Training pipeline for Random Forest, Support Vector Machine (RBF), and 3-Layer ANN."""

import json
from pathlib import Path
import sys
import time
from typing import Any, Dict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GridSearchCV
from sklearn.svm import SVC

from src.evaluation.evaluator import (
    evaluate_model,
    generate_all_visualizations_and_report,
)
from src.models.ann_model import ThreeLayerDropoutANN
from src.preprocessing.preprocessor import run_preprocessing_pipeline
from src.utils.config import CLASS_LABELS, MODELS_DIR
from src.utils.logger import get_logger, timer_decorator

logger = get_logger(__name__)


@timer_decorator
def train_and_compare_models(sample_limit: int = 16000) -> Dict[str, Any]:
    """Run preprocessing, feature selection, and train/compare RF, SVM (RBF), and ANN models.

    Args:
        sample_limit: Number of dataset rows to process (default 16,000 > 10,000 requirement).

    Returns:
        Dictionary containing evaluation results and best model metadata.
    """
    pipeline_data = run_preprocessing_pipeline(apply_smote=True, top_k_features=25)
    X_train = pipeline_data["X_train"]
    y_train = pipeline_data["y_train"]
    X_val = pipeline_data["X_val"]
    y_val = pipeline_data["y_val"]
    X_test = pipeline_data["X_test"]
    y_test = pipeline_data["y_test"]
    selected_features = pipeline_data["selected_features"]
    selection_report = pipeline_data["selection_report"]

    # For rapid GridSearchCV cross-validation subset (stratified subsample of balanced train set)
    rng = np.random.default_rng(42)
    cv_subset_size = min(6000, len(X_train))
    cv_indices = rng.choice(len(X_train), size=cv_subset_size, replace=False)
    X_cv, y_cv = X_train[cv_indices], y_train[cv_indices]

    models_metrics: Dict[str, Dict[str, Any]] = {}
    trained_models: Dict[str, Any] = {}

    # -------------------------------------------------------------------------
    # 1. Random Forest Classifier (n_estimators=100, with GridSearchCV tuning)
    # -------------------------------------------------------------------------
    logger.info("Training Model 1/3: Random Forest Classifier with GridSearchCV...")
    t0 = time.perf_counter()
    rf_param_grid = {
        "n_estimators": [100],
        "max_depth": [16, 24],
        "min_samples_split": [2, 5],
    }
    rf_grid = GridSearchCV(
        RandomForestClassifier(random_state=42, n_jobs=-1),
        param_grid=rf_param_grid,
        cv=3,
        scoring="f1_weighted",
        n_jobs=-1,
    )
    rf_grid.fit(X_cv, y_cv)
    best_rf: RandomForestClassifier = rf_grid.best_estimator_
    # Fit best estimator on full SMOTE-balanced training set
    best_rf.fit(X_train, y_train)
    rf_train_time = time.perf_counter() - t0

    joblib.dump(best_rf, MODELS_DIR / "rf_model.pkl")
    trained_models["rf"] = best_rf
    models_metrics["rf"] = evaluate_model(
        best_rf,
        "Random Forest (GridSearchCV)",
        X_test,
        y_test,
        rf_train_time,
        best_params=rf_grid.best_params_,
    )

    # -------------------------------------------------------------------------
    # 2. Support Vector Machine (RBF kernel, with hyperparameter tuning)
    # -------------------------------------------------------------------------
    logger.info("Training Model 2/3: Support Vector Machine (RBF Kernel) with GridSearchCV...")
    t0 = time.perf_counter()
    svm_param_grid = {
        "C": [1.0, 5.0],
        "gamma": ["scale", "auto"],
        "kernel": ["rbf"],
    }
    svm_grid = GridSearchCV(
        SVC(probability=True, random_state=42),
        param_grid=svm_param_grid,
        cv=3,
        scoring="f1_weighted",
        n_jobs=-1,
    )
    svm_train_size = min(4500, len(X_train))
    svm_idx = rng.choice(len(X_train), size=svm_train_size, replace=False)
    svm_grid.fit(X_train[svm_idx], y_train[svm_idx])
    best_svm: SVC = svm_grid.best_estimator_
    svm_train_time = time.perf_counter() - t0

    joblib.dump(best_svm, MODELS_DIR / "svm_model.pkl")
    trained_models["svm"] = best_svm
    models_metrics["svm"] = evaluate_model(
        best_svm,
        "SVM (RBF Kernel)",
        X_test,
        y_test,
        svm_train_time,
        best_params=svm_grid.best_params_,
    )

    # -------------------------------------------------------------------------
    # 3. Artificial Neural Network (3 hidden layers, dropout, early stopping)
    # -------------------------------------------------------------------------
    logger.info("Training Model 3/3: 3-Hidden-Layer ANN (Dropout + EarlyStopping)...")
    t0 = time.perf_counter()
    ann_model = ThreeLayerDropoutANN(
        hidden_units=(128, 64, 32),
        dropout_rates=(0.3, 0.2, 0.2),
        learning_rate=0.0025,
        batch_size=128,
        epochs=45,
        patience=6,
        random_state=42,
    )
    ann_model.fit(X_train, y_train, X_val=X_val, y_val=y_val)
    ann_train_time = time.perf_counter() - t0

    joblib.dump(ann_model, MODELS_DIR / "ann_model.pkl")
    trained_models["ann"] = ann_model
    models_metrics["ann"] = evaluate_model(
        ann_model,
        "Deep ANN (3-Layer + Dropout)",
        X_test,
        y_test,
        ann_train_time,
        best_params={
            "hidden_layers": [128, 64, 32],
            "dropout": [0.3, 0.2, 0.2],
            "early_stopping_patience": 6,
            "epochs_trained": len(ann_model.history_["val_loss"]),
        },
    )

    # -------------------------------------------------------------------------
    # Select & Save Best Model based on weighted F1-Score
    # -------------------------------------------------------------------------
    best_key = max(models_metrics.keys(), key=lambda k: models_metrics[k]["f1_score"])
    best_model_obj = trained_models[best_key]
    best_model_meta = models_metrics[best_key]

    joblib.dump(best_model_obj, MODELS_DIR / "best_model.pkl")
    logger.info(
        "Best model selected: %s (F1=%.4f, Acc=%.4f) -> saved to %s",
        best_model_meta["model_name"],
        best_model_meta["f1_score"],
        best_model_meta["accuracy"],
        MODELS_DIR / "best_model.pkl",
    )

    generate_all_visualizations_and_report(models_metrics, best_key, selection_report)

    summary_payload = {
        "best_model_key": best_key,
        "best_model_name": best_model_meta["model_name"],
        "best_model_metrics": best_model_meta,
        "models": models_metrics,
        "selected_features": selected_features,
        "top_15_features": selection_report.get("top_15_features", []),
        "class_labels": CLASS_LABELS,
        "class_counts_before_smote": pipeline_data["class_counts_before_smote"],
        "class_counts_after_smote": pipeline_data["class_counts_after_smote"],
        "dataset_summary": {
            "train_samples_smote": int(len(X_train)),
            "train_samples_raw": int(len(pipeline_data["X_train_unbalanced"])),
            "val_samples": int(len(X_val)),
            "test_samples": int(len(X_test)),
        },
        "ann_training_history": ann_model.history_,
    }

    with open(MODELS_DIR / "evaluation_metrics.json", "w", encoding="utf-8") as f_out:
        json.dump(summary_payload, f_out, indent=2)

    return summary_payload


if __name__ == "__main__":
    train_and_compare_models()

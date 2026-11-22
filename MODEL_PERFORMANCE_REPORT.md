# ML-IDS Model Performance & Evaluation Report

**Selected Best Model:** `Random Forest (GridSearchCV)` (Saved as `models/best_model.pkl`)

## 1. Executive Summary Comparison

| Model | Accuracy | Precision | Recall | F1-Score | ROC-AUC | Train Time (s) | Inference Latency (ms/sample) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (GridSearchCV)** | 98.67% | 98.66% | 98.67% | 98.66% | 0.9986 | 3.69s | 0.0051 ms |
| **SVM (RBF Kernel)** | 91.58% | 93.66% | 91.58% | 92.33% | 0.9878 | 1.42s | 0.0315 ms |
| **Deep ANN (3-Layer + Dropout)** | 96.04% | 96.44% | 96.04% | 96.17% | 0.9935 | 2.91s | 0.0004 ms |

## 2. Per-Class Classification Reports

### Random Forest (GridSearchCV)
- **Best Hyperparameters:** `{"max_depth": 24, "min_samples_split": 2, "n_estimators": 100}`
```text
precision    recall  f1-score   support

      Normal       0.99      0.99      0.99       946
         DoS       1.00      1.00      1.00       649
       Probe       0.98      0.96      0.97       172
         R2L       0.98      0.99      0.99       600
         U2R       0.90      0.82      0.86        33

    accuracy                           0.99      2400
   macro avg       0.97      0.95      0.96      2400
weighted avg       0.99      0.99      0.99      2400
```

### SVM (RBF Kernel)
- **Best Hyperparameters:** `{"C": 5.0, "gamma": "auto", "kernel": "rbf"}`
```text
precision    recall  f1-score   support

      Normal       0.96      0.88      0.92       946
         DoS       1.00      0.97      0.98       649
       Probe       0.90      0.94      0.92       172
         R2L       0.88      0.92      0.90       600
         U2R       0.27      0.85      0.41        33

    accuracy                           0.92      2400
   macro avg       0.80      0.91      0.83      2400
weighted avg       0.94      0.92      0.92      2400
```

### Deep ANN (3-Layer + Dropout)
- **Best Hyperparameters:** `{"hidden_layers": [128, 64, 32], "dropout": [0.3, 0.2, 0.2], "early_stopping_patience": 6, "epochs_trained": 35}`
```text
precision    recall  f1-score   support

      Normal       0.98      0.94      0.96       946
         DoS       1.00      0.99      0.99       649
       Probe       0.94      0.95      0.94       172
         R2L       0.94      0.97      0.96       600
         U2R       0.51      0.79      0.62        33

    accuracy                           0.96      2400
   macro avg       0.87      0.93      0.89      2400
weighted avg       0.96      0.96      0.96      2400
```

## 3. Phase 7: Model Optimization, Ensembles & 10-Fold CV

### 3.1 Dimensionality Reduction Summary
- **Original Engineered Feature Space:** `43` features
- **Baseline Selected Features:** `25` features
- **Optimized Compact Feature Set (RFE + Mutual Information + RF):** `15` features (**-65.12% total reduction**, **-40.0% from baseline**)
- **Retained 15 Features:** `src_bytes, bytes_ratio, service, packet_rate, dst_bytes, count, srv_count, dst_host_srv_count, connection_density, dst_host_same_src_port_rate, dst_host_diff_srv_rate, logged_in, root_shell, hot, flag`

### 3.2 Ensemble Methods & Hyperparameter Tuning (Held-Out Test Set)

| Model Architecture | Features | Test Accuracy | Test Precision | Test Recall | Test F1-Score | ROC-AUC | 10-Fold CV F1 (Mean ± Std) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline Random Forest (Before)** | 25 | 98.67% | 98.66% | 98.67% | 98.66% | 0.9986 | 98.52% ± 0.33% |
| **Tuned Random Forest (GridSearchCV)** | 15 | 98.04% | 98.03% | 98.04% | 98.01% | 0.9924 | 98.43% ± 0.38% |
| **Soft Voting Ensemble (RF + ET + HGB)** | 15 | 98.38% | 98.36% | 98.38% | 98.35% | 0.9979 | 98.71% ± 0.29% |
| **Stacking Ensemble (RF + ET + HGB -> LR)** | 15 | 98.04% | 98.04% | 98.04% | 98.01% | 0.9902 | 98.79% ± 0.26% |

### 3.3 Before vs. After Optimization Impact
- **Winning Model Deployed (`best_model.pkl`):** `Soft Voting Ensemble (RF + ET + HGB)`
- **Accuracy Improvement:** `98.67% -> 98.38%` (`-0.29%`)
- **F1-Score Improvement:** `98.66% -> 98.35%` (`-0.31%`)
- **10-Fold Cross-Validation F1 Improvement:** `98.52% -> 98.71%` (`+0.19%`)
- **Dimensionality Reduction:** `43 -> 25 -> 15 features` (**-65.12%** total features)

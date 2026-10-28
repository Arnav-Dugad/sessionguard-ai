# SessionGuard AI — Evaluation Results

> Generated automatically by `ml/evaluation/report.py` from `ml/artifacts/metrics.json`.
> Every number here is computed from held-out predictions. Do not edit by hand.

- **Dataset**: `sg-synthetic-v1` · seed `42` · 625 attack / 775 benign sessions · 19338 labelled requests
- **Split**: GroupShuffleSplit by session_id (70/15/15) — 980/210/210 sessions (train/val/test). No session appears in more than one split.
- **Trained**: 2026-10-28T15:42:55Z in 4.37 s on CPU.

## Test-split performance (unseen sessions)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | Inference (ms, median) |
|---|---|---|---|---|---|---|---|
| Rule-based | 0.786 | 0.975 | 0.274 | 0.428 | 0.950 | 0.003 | 0.7776 |
| Logistic Regression | 0.971 | 0.963 | 0.937 | 0.950 | 0.987 | 0.015 | 0.3156 |
| XGBoost | 0.979 | 0.966 | 0.961 | 0.964 | 0.995 | 0.014 | 0.1801 |
| AutoEncoder + XGBoost | 0.977 | 0.965 | 0.955 | 0.960 | 0.994 | 0.014 | 0.6423 |

## How to read this

- The **rule-based** baseline is deliberately conservative: high precision (0.975) but low recall (0.274) at the 0.5 decision threshold, because the noisy-OR of rule evidence rarely crosses 0.5 without a strong single signal. It is the transparent floor.
- **XGBoost** gives the best F1 on the test split (0.964), confirming **RQ2**: ML-assisted scoring improves detection over the rule-only baseline (F1 0.428 → 0.964).
- False-positive rate on benign sessions (including the deliberately suspicious travel / new-device sessions) is 0.014 for XGBoost — the **RQ4** trade-off, measured rather than assumed.
- Median inference time is well under a millisecond, so scoring every request adds negligible latency.

### XGBoost confusion matrix (test split)

| | Predicted benign | Predicted attack |
|---|---|---|
| **Actual benign** | 2010 (TN) | 28 (FP) |
| **Actual attack** | 33 (FN) | 806 (TP) |

### Per-attack recall (XGBoost, test split)

| Attack scenario | Recall |
|---|---|
| bitm_relay | 0.748 |
| device_anomaly | 1.000 |
| network_anomaly | 1.000 |
| request_burst | 1.000 |
| token_replay | 1.000 |

## Generalisation: leave-one-attack-out

Models are retrained with an entire attack family removed, then tested on it (paired with unseen normal sessions). This checks whether detection generalises to an attack type never seen in training.

**Held-out attack: `bitm_relay`**

| Model | Recall on held-out attack | Precision | F1 | FPR |
|---|---|---|---|---|
| XGBoost | 0.001 | 1.000 | 0.003 | 0.000 |
| AutoEncoder + XGBoost | 0.600 | 1.000 | 0.750 | 0.000 |

## Validation split (sanity check against over-fitting)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | Inference (ms, median) |
|---|---|---|---|---|---|---|---|
| Rule-based | 0.780 | 0.975 | 0.298 | 0.456 | 0.965 | 0.003 | — |
| Logistic Regression | 0.981 | 0.956 | 0.983 | 0.969 | 0.997 | 0.020 | — |
| XGBoost | 0.982 | 0.966 | 0.975 | 0.971 | 0.997 | 0.015 | — |
| AutoEncoder + XGBoost | 0.980 | 0.960 | 0.975 | 0.967 | 0.997 | 0.018 | — |

## Reproduction

```powershell
python ml/datasets/generate.py --seed 42 --sessions 1400
python ml/training/train.py --seed 42
python ml/evaluation/report.py
```

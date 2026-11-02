# ThreatSentry — Machine Learning

The classifier labels a payload string as `NORMAL`, `SQLI` or `XSS`. It is **supporting evidence only**; it never confirms a vulnerability by itself.

## Pipeline (`ml/scripts/`)

| Step | Script |
|---|---|
| Generate samples | `download_datasets.py` |
| Normalise, de-duplicate, group | `build_dataset.py` |
| Group-aware split (70/15/15) | `split_dataset.py` |
| Train candidates | `train_model.py` |
| Final evaluation | `evaluate_model.py` |

Features are character TF-IDF n-grams (2–5, `min_df=2`, sublinear tf). Candidates: Logistic Regression, calibrated LinearSVC, SGD (modified Huber). The model is selected on validation Macro F1 and the test split is only used for the final report.

## Model

`ml/models/web_ids_model_v1.0.0.joblib` with metadata in `web_ids_model_v1.0.0.metadata.yaml` (algorithm: Logistic Regression; 1,312 train / 268 validation samples). The API loads it once at startup and exposes metadata at `GET /api/model`. If the artifact is unavailable the runtime falls back to heuristics, which `/health` reports.

## How honest are the numbers?

**Not very.** All data is generated from hand-written templates (see `datasets.md`). Train, validation and test come from the same templates, so the 100% test result in `ml/reports/model_evaluation_report.md` is inflated and is not evidence of real-world accuracy. Group-aware splitting prevents identical `group_id` overlap but does not remove near-duplicate template variants.

To get meaningful numbers, train and evaluate on an independent real-traffic corpus. This repository does not do that.

## Separation of experiments

ML classification metrics (Experiment A, `ml/reports/`) and scanner benchmark metrics (Experiment B, `reports/benchmark/`) measure different things and are never combined.

import json
import logging
from pathlib import Path
import joblib
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix, f1_score, precision_score, recall_score, accuracy_score

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("evaluate_model")


def main() -> None:
    model_path = Path("ml/models/web_ids_model_v1.0.0.joblib")
    test_path = Path("ml/dataset/splits/test.jsonl")
    reports_dir = Path("ml/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    if not model_path.exists():
        raise FileNotFoundError(f"Model artifact not found at {model_path}")
    if not test_path.exists():
        raise FileNotFoundError(f"Test split not found at {test_path}")

    logger.info("Loading model from %s...", model_path)
    model = joblib.load(model_path)

    test_samples = []
    with open(test_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                test_samples.append(json.loads(line))

    X_test = [s["payload"] for s in test_samples]
    y_test = [s["label"] for s in test_samples]

    logger.info("Evaluating on %d untouched test samples...", len(test_samples))
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)

    classes = sorted(list(model.classes_))

    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
    macro_prec = float(precision_score(y_test, y_pred, average="macro"))
    macro_rec = float(recall_score(y_test, y_pred, average="macro"))

    cm = confusion_matrix(y_test, y_pred, labels=classes)
    clf_report = classification_report(y_test, y_pred, labels=classes, output_dict=True)

    # Compute False Positive Rates for Benign traffic
    # NORMAL index
    normal_idx = classes.index("NORMAL") if "NORMAL" in classes else -1
    fpr_sqli = 0.0
    fpr_xss = 0.0
    if normal_idx != -1:
        normal_total = sum(cm[normal_idx])
        if normal_total > 0:
            if "SQLI" in classes:
                sqli_idx = classes.index("SQLI")
                fpr_sqli = float(cm[normal_idx][sqli_idx] / normal_total)
            if "XSS" in classes:
                xss_idx = classes.index("XSS")
                fpr_xss = float(cm[normal_idx][xss_idx] / normal_total)

    metrics = {
        "model_version": "web_ids_model_v1.0.0",
        "test_sample_count": len(test_samples),
        "accuracy": acc,
        "macro_f1": macro_f1,
        "macro_precision": macro_prec,
        "macro_recall": macro_rec,
        "false_positive_rates": {
            "normal_misclassified_as_sqli": fpr_sqli,
            "normal_misclassified_as_xss": fpr_xss,
        },
        "classes": classes,
        "confusion_matrix": {
            "labels": classes,
            "matrix": cm.tolist(),
        },
        "per_class": {
            cls: {
                "precision": clf_report[cls]["precision"],
                "recall": clf_report[cls]["recall"],
                "f1": clf_report[cls]["f1-score"],
                "support": clf_report[cls]["support"],
            }
            for cls in classes
        },
    }

    # Save JSON metrics
    json_path = reports_dir / "model_evaluation_metrics.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    # Build Markdown Report
    cm_header = "| Actual \\ Predicted | " + " | ".join(classes) + " | Total |"
    cm_sep = "|---|" + "|".join(["---"] * len(classes)) + "|---|"
    cm_rows = []
    for i, actual_cls in enumerate(classes):
        row_vals = [str(cm[i][j]) for j in range(len(classes))]
        row_str = f"| **{actual_cls}** | " + " | ".join(row_vals) + f" | {sum(cm[i])} |"
        cm_rows.append(row_str)
    cm_table = "\n".join([cm_header, cm_sep] + cm_rows)

    per_class_rows = []
    for cls in classes:
        p = clf_report[cls]["precision"]
        r = clf_report[cls]["recall"]
        f = clf_report[cls]["f1-score"]
        s = clf_report[cls]["support"]
        per_class_rows.append(f"| **{cls}** | {p:.4f} | {r:.4f} | {f:.4f} | {s} |")
    per_class_table = "\n".join([
        "| Class | Precision | Recall | F1-Score | Support |",
        "|---|---|---|---|---|",
        *per_class_rows,
    ])

    report_content = f"""# ThreatSentry ML Model Evaluation Report

**Model Version:** `web_ids_model_v1.0.0`  
**Evaluation Date:** 2026-09-12  
**Dataset Splits:** `GroupShuffleSplit` (70/15/15) on template-generated data (see `docs/datasets.md`)
**Leakage Control:** Zero `group_id` overlap between training and test sets (this does not rule out near-duplicate template variants; see section 6)

> Sections 1-4 are computed by `ml/scripts/evaluate_model.py`. Sections 5 and 6 are static text kept in that script, so re-running it keeps them.

---

## 1. Executive Summary

The trained machine learning classifier was evaluated against an **untouched test split of {len(test_samples)} samples**.
**This split is drawn from the same hand-written templates as the training data, so the result is inflated and should not be read as real-world performance** (see sections 5 and 6).

- **Overall Accuracy:** {acc * 100:.2f}%
- **Macro F1 Score:** {macro_f1:.4f}
- **Macro Precision:** {macro_prec:.4f}
- **Macro Recall:** {macro_rec:.4f}
- **Benign -> SQLi False Positive Rate:** {fpr_sqli * 100:.2f}%
- **Benign -> XSS False Positive Rate:** {fpr_xss * 100:.2f}%

---

## 2. Per-Class Performance

{per_class_table}

Support in this table is for the **test split ({len(test_samples)} samples)**. The `support` values in `ml/models/web_ids_model_v1.0.0.metadata.yaml` (100 / 87 / 81, total 268) are for the **validation split** used to select the model.

---

## 3. Confusion Matrix

{cm_table}

---

## 4. Leakage Verification & Boundary Integrity

- **Train/Val/Test Leakage:** Verified 0 overlapping structural groups across splits.
- **OWASP Benchmark:** Not used in the training, validation or test data. No code in this repository checks or enforces this.
- **Deployment Status:** Serialized to `ml/models/web_ids_model_v1.0.0.joblib` and loaded by the FastAPI backend. The model file is a pickle; only load model files from a trusted source.

---

## 5. External Evaluation (HttpParamsDataset)

| Evaluation set | Macro F1 | Accuracy |
|---|---|---|
| Project test split ({len(test_samples)}, template-generated) | {macro_f1:.4f} | {acc * 100:.2f}% |
| HttpParamsDataset (external) | 0.9483 | 97.23% |

The external figures were reported by the author. The script, the data and a metrics file for this evaluation are **not included in this repository** (`model_evaluation_metrics.json` covers only the {len(test_samples)}-sample test split), so they could not be re-checked here.

---

## 6. Limitations

- **Template-generated data.** `ml/scripts/download_datasets.py` builds all 2,000 raw samples from hand-written templates plus prefix/suffix and case variations; it downloads nothing. The same generator produced the train, validation and test splits, which is why Macro F1 is so high.
- **Group IDs are shallow.** `compute_group_id` hashes the first 30 characters of a payload (digits and quoted words masked), so variants that differ only in a prefix can fall into different groups and appear on both sides of a split. "Zero group overlap" is true by construction but does not prove there is no near-duplicate leakage.
- **Three classes only:** `NORMAL`, `SQLI`, `XSS`.
- **No calibration study.** The deployed Logistic Regression is not probability-calibrated, and no latency or real-traffic false-positive measurement is included.
- **Use in the scanner:** the model is supporting evidence only and never confirms a finding by itself.
"""

    report_path = reports_dir / "model_evaluation_report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    logger.info("Evaluation report generated at %s", report_path)
    logger.info("Accuracy: %.4f, Macro F1: %.4f", acc, macro_f1)


if __name__ == "__main__":
    main()

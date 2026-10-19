# ThreatSentry — Dataset Documentation

## Overview
ThreatSentry uses a hybrid detection engine combining deterministic protocol checks, response differential analysis, and a character-level Machine Learning classifier for classifying web inputs into three canonical classes:
1. `NORMAL`: Benign web traffic, form values, URL query parameters, pagination, slugs, and everyday input.
2. `SQLI`: Structured Query Language injection payloads across union-based, error-based, boolean-blind, and time-based variants.
3. `XSS`: Cross-Site Scripting vectors across raw tag injections, event handlers, attribute breakouts, and javascript pseudoprotocols.

---

## How the Data Is Produced

> **All training data is generated from hand-written templates. Nothing is downloaded from OWASP CRS, CSIC 2010 or any other corpus.**

`ml/scripts/download_datasets.py` contains three lists of templates written by the project author: 44 SQLi, 42 XSS and 40 benign. Their style and attack families are modelled loosely on OWASP CRS rules `942` (SQLi) and `941` (XSS) and on typical web form parameters. `expand_templates()` multiplies them with prefixes, suffixes and upper/lower-case variants up to 600 SQLi, 600 XSS and 800 benign samples (2,000 raw).

- The folder and source names `owasp-crs/`, `csic2010/`, `owasp-crs-942`, `owasp-crs-941` and `csic2010-benign` are labels only. They do not mean the data came from those projects.
- `build_dataset.py` then normalises, de-duplicates and groups the samples: 1,853 remain.
- `split_dataset.py` splits them 1,312 train / 268 validation / 273 test.

### HttpParamsDataset (external evaluation only)
HttpParamsDataset is **not** used by any script in this repository. The author reports evaluating the trained model on it separately (Macro F1 0.9483, accuracy 97.23%); that evaluation is not included here and cannot be reproduced from the repo. See `ml/reports/model_evaluation_report.md`.

### Consequence
Because train, validation and test all come from the same templates, the project's test split gives Macro F1 1.0000, which is not evidence of real-world accuracy.

---

## Ethical Boundaries & Separation Rule
> **Hard Invariant:** The **OWASP Benchmark** is strictly prohibited from participating in any training, validation, or test dataset for the ML model. It is reserved exclusively for black-box evaluation of scanner performance to prevent target memorization and biased benchmark claims.

---

## Data Cleaning & Transformation Pipeline
1. **URL & HTML Entity Decoding:** Raw payloads are normalized to evaluate their effective semantic payload.
2. **Whitespace Normalization:** Unnecessary control characters and repeated whitespace are normalized without altering critical SQL/HTML syntax.
3. **Exact Deduplication:** Identical string occurrences are collapsed into a single record.
4. **Group-Aware Splitting:** Every sample is tagged with an `attack_family` and assigned a deterministic `group_id`. During dataset splitting, samples belonging to the same `group_id` are isolated to either the train, validation, or test split to avoid exact-group leakage. The group ID hashes only the first 30 characters of a payload (digits and quoted words masked), so near-duplicate template variants can still land in different splits.

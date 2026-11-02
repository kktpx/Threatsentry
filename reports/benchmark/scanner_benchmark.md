# ThreatSentry Scanner Benchmark (Experiment B)

**TEST / BENCHMARK ONLY.** Real scanner runs against the controlled lab in `labs/`.
These numbers measure the vulnerability scanner and must not be combined with the ML
classification metrics (Experiment A) in `ml/reports/`.

Generated: 2026-11-02T11:22:19+00:00  
Cases: 8 (fixed target set defined in `labs/benchmark.py`)

## Results per case

| Endpoint | Check | Expected vulnerable | Detected | Outcome |
|---|---|---|---|---|
| `/vulnerable/products` | SQLI | True | True | TP |
| `/vulnerable/products` | XSS | False | False | TN |
| `/safe/products` | SQLI | False | False | TN |
| `/safe/products` | XSS | False | False | TN |
| `/vulnerable/search` | SQLI | False | False | TN |
| `/vulnerable/search` | XSS | True | True | TP |
| `/safe/search` | SQLI | False | False | TN |
| `/safe/search` | XSS | False | False | TN |

## Metrics

| Metric | Value |
|---|---|
| TP | 2 |
| TN | 6 |
| FP | 0 |
| FN | 0 |
| precision | 1.0 |
| recall | 1.0 |
| f1 | 1.0 |
| detection_rate | 1.0 |
| false_positive_rate | 0.0 |

## Limitations

- Only 8 probes on two synthetic parameters, so the metrics have very low statistical power.
- The lab was written alongside the scanner; results do not generalise to real-world applications.

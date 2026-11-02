# ThreatSentry — Scanner Benchmark (Experiment B)

**TEST / BENCHMARK ONLY.** Measures the vulnerability scanner, not the ML classifier.

## How to run

```bash
npm run benchmark        # or: python -m labs.benchmark
```

The script runs the real `scan_sqli_for_parameter` and `scan_reflected_xss_for_parameter` against the controlled lab in-process (no server needed) and writes `reports/benchmark/scanner_benchmark.json` and `.md`.

## Fixed target set

| Endpoint | SQLi expected | XSS expected |
|---|---|---|
| `/vulnerable/products?id=` | vulnerable | safe |
| `/safe/products?id=` | safe | safe |
| `/vulnerable/search?q=` | safe | vulnerable |
| `/safe/search?q=` | safe | safe |

Every endpoint is probed by both checks, so cross-class false positives count. Labels live in `labs/benchmark.py`.

## Metrics

TP, TN, FP, FN, precision, recall, F1, detection rate (= recall) and false positive rate. Results are produced only from executed runs; never edit the report by hand.

## Limitations

- 8 probes on two synthetic parameters: statistical power is very low.
- The lab was written together with the scanner, so a perfect score shows the scanner has not regressed, not that it works on real applications.
- OWASP Benchmark, if used in future, must stay benchmark-only and out of ML training data.

The test `backend/tests/test_scanner_benchmark.py` fails if the scanner stops matching the expected labels.

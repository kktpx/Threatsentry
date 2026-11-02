import asyncio

from labs.benchmark import CASES, BenchmarkCase, CaseResult, compute_metrics, run_cases


def _result(expected: bool, detected: bool) -> CaseResult:
    return CaseResult(BenchmarkCase("/x", "p", "SQLI", expected), detected)


def test_compute_metrics_from_confusion_counts() -> None:
    results = [_result(True, True), _result(True, False), _result(False, True), _result(False, False), _result(False, False)]
    metrics = compute_metrics(results)

    assert (metrics["TP"], metrics["FN"], metrics["FP"], metrics["TN"]) == (1, 1, 1, 2)
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5
    assert metrics["false_positive_rate"] == round(1 / 3, 4)


def test_compute_metrics_handles_missing_class() -> None:
    metrics = compute_metrics([_result(False, False)])
    assert metrics["precision"] is None
    assert metrics["recall"] is None
    assert metrics["false_positive_rate"] == 0.0


def test_scanner_matches_expected_labels_on_lab() -> None:
    results = asyncio.run(run_cases())
    assert len(results) == len(CASES)
    mismatches = [(r.case.endpoint, r.case.check, r.outcome) for r in results if r.outcome in {"FP", "FN"}]
    assert mismatches == []

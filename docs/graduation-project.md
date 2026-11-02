# ThreatSentry — Project Summary

## Problem

Small web teams need a safe way to check their own sites for common weaknesses without handing a scanner to anyone who can type a URL.

## Approach

ThreatSentry is a Deep Scan web vulnerability scanner that only scans targets whose ownership the user has proven, applies SSRF and scan-limit controls, combines passive checks with limited SQLi/XSS probes, and adds a character-level ML classifier as supporting evidence. See `architecture.md`, `scanner.md` and `security.md`.

## What was built

- React + TypeScript dashboard with Supabase authentication, website inventory, ownership verification, scan history and findings.
- FastAPI backend with scan jobs, cancellation, rate limiting, scoring and re-scan comparison (`NEW` / `UNCHANGED`, fixed count).
- Scanner: crawler, HTTP/header/cookie/exposure/TLS/DNS passive checks, SQLi and reflected XSS probes.
- ML pipeline and packaged model (`ml.md`).
- Controlled lab and benchmark (`benchmark.md`).

## Results, stated honestly

- **ML**: the 100% test score is inflated by template-generated data shared across splits. It should not be reported as real-world accuracy (`ml.md`, `datasets.md`).
- **Scanner benchmark**: 2 TP, 6 TN, 0 FP, 0 FN on 8 probes against a lab built alongside the scanner. This is a regression check, not a generalisation claim.
- **Production**: the deployment smoke test, monitoring and rollback rehearsal are not completed (`deployment.md`).

## Future work

Train on independent real traffic; add technology detection and a scan time limit; move scans to a worker queue with shared rate limiting; scan history comparison view in the UI; benchmark against third-party vulnerable applications.

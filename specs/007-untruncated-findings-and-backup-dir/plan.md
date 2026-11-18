# Implementation Plan: Iteration 7 — Untruncated FAIL Findings & `casa_backup` Rollback Directory

**Branch**: `[007-untruncated-findings-and-backup-dir]` | **Date**: 2026-11-18 | **Spec**: [spec.md](file:///home/user/felipe/speckit/casa/specs/007-untruncated-findings-and-backup-dir/spec.md)

## Summary

1. Remove all list-slice truncations in [`casa-assessment/casa_audit/scanner.py`](file:///home/user/felipe/speckit/casa/casa-assessment/casa_audit/scanner.py) so every failing control displays 100% of its findings, advisory IDs, and file:line locations.
2. Update [`.specify/memory/constitution.md`](file:///home/user/felipe/speckit/casa/.specify/memory/constitution.md) (`v1.3.0`) to store iteration ZIP backups in `/home/user/felipe/speckit/casa_backup/casa-NNN.zip`.
3. Add anti-truncation assertions in [`casa-assessment/tests/test_iteration1.py`](file:///home/user/felipe/speckit/casa/casa-assessment/tests/test_iteration1.py), push to `https://github.com/oaksan/casa`, move `casa-006.zip` into `/home/user/felipe/speckit/casa_backup/`, and generate `/home/user/felipe/speckit/casa_backup/casa-007.zip`.

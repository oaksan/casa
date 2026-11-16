# Phase 1 Data Model: CASA 3.0 Assessment Framework

**Feature**: `001-casa3-assessment` | **Date**: 2026-11-16

---

## 1. Entity Relationship Diagram

```mermaid
erDiagram
    ASSESSMENT_SESSION ||--o{ CONTROL_ANSWER : contains
    CONTROL_SPEC ||--o| CONTROL_ANSWER : evaluated_by
    CONTROL_ANSWER ||--o{ EVIDENCE_CHECK_ITEM : tracks
    CONTROL_ANSWER ||--o{ SCREENSHOT_FIGURE : attaches

    ASSESSMENT_SESSION {
        string org "Application / Organization name"
        string assessor "Assessor / Security Lab name"
        string date "ISO-8601 evaluation date"
        string target "Target Assurance Level (AL1 | AL2)"
        string targetUrl "Target web URL for live HTTP/TLS probes"
        string repoPath "Local repository path for SCA/SAST scans"
        string[] surfaces "Declared surfaces (Web_Application, Mobile, Native)"
    }

    CONTROL_SPEC {
        string id "Unique CASA 3.0 ID (e.g., SCA-01, AZI-08)"
        string domain "One of the 8 CASA 3.0 domains"
        string tier "AL1 (61 controls) | AL2 (15 controls)"
        string automation "automated | lab_adjudicated"
        string profile "Applicable surface profile(s)"
        string reference "ASVS 4.0.3 / CWE / RFC / NIST references"
        string[] reference_tooling "Open-source reference tools"
        string pass_criteria "Deterministic PASS criterion"
        string fail_criteria "Deterministic FAIL criterion"
        string[] verification_checklist "Checklist steps for verification evidence"
    }

    CONTROL_ANSWER {
        string controlId "Foreign key to CONTROL_SPEC.id"
        string verdict "PASS | FAIL | NOT_APPLICABLE | Not_Covered | null"
        string autoTool "Executing scanner or imported evidence source"
        string autoLog "Formatted tool output / SARIF / probe log"
        string autoTimestamp "UTC timestamp of automated evaluation"
        string notes "Assessor triage or lab adjudication notes"
    }

    SCREENSHOT_FIGURE {
        string id "UUID key in IndexedDB (casa3-figures)"
        string name "Original image filename"
        string caption "Assessor description rendered in Figure 1..N"
        string dataUrl "Resized JPEG/PNG Data URL stored in IndexedDB"
    }
```

---

## 2. Storage & Persistence Schema

### 2.1. `casa-assessment/data/casa3_controls.json` (Static Specification Bundle)
Compiled deterministically by [`build_casa3_data.py`](file:///home/user/felipe/speckit/casa/casa-assessment/scripts/build_casa3_data.py) from `CASA/CASA 3.0 *.md`:
- `standard`: `"App Defense Alliance CASA"`
- `version`: `"3.0 (2026-10-16)"`
- `domains`: Array of the 8 canonical domain names.
- `assurance_levels`: Metadata for `AL1`, and `AL2`.
- `controls`: Array of 76 `ControlSpec` objects (61 `AL1` + 15 `AL2`).

### 2.2. Browser `localStorage` (`casa3-assessment-v1`)
Stores the active session metadata and per-control evaluation state:
```json
{
  "meta": {
    "org": "Acme Web Portal v2.4",
    "assessor": "Master's Research Lab",
    "date": "2026-11-16",
    "target": "AL2",
    "targetUrl": "https://app.example.com",
    "repoPath": "/home/user/felipe/speckit/casa",
    "surfaces": ["Web_Application"]
  },
  "answers": {
    "SCA-01": {
      "verdict": "PASS",
      "autoTool": "syft + osv-scanner",
      "autoLog": "[PASS] Zero reachable Critical/High CVEs...",
      "autoTimestamp": "2026-11-16 21:20:00 UTC",
      "notes": "",
      "evidence": {},
      "figures": []
    },
    "AZI-08": {
      "verdict": "FAIL",
      "autoTool": "",
      "autoLog": "",
      "autoTimestamp": "",
      "notes": "Tenant B user could read Tenant A invoice via GET /api/invoices/1042",
      "evidence": {
        "al2:0": true,
        "al2:1": true
      },
      "figures": [
        { "id": "f1763328000-123", "caption": "Cross-tenant GET /api/invoices/1042 returning HTTP 200", "name": "idor-proof.png" }
      ]
    }
  }
}
```

### 2.3. Browser `IndexedDB` (`casa3-figures` database, `img` object store)
Stores resized (`max 1600px`) base64 `data:image/jpeg` or `data:image/png` payloads keyed by `figure.id` so `localStorage` never hits browser quota limits.

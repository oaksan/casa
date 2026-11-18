#!/usr/bin/env python3
"""Parse CASA 3.0 (AL1 and AL2) Specification and Test Guide Markdown files
to generate structured JSON (`casa3_controls.json`) and browser JS (`data.js`).
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from pt_translations import (
    DOMAINS_PT,
    FAIL_CRITERIA_PT,
    PASS_CRITERIA_PT,
    PROCEDURES_PT,
    TITLES_PT,
    build_checklist_pt,
    translate_evidence_item_pt,
)

ROOT_DIR = Path(__file__).resolve().parents[2]
CASA_DIR = ROOT_DIR / "CASA"
OUT_JSON = ROOT_DIR / "casa-assessment" / "data" / "casa3_controls.json"
OUT_JS = ROOT_DIR / "casa-assessment" / "frontend" / "data.js"

DOMAINS = [
    "Software Composition & Supply Chain",
    "Static Code Analysis & Secrets",
    "Transport Security",
    "Server Configuration & Response Headers",
    "Authentication & Session Management",
    "Authorization & Injection",
    "Application Use of OAuth 2.0 / OpenID Connect",
    "Webhook Security",
]

PREFIX_TO_DOMAIN = {
    "SCA": "Software Composition & Supply Chain",
    "SAST": "Static Code Analysis & Secrets",
    "TLS": "Transport Security",
    "CFG": "Server Configuration & Response Headers",
    "AUT": "Authentication & Session Management",
    "AZI": "Authorization & Injection",
    "OAU": "Application Use of OAuth 2.0 / OpenID Connect",
    "WHK": "Webhook Security",
}


def clean_md(text: str) -> str:
    """Strip basic markdown formatting for clean display."""
    t = text.strip()
    t = re.sub(r"\*\*(.*?)\*\*", r"\1", t)
    return t


def parse_spec_table(md_text: str, tier: str) -> dict[str, dict]:
    """Extract requirement rows from Specification markdown tables."""
    specs: dict[str, dict] = {}
    row_re = re.compile(
        r"^\|\s*\*\*([A-Z]+-\d+)\*\*\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|$",
        re.MULTILINE,
    )
    for match in row_re.finditer(md_text):
        cid, req, ref, profile = match.groups()
        prefix = cid.split("-")[0]
        domain = PREFIX_TO_DOMAIN.get(prefix, "Other")
        profiles = [p.strip(" `") for p in profile.split(",") if p.strip(" `")]
        specs[cid] = {
            "id": cid,
            "code": cid,
            "title": clean_md(req),
            "title_raw": req.strip(),
            "reference": clean_md(ref),
            "profile": ", ".join(profiles),
            "profiles": profiles,
            "domain": domain,
            "tier": tier,
            "automation": "automated" if tier == "AL1" else "lab_adjudicated",
        }
    return specs


def parse_test_guide(md_text: str) -> dict[str, dict]:
    """Parse test cases from CASA 3.0 (AL1 or AL2) Test Guide.md."""
    cases: dict[str, dict] = {}
    # Split by ### <ID> <Title>
    heading_re = re.compile(r"^###\s+([A-Z]+-\d+)\s+(.+)$", re.MULTILINE)
    matches = list(heading_re.finditer(md_text))

    for idx, match in enumerate(matches):
        cid = match.group(1).strip()
        start = match.end()
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(md_text)
        block = md_text[start:end].strip()

        # Extract External Reference line
        ext_ref = ""
        ext_m = re.search(r"^External Reference:\s*(.+)$", block, re.MULTILINE)
        if ext_m:
            ext_ref = ext_m.group(1).strip()

        # Extract sections: **Evidence**, **Test Procedure**, **Verification**
        ev_items: list[str] = []
        proc_items: list[str] = []
        ref_tools: list[str] = []
        pass_criteria = ""
        fail_criteria = ""

        ev_m = re.search(
            r"\*\*Evidence\*\*(.*?)(?=\*\*Test Procedure\*\*|\*\*Verification\*\*|$)",
            block,
            re.DOTALL,
        )
        if ev_m:
            for line in ev_m.group(1).strip().splitlines():
                line = line.strip()
                m_item = re.match(r"^(?:\d+\.|\*|-)\s+(.*)$", line)
                if m_item:
                    ev_items.append(clean_md(m_item.group(1)))

        proc_m = re.search(
            r"\*\*Test Procedure\*\*(.*?)(?=\*\*Verification\*\*|$)",
            block,
            re.DOTALL,
        )
        if proc_m:
            for line in proc_m.group(1).strip().splitlines():
                line = line.strip()
                m_item = re.match(r"^(?:\d+\.|\*|-)\s+(.*)$", line)
                if m_item:
                    item_txt = m_item.group(1).strip()
                    if item_txt.lower().startswith("reference tooling"):
                        parts = item_txt.split(":", 1)
                        if len(parts) > 1:
                            tools_raw = parts[1].strip().rstrip(".")
                            ref_tools = [
                                t.strip(" `")
                                for t in re.split(r",|;", tools_raw)
                                if t.strip(" `")
                            ]
                    else:
                        proc_items.append(clean_md(item_txt))

        ver_m = re.search(r"\*\*Verification\*\*(.*?)(?=^---|\Z)", block, re.DOTALL | re.MULTILINE)
        if ver_m:
            ver_block = ver_m.group(1).strip()
            pass_m = re.search(r"\*\s*\*\*PASS\*\*\s*[—–-]\s*(.+)", ver_block)
            fail_m = re.search(r"\*\s*\*\*FAIL\*\*\s*[—–-]\s*(.+)", ver_block)
            if pass_m:
                pass_criteria = clean_md(pass_m.group(1))
            if fail_m:
                fail_criteria = clean_md(fail_m.group(1))

        # Build verification checklist items (especially useful for AL2 interactive checklist)
        checklist: list[str] = []
        for ev in ev_items:
            if "not accepted" not in ev.lower():
                checklist.append(f"Evidence collected: {ev}")
        for pr in proc_items:
            if "lab adjudication" not in pr.lower():
                # Split multi-sentence procedure into clear actionable checklist steps
                sentences = [s.strip() for s in re.split(r"(?<=\.)\s+", pr) if s.strip()]
                for s in sentences:
                    checklist.append(s)
        if pass_criteria:
            checklist.append(f"Verified PASS criterion: {pass_criteria}")

        cases[cid] = {
            "ext_reference": ext_ref,
            "evidence_items": ev_items,
            "procedure_items": proc_items,
            "reference_tooling": ref_tools,
            "pass_criteria": pass_criteria,
            "fail_criteria": fail_criteria,
            "verification_checklist": checklist,
        }

    return cases


def main() -> None:
    al1_spec_text = (CASA_DIR / "CASA 3.0 (AL1) Specification.md").read_text(encoding="utf-8")
    al1_guide_text = (CASA_DIR / "CASA 3.0 (AL1) Test Guide.md").read_text(encoding="utf-8")
    al2_spec_text = (CASA_DIR / "CASA 3.0 (AL2) Specification.md").read_text(encoding="utf-8")
    al2_guide_text = (CASA_DIR / "CASA 3.0 (AL2) Test Guide.md").read_text(encoding="utf-8")

    al1_specs = parse_spec_table(al1_spec_text, tier="AL1")
    al2_specs = parse_spec_table(al2_spec_text, tier="AL2")
    al1_cases = parse_test_guide(al1_guide_text)
    al2_cases = parse_test_guide(al2_guide_text)

    all_controls: list[dict] = []

    # Merge and sort by domain order and numeric ID
    combined_specs = {**al1_specs, **al2_specs}
    combined_cases = {**al1_cases, **al2_cases}

    def sort_key(cid: str) -> tuple[int, int]:
        prefix, num = cid.split("-")
        domain_name = PREFIX_TO_DOMAIN.get(prefix, "Other")
        d_idx = DOMAINS.index(domain_name) if domain_name in DOMAINS else 99
        return (d_idx, int(num))

    for cid in sorted(combined_specs.keys(), key=sort_key):
        spec = combined_specs[cid]
        case = combined_cases.get(cid, {})
        ev_en = case.get("evidence_items", [])
        proc_en = case.get("procedure_items", [])
        pass_en = case.get("pass_criteria", "")
        fail_en = case.get("fail_criteria", "")
        chk_en = case.get("verification_checklist", [])

        ev_pt = [translate_evidence_item_pt(x) for x in ev_en]
        proc_pt = PROCEDURES_PT.get(cid, proc_en)
        pass_pt = PASS_CRITERIA_PT.get(cid, pass_en)
        fail_pt = FAIL_CRITERIA_PT.get(cid, fail_en)
        chk_pt = build_checklist_pt(cid, ev_pt, proc_pt, pass_pt)

        merged = {
            **spec,
            "domain_pt": DOMAINS_PT.get(spec["domain"], spec["domain"]),
            "title_pt": TITLES_PT.get(cid, spec["title"]),
            "evidence_items": ev_en,
            "evidence_items_pt": ev_pt,
            "procedure_items": proc_en,
            "procedure_items_pt": proc_pt,
            "reference_tooling": case.get("reference_tooling", []),
            "pass_criteria": pass_en,
            "pass_criteria_pt": pass_pt,
            "fail_criteria": fail_en,
            "fail_criteria_pt": fail_pt,
            "verification_checklist": chk_en,
            "verification_checklist_pt": chk_pt,
        }
        all_controls.append(merged)

    payload = {
        "standard": "App Defense Alliance CASA",
        "version": "3.0 (2026-10-16)",
        "domains": DOMAINS,
        "domains_pt": DOMAINS_PT,
        "assurance_levels": {
            "AL1": {
                "code": "AL1",
                "name": "AL1 — Automated Assessment (61 Controls)",
                "name_pt": "AL1 — Avaliação Automatizada (61 Controles)",
                "description": "Evaluates all 61 deterministic AL1 requirements against the application, build artifacts, or source using automated tooling and open evidence formats (SARIF 2.1.0, CycloneDX, HAR 1.2).",
                "description_pt": "Avalia todos os 61 requisitos determinísticos do AL1 contra a aplicação, artefatos de build ou código-fonte usando ferramentas automatizadas e formatos abertos de evidência (SARIF 2.1.0, CycloneDX, HAR 1.2).",
                "included_tiers": ["AL1"],
            },
            "AL2": {
                "code": "AL2",
                "name": "AL2 — Full Lab Assessment (61 Automated AL1 + 15 Lab-Adjudicated AL2)",
                "name_pt": "AL2 — Avaliação Completa de Laboratório (61 AL1 Automatizados + 15 AL2 Manuais)",
                "description": "Runs all 61 automated AL1 tests plus 15 lab-adjudicated AL2 tests requiring interactive verification evidence checklists, notes, and screenshots.",
                "description_pt": "Executa todos os 61 testes automatizados do AL1 mais os 15 testes adjudicados em laboratório do AL2, exigindo checklist interativo de evidências de verificação, notas e capturas de tela.",
                "included_tiers": ["AL1", "AL2"],
            },
        },
        "controls": all_controls,
    }

    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JS.parent.mkdir(parents=True, exist_ok=True)

    OUT_JSON.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    OUT_JS.write_text(
        "/* Auto-generated from CASA 3.0 (AL1 & AL2) Specifications and Test Guides */\n"
        f"window.CASA3_DATA = {json.dumps(payload, indent=2, ensure_ascii=False)};\n",
        encoding="utf-8",
    )

    al1_count = sum(1 for c in all_controls if c["tier"] == "AL1")
    al2_count = sum(1 for c in all_controls if c["tier"] == "AL2")
    print(f"Generated {len(all_controls)} total controls (AL1={al1_count}, AL2={al2_count})")
    print(f"JSON saved to: {OUT_JSON}")
    print(f"JS saved to:   {OUT_JS}")


if __name__ == "__main__":
    main()

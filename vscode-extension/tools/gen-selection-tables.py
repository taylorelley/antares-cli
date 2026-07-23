"""Dev-only: dump the deterministic CWE-selection rule tables from the Python
reference into a JSON file the TypeScript engine loads. Run with `uv run`:

    uv run python vscode-extension/tools/gen-selection-tables.py

This keeps the (large) data tables byte-identical to antares_cli without hand
transcription; the TypeScript port only reimplements the algorithm logic.
"""

from __future__ import annotations

import json
from pathlib import Path

from antares_cli.core import cwe_selection as sel
from antares_cli.core import cwe_selection_evidence as ev
from antares_cli.core import cwe_selection_profile as prof


def convert(value: object) -> object:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (frozenset, set)):
        return sorted(convert(v) for v in value)
    if isinstance(value, (tuple, list)):
        return [convert(v) for v in value]
    if isinstance(value, dict):
        return {str(k): convert(v) for k, v in value.items()}
    # dataclass-like (e.g. _EvidenceRule)
    if hasattr(value, "__dataclass_fields__"):
        return {name: convert(getattr(value, name)) for name in value.__dataclass_fields__}
    return str(value)


def evidence_rules() -> list[dict[str, object]]:
    return [
        {
            "label": rule.label,
            "cwe_scores": [[c, s] for c, s in rule.cwe_scores],
            "tokens": list(rule.tokens),
            "languages": sorted(rule.languages),
            "required_token_groups": [list(g) for g in rule.required_token_groups],
        }
        for rule in ev._EVIDENCE_RULES
    ]


def main() -> int:
    payload = {
        "PROFILE_SIGNAL_RULES": convert(sel._PROFILE_SIGNAL_RULES),
        "PRIMARY_PROFILE_SIGNAL_CWE_IDS": convert(sel._PRIMARY_PROFILE_SIGNAL_CWE_IDS),
        "FRAMEWORK_PROFILE_SIGNAL_RULES": convert(sel._FRAMEWORK_PROFILE_SIGNAL_RULES),
        "AUTOMATIC_SELECTION_POLICY": sel._AUTOMATIC_SELECTION_POLICY,
        "EXPLICIT_SELECTION_POLICY": sel._EXPLICIT_SELECTION_POLICY,
        "SIMPLIFIED_MAPPING_VIEW": sel._SIMPLIFIED_MAPPING_VIEW,
        "SOFTWARE_DEVELOPMENT_VIEW": sel._SOFTWARE_DEVELOPMENT_VIEW,
        "CURRENT_TOP_25_BASELINE_NAME": sel._CURRENT_TOP_25_BASELINE_NAME,
        "AUTO_RELATIONSHIP_FAMILY_CAP": sel._AUTO_RELATIONSHIP_FAMILY_CAP,
        "COMMON_AUTOMATIC_SELECTION_NOTES": list(sel._COMMON_AUTOMATIC_SELECTION_NOTES),
        "EXPLICIT_SELECTION_NOTES": list(sel._EXPLICIT_SELECTION_NOTES),
        "LANGUAGE_BY_SUFFIX": convert(prof._LANGUAGE_BY_SUFFIX),
        "FRAMEWORK_DEPENDENCY_EXACT": convert(prof._FRAMEWORK_DEPENDENCY_EXACT),
        "FRAMEWORK_DEPENDENCY_PREFIXES": convert(prof._FRAMEWORK_DEPENDENCY_PREFIXES),
        "DEPENDENCY_CAPABILITY_PREFIXES": convert(prof._DEPENDENCY_CAPABILITY_PREFIXES),
        "DEPENDENCY_MANIFEST_NAMES": convert(prof._DEPENDENCY_MANIFEST_NAMES),
        "SECURITY_SENSITIVE_PATH_MARKERS": list(prof._SECURITY_SENSITIVE_PATH_MARKERS),
        "MAX_PROFILE_FILES": prof._MAX_PROFILE_FILES,
        "MAX_PROFILE_FILE_BYTES": prof._MAX_PROFILE_FILE_BYTES,
        "MAX_PRIORITY_PROFILE_FILES": prof._MAX_PRIORITY_PROFILE_FILES,
        "SECRET_SIGNAL_PATTERN": prof._SECRET_SIGNAL_PATTERN.pattern,
        "SENSITIVE_VALUE_TOKENS": list(ev._SENSITIVE_VALUE_TOKENS),
        "EVIDENCE_RULES": evidence_rules(),
    }
    out = Path(__file__).resolve().parent.parent / "data" / "selection_tables.json"
    out.write_text(json.dumps(payload, indent=1, sort_keys=False), encoding="utf-8")
    print(f"wrote {out} ({out.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

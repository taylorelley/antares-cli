"""Repository-owned scan fixtures remain available from a clean checkout."""

from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DEMO_ROOT = REPOSITORY_ROOT / "examples" / "vulnerable-restaurant-app"
ROOT_CWE_NOTICE = REPOSITORY_ROOT / "THIRD_PARTY_NOTICES.md"
PROJECT_LICENSE = REPOSITORY_ROOT / "LICENSE"
PACKAGED_CWE_NOTICE = (
    REPOSITORY_ROOT / "src" / "antares_cli" / "knowledge" / "data" / "CWE_NOTICE.txt"
)


def test_vulnerable_restaurant_demo_is_available_as_a_scan_fixture() -> None:
    if not (DEMO_ROOT / "app" / "main.py").is_file():
        pytest.skip(
            "Demo fixture not vendored. Clone it into the examples path first:\n"
            "  git clone https://github.com/theowni/Damn-Vulnerable-RESTaurant-API-Game "
            "examples/vulnerable-restaurant-app"
        )
    assert any((DEMO_ROOT / "app").rglob("*.py"))


def test_mitre_cwe_notice_is_present_at_repository_and_package_boundaries() -> None:
    for notice_path in (ROOT_CWE_NOTICE, PACKAGED_CWE_NOTICE):
        notice = notice_path.read_text(encoding="utf-8")
        normalized_notice = " ".join(notice.split())
        assert "Copyright © 2006–2026, The MITRE Corporation" in normalized_notice
        assert "non-exclusive, royalty-free license to use CWE" in normalized_notice
        assert "https://cwe.mitre.org/about/termsofuse.html" in notice

    readme = " ".join((REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8").split())
    assert "[official CWE Terms of" in readme
    assert "[Apache License 2.0](LICENSE)" in readme


def test_apache_2_license_is_present() -> None:
    license_text = PROJECT_LICENSE.read_text(encoding="utf-8")
    assert "Apache License" in license_text
    assert "Version 2.0, January 2004" in license_text
    assert "http://www.apache.org/licenses/" in license_text

import pytest

from app import detection
from app.detection import evaluate, parse_version


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("PHP/8.3.36", (8, 3, 36)),
        ("php/8.2.34", (8, 2, 34)),
        ("PHP/7.4.33", (7, 4, 33)),
        ("PHP/5.6.40", (5, 6, 40)),
        ("PHP/8.3", (8, 3, 0)),
        ("PHP/8", (8, 0, 0)),
        ("PHP/8.4.27 (cli)", (8, 4, 27)),
        ("Apache/2.4.58 (Unix) PHP/8.2.10", (8, 2, 10)),
        ("nginx/1.25.4", None),
        ("PHP Version 8.3.1", None),
        (None, None),
        ("", None),
    ],
)
def test_parse_version(header, expected):
    assert parse_version(header) == expected


@pytest.mark.parametrize(
    ("version", "expected_status"),
    [
        # Just below each patched release.
        ("8.2.34", detection.STATUS_VULNERABLE),
        ("8.3.35", detection.STATUS_VULNERABLE),
        ("8.4.26", detection.STATUS_VULNERABLE),
        ("8.5.11", detection.STATUS_VULNERABLE),
        # Exactly the patched release and beyond.
        ("8.2.35", detection.STATUS_PATCHED),
        ("8.3.36", detection.STATUS_PATCHED),
        ("8.4.27", detection.STATUS_PATCHED),
        ("8.5.12", detection.STATUS_PATCHED),
        ("8.3.99", detection.STATUS_PATCHED),
        # Newer than every affected branch.
        ("8.6.0", detection.STATUS_PATCHED),
        # EOL branches — always vulnerable.
        ("8.1.31", detection.STATUS_VULNERABLE),
        ("8.0.30", detection.STATUS_VULNERABLE),
        ("7.4.33", detection.STATUS_VULNERABLE),
        ("5.4.45", detection.STATUS_VULNERABLE),
    ],
)
def test_verdict_matrix(version, expected_status):
    result = evaluate(x_powered_by=f"PHP/{version}")
    assert result.status == expected_status
    assert result.php_version == version
    assert result.evidence_source == "x-powered-by"


def test_patched_version_reported_for_known_branch():
    result = evaluate(x_powered_by="PHP/8.3.1")
    assert result.status == detection.STATUS_VULNERABLE
    assert result.branch == "8.3"
    assert result.patched_version == "8.3.36"


def test_version_parsed_from_server_header():
    result = evaluate(server="Apache/2.4.58 (Unix) PHP/8.2.10 OpenSSL/3.0.13")
    assert result.status == detection.STATUS_VULNERABLE
    assert result.php_version == "8.2.10"
    assert result.evidence_source == "server"


def test_x_powered_by_takes_precedence():
    result = evaluate(x_powered_by="PHP/8.4.27", server="Apache/2.4.58 PHP/8.2.1")
    assert result.php_version == "8.4.27"
    assert result.status == detection.STATUS_PATCHED


def test_cookie_only_means_unknown():
    result = evaluate(server="nginx", cookie_names=["PHPSESSID", "other"])
    assert result.status == detection.STATUS_UNKNOWN
    assert result.evidence_source == "cookie"


def test_php_token_without_version_means_unknown():
    result = evaluate(x_powered_by="PHP")
    assert result.status == detection.STATUS_UNKNOWN


def test_no_php_evidence():
    result = evaluate(server="nginx/1.25.4", cookie_names=["session"])
    assert result.status == detection.STATUS_NOT_PHP


def test_case_insensitive_cookie_match():
    result = evaluate(cookie_names=["phpsessid"])
    assert result.status == detection.STATUS_UNKNOWN

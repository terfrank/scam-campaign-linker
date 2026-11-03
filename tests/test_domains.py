"""Tests for hostname and registered-domain helpers."""

import pytest

from scam_linker.domains import hostname_of, registered_domain


@pytest.mark.parametrize(
    ("hostname", "expected"),
    [
        ("examplebank-secure-a.xyz", "examplebank-secure-a.xyz"),
        ("login.secure.examplebank-secure-a.xyz", "examplebank-secure-a.xyz"),
        ("www.example.co.uk", "example.co.uk"),
        ("45.67.89.10", None),
        ("localhost", None),
    ],
)
def test_registered_domain(hostname: str, expected: str | None) -> None:
    assert registered_domain(hostname) == expected


def test_hostname_is_lower_cased() -> None:
    assert hostname_of("HTTPS://Login.Example.COM:8443/x") == "login.example.com"

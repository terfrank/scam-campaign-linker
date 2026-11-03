"""Tests for the campaign graph page: it is served, locked down, and can't render HTML from data."""

import re
from importlib import resources

import pytest
from fastapi.testclient import TestClient

STATIC = resources.files("scam_linker").joinpath("static")


def test_page_is_served_with_a_strict_csp(client: TestClient) -> None:
    response = client.get("/")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    csp = response.headers["content-security-policy"]
    assert "default-src 'none'" in csp
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert response.headers["x-content-type-options"] == "nosniff"


def test_page_has_no_inline_script_or_style(client: TestClient) -> None:
    """The CSP would block inline code anyway; this catches it before it silently breaks."""
    page = client.get("/").text

    scripts = re.findall(r"<script\b[^>]*>", page)
    assert scripts and all("src=" in tag for tag in scripts)
    assert "<style" not in page
    assert not re.search(r"\sstyle=", page)
    assert not re.search(r"\son[a-z]+=", page)  # no onclick= style handlers


@pytest.mark.parametrize(
    ("path", "content_type"),
    [("/static/graph.js", "text/javascript"), ("/static/graph.css", "text/css")],
)
def test_assets_are_served(client: TestClient, path: str, content_type: str) -> None:
    response = client.get(path)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith(content_type)


@pytest.mark.parametrize(
    "dangerous",
    ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"],
)
def test_graph_script_never_parses_data_as_html(dangerous: str) -> None:
    """Every displayed string comes from a scam site. Only textContent may be used for it."""
    script = STATIC.joinpath("graph.js").read_text(encoding="utf-8")
    code = "\n".join(line for line in script.splitlines() if not line.lstrip().startswith("//"))

    assert dangerous not in code

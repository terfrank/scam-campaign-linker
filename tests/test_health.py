"""Tests for GET /health."""

from pathlib import Path

from fastapi.testclient import TestClient

from scam_linker import __version__
from scam_linker.config import Settings
from scam_linker.db.session import make_engine
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import SafeFetcher
from scam_linker.main import create_app


def test_health_returns_ok(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__, "database": "ok"}


def test_health_reports_unavailable_database(
    tmp_path: Path, fetcher: SafeFetcher, dns_client: DnsClient
) -> None:
    broken = make_engine(f"sqlite:///{(tmp_path / 'no-such-dir' / 'db.sqlite').as_posix()}")
    app = create_app(Settings(_env_file=None), engine=broken, fetcher=fetcher, dns=dns_client)

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 503
    assert response.json()["database"] == "unavailable"

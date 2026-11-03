"""Integration tests: the real API over HTTP, with a test database, fake DNS and mocked HTTP.

Pages are mocked per test. Favicons, RDAP and crt.sh are answered from fixtures (or 404),
and any request with no matching route raises, so nothing here can reach the internet.
"""

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session

from fakes import FIXTURES, fixture_bytes, fixture_text
from scam_linker.config import Settings
from scam_linker.db import models
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import SafeFetcher
from scam_linker.main import create_app

KIT_A = "https://examplebank-secure-a.xyz/"
KIT_B = "https://examplebank-secure-b.xyz/"
BLOG = "https://harmless-blog.org/"


def _from_fixture(folder: str, name: str, content_type: str) -> httpx.Response:
    path = FIXTURES / folder / f"{name}.json"
    if not path.exists():
        return httpx.Response(404)
    return httpx.Response(200, headers={"content-type": content_type}, content=path.read_bytes())


@pytest.fixture
def api_router(router: respx.MockRouter) -> respx.MockRouter:
    router.get("https://cdn.harmless-blog.org/icon.png").respond(
        200, headers={"content-type": "image/png"}, content=b"\x89PNG blog icon"
    )
    router.get(path__regex=r"\.ico$").respond(
        200, headers={"content-type": "image/x-icon"}, content=fixture_bytes("favicons/kit.ico")
    )
    router.get(host="rdap.org").mock(
        side_effect=lambda request: _from_fixture(
            "rdap", request.url.path.rsplit("/", 1)[-1], "application/rdap+json"
        )
    )
    router.get(host="crt.sh").mock(
        side_effect=lambda request: _from_fixture(
            "crtsh", request.url.params["q"], "application/json"
        )
    )
    return router


def serve(router: respx.MockRouter, url: str, fixture: str) -> None:
    router.get(url).respond(200, html=fixture_text(f"html/{fixture}"))


def site_count(engine: Engine) -> int:
    with Session(engine) as session:
        return session.scalar(select(func.count()).select_from(models.Site)) or 0


# --- POST /sites ---------------------------------------------------------------------


def test_post_site_collects_and_stores(client: TestClient, api_router: respx.MockRouter) -> None:
    serve(api_router, KIT_A, "kit_a.html")

    response = client.post("/sites", json={"url": KIT_A})

    assert response.status_code == 200
    body = response.json()
    assert body["url"] == KIT_A
    assert body["domain"] == "examplebank-secure-a.xyz"
    assert body["fetch_status"] == "ok"
    assert body["collector_errors"] == {}
    types = {signal["type"] for signal in body["signals"]}
    assert {"favicon_hash", "html_fingerprint", "tracking_id", "cert", "registrar"} <= types


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "ftp://files.example.xyz/kit.zip", "not a url", ""]
)
def test_post_site_rejects_non_http_urls(
    client: TestClient, api_router: respx.MockRouter, url: str
) -> None:
    response = client.post("/sites", json={"url": url})

    assert response.status_code == 422
    assert len(api_router.calls) == 0  # rejected before any network activity


def test_collection_endpoints_are_rate_limited(
    engine: Engine, fetcher: SafeFetcher, dns_client: DnsClient, api_router: respx.MockRouter
) -> None:
    serve(api_router, KIT_A, "kit_a.html")
    settings = Settings(_env_file=None, collect_rate_limit_per_minute=2)
    app = create_app(settings, engine=engine, fetcher=fetcher, dns=dns_client)

    with TestClient(app) as client:
        codes = [client.post("/sites", json={"url": KIT_A}).status_code for _ in range(3)]
        limited = client.post("/campaigns/from-seed", json={"url": KIT_A})

    assert codes == [200, 200, 429]
    assert limited.status_code == 429
    assert int(limited.headers["retry-after"]) > 0


# --- POST /sites/bulk ----------------------------------------------------------------


def test_bulk_dedupes_and_collects_in_the_background(
    client: TestClient, api_router: respx.MockRouter, engine: Engine
) -> None:
    serve(api_router, KIT_A, "kit_a.html")
    serve(api_router, KIT_B, "kit_b.html")

    response = client.post(
        "/sites/bulk", json={"urls": [KIT_A, "HTTPS://ExampleBank-Secure-A.xyz", KIT_B]}
    )

    assert response.status_code == 202
    assert response.json() == {"queued": 2, "duplicates_skipped": 1}
    assert site_count(engine) == 2  # TestClient runs background tasks before returning


def test_bulk_failure_on_one_url_does_not_stop_the_rest(
    client: TestClient, api_router: respx.MockRouter, engine: Engine
) -> None:
    api_router.get(KIT_A).mock(side_effect=RuntimeError("unexpected crash"))
    serve(api_router, KIT_B, "kit_b.html")

    client.post("/sites/bulk", json={"urls": [KIT_A, KIT_B]})

    with Session(engine) as session:
        urls = session.scalars(select(models.Site.url)).all()
    assert urls == [KIT_B]


# --- POST /campaigns/from-seed and GET /campaigns/{id} -------------------------------


def test_from_seed_returns_the_linked_campaign(
    client: TestClient, api_router: respx.MockRouter
) -> None:
    for url, fixture in [(KIT_A, "kit_a.html"), (KIT_B, "kit_b.html"), (BLOG, "unrelated.html")]:
        serve(api_router, url, fixture)
    client.post("/sites", json={"url": KIT_B})
    client.post("/sites", json={"url": BLOG})

    response = client.post("/campaigns/from-seed", json={"url": KIT_A})  # A not yet collected

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "linked"
    assert body["confidence"] == 1.0
    assert body["summary"].startswith("2 sites share ")
    assert [(m["url"], m["is_seed"]) for m in body["members"]] == [(KIT_A, True), (KIT_B, False)]
    assert "tracking_id:G-EXMPL12345" in body["members"][0]["shared"]
    assert body["evidence"][0]["sites"] == 2

    # The blog shares only an IP and ASN with the kits: reported, never merged.
    [related] = body["possibly_related_unknown"]
    assert related["url"] == BLOG
    assert sorted(related["shared"]) == ["asn:AS64500", "ip:45.67.89.10"]
    assert related["explanation"].startswith("Possibly related (UNKNOWN)")

    stored = client.get(f"/campaigns/{body['campaign_id']}").json()
    assert [m["url"] for m in stored["members"]] == [KIT_A, KIT_B]
    assert stored["summary"] == body["summary"]


def test_from_seed_with_only_weak_evidence_is_unknown(
    client: TestClient, api_router: respx.MockRouter
) -> None:
    serve(api_router, KIT_A, "kit_a.html")
    serve(api_router, BLOG, "unrelated.html")
    client.post("/sites", json={"url": KIT_A})

    body = client.post("/campaigns/from-seed", json={"url": BLOG}).json()

    assert body["status"] == "unknown"
    assert body["campaign_id"] is None
    assert body["members"] == []
    assert body["summary"].startswith("UNKNOWN: no other known site shares strong or medium")
    assert [related["url"] for related in body["possibly_related_unknown"]] == [KIT_A]


def test_from_seed_explains_an_unreachable_seed(
    client: TestClient, api_router: respx.MockRouter
) -> None:
    api_router.get(KIT_A).respond(503)

    body = client.post("/campaigns/from-seed", json={"url": KIT_A}).json()

    assert body["status"] == "unknown"
    assert body["seed"]["fetch_status"] == "http_error"
    assert "could not be fetched (http_error)" in body["summary"]


def test_get_missing_campaign_is_404(client: TestClient) -> None:
    assert client.get("/campaigns/999").status_code == 404

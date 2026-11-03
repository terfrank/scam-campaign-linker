"""Load fictional demo sites into the database, so the graph page can be shown offline.

No network access at all: signals are written directly, as if they had been collected.
Every domain, hash and ID below is made up.

    DATABASE_URL=sqlite:///demo.db alembic upgrade head
    DATABASE_URL=sqlite:///demo.db python scripts/demo_data.py
    DATABASE_URL=sqlite:///demo.db uvicorn --factory scam_linker.main:create_app
    # then open http://127.0.0.1:8000/?seed=https://examplebank-secure-a.xyz/
"""

from scam_linker.collectors.base import Signal, SignalType
from scam_linker.collectors.runner import SiteCollection
from scam_linker.db import repository
from scam_linker.db.session import make_engine, make_session_factory
from scam_linker.fetcher import FetchStatus

T = SignalType
KIT_FAVICON = Signal(T.FAVICON_HASH, "495416780")
KIT_HTML = Signal(
    T.HTML_FINGERPRINT, "3f9a0c2b71de44c1a9e0b6d2f5c8a7e1b3d4f6a8c0e2b4d6f8a1c3e5b7d9f0a2"
)
KIT_TRACKING = Signal(T.TRACKING_ID, "G-EXMPL12345")
KIT_PATH = Signal(T.KIT_PATH, "/secure/verify.php")
SHARED_CERT = Signal(T.CERT, "295813:03bb00000000000000000000000000000002")
BULLETPROOF_ASN = Signal(T.ASN, "AS64500")
HOST_IP = Signal(T.IP, "45.67.89.10")

DEMO_SITES: dict[str, set[Signal]] = {
    # The campaign: linked by favicon, page structure, tracking ID, a certificate and a kit path.
    "https://examplebank-secure-a.xyz/": {
        KIT_FAVICON,
        KIT_HTML,
        KIT_TRACKING,
        KIT_PATH,
        BULLETPROOF_ASN,
        HOST_IP,
        Signal(T.TITLE, "examplebank - secure login"),
        Signal(T.CREATED_DATE, "2026-11-02"),
    },
    "https://examplebank-secure-b.xyz/": {
        KIT_FAVICON,
        KIT_HTML,
        KIT_TRACKING,
        BULLETPROOF_ASN,
        Signal(T.IP, "45.67.89.11"),
        Signal(T.CREATED_DATE, "2026-11-04"),
    },
    "https://examplebank-login.top/": {
        KIT_FAVICON,
        SHARED_CERT,
        Signal(T.CREATED_DATE, "2026-11-03"),
    },
    "https://examplebank-verify.shop/account/": {
        SHARED_CERT,
        KIT_PATH,
        Signal(T.ASN, "AS64511"),
        Signal(T.CREATED_DATE, "2026-11-03"),
    },
    # Weak only: same hosting network/IP as campaign sites. Shown as UNKNOWN, never merged.
    "https://unrelated-shop.xyz/": {HOST_IP, BULLETPROOF_ASN},
    "https://harmless-blog.org/": {BULLETPROOF_ASN, Signal(T.TITLE, "gardening notes")},
}


def main() -> None:
    engine = make_engine()
    with make_session_factory(engine)() as session:
        for url, signals in DEMO_SITES.items():
            collection = SiteCollection(
                url=url,
                hostname=None,
                domain=url.split("/")[2],
                fetch_status=FetchStatus.OK,
                signals=tuple(sorted(signals)),
            )
            repository.save_collection(session, collection)
        session.commit()
    engine.dispose()
    print(f"Loaded {len(DEMO_SITES)} fictional demo sites.")


if __name__ == "__main__":
    main()

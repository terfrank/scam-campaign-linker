"""The campaign graph page, served with strict security headers."""

from importlib import resources

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

# The page shows attacker-controlled strings, so it gets a locked-down Content-Security-Policy:
# only its own script, stylesheet and API; no inline code, no third-party origins, no framing.
PAGE_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
        "img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}

router = APIRouter(include_in_schema=False)


@router.get("/")
def graph_page() -> HTMLResponse:
    """The campaign graph UI. Use /?seed=<url> to open it on a specific seed."""
    page = resources.files("scam_linker").joinpath("static/graph.html").read_text(encoding="utf-8")
    return HTMLResponse(page, headers=PAGE_SECURITY_HEADERS)

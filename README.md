# Scam Campaign Linker

A defensive security tool. Give it one known scam or phishing URL (the "seed") and it collects
**public, passive** signals about that site and other known scam sites. It groups sites that share
infrastructure into **campaigns**, explains *why* each site was linked, and gives a confidence
score. When the evidence is weak or conflicting, it answers **UNKNOWN** instead of guessing.

> **Status:** Phase 3 of 8: skeleton, safe fetcher and signal collectors.

## Quick start

### Local (Python 3.12)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
uvicorn scam_linker.main:app --reload
```

Then open <http://127.0.0.1:8000/health> or the interactive docs at <http://127.0.0.1:8000/docs>.

### Docker (API + PostgreSQL)

```bash
cp .env.example .env             # then change POSTGRES_PASSWORD
docker compose up --build
```

### Checks (the same ones CI runs)

```bash
ruff check .
ruff format --check .
mypy
pytest
```

## Project layout

```
src/scam_linker/   application package (API, config; fetcher/collectors/linker in later phases)
tests/             pytest suite; tests only ever use saved fixture files, never live sites
.github/workflows/ CI: ruff, mypy, pytest and a Docker build on every push
```

## How fetching stays safe

All HTTP requests to scanned sites go through one module, `src/scam_linker/fetcher.py`, and
`tests/test_fetcher.py` has a test for each rule:

| Rule | How it is enforced |
|---|---|
| 5 s timeout | httpx per-operation timeout, plus a total deadline per download (stops slow-drip servers) |
| 2 MB cap | `Content-Length` is checked first, then the body is streamed and cut off at 2 MB |
| Max 3 redirects | Redirects are followed by hand, so every hop is re-checked |
| No cookies | Cookie jar with a policy that rejects every cookie |
| No JavaScript / forms | Only `GET` of the page itself; the body is returned as raw bytes, never parsed for sub-resources |
| HTML and favicons only | Content-type allow-list per resource kind |
| No internal targets (SSRF) | Hosts resolving to private, loopback or link-local IPs are refused, including on redirects |
| robots.txt | Fetched once per origin; RFC 9309 rules (4xx = no rules, 5xx/unreachable = disallow all). Not applied to the crt.sh and RDAP APIs, which are built for programmatic queries |
| Rate limit | At least 1 s between requests to the same host |

Known limitation: the address check resolves DNS before httpx resolves it again, so a
DNS-rebinding attacker could in theory change the answer in between. Closing that gap would mean
connecting to the pinned IP directly, which is out of scope for this project.

## Signals collected

Each signal comes from one small collector in `src/scam_linker/collectors/`. The page HTML is
fetched once and shared. If a collector fails, the failure is logged and recorded, and the
other collectors still run.

| Signal | Source | Notes |
|---|---|---|
| `favicon_hash` | `<link rel="icon">` or `/favicon.ico` | MurmurHash3 in Shodan's format, so values can be searched as `http.favicon.hash` |
| `html_fingerprint` | Page HTML | SHA-256 of the start-tag sequence only; pages with fewer than 10 tags are skipped |
| `title` | Page HTML | Case-folded, whitespace collapsed |
| `kit_path` | Links, forms and the URL itself | `.php` scripts, or paths with words such as `verify`/`login` as whole tokens |
| `tracking_id` | Page HTML | `UA-`, `G-`, `GTM-`, `AW-` and Facebook pixel IDs |
| `ip`, `asn` | DNS A records; Team Cymru IP-to-ASN DNS | ASN looked up only for public IPv4 addresses |
| `nameserver` | DNS NS records of the registered domain | |
| `registrar`, `created_date` | RDAP via rdap.org | |
| `cert` | crt.sh certificate transparency logs | Only certificates that also cover *another* registered domain; value is `issuer_ca_id:serial` |

All test fixtures in `tests/fixtures/` are synthetic. See its README.

## Responsible use

This project is for **defensive research only**: helping defenders, researchers, abuse teams and
CERTs find and report infrastructure that is already being used for scams.

- **Public data only.** Input URLs come from public threat feeds (for example the OpenPhish
  community feed). Respect each feed's terms of use.
- **Passive collection only.** The tool makes DNS lookups, queries public certificate transparency
  logs (crt.sh) and RDAP/WHOIS, and fetches raw HTML and the favicon. That is all.
- **No interaction with scam sites.** It never runs JavaScript, follows or submits forms, logs in,
  or downloads anything other than HTML and the favicon.
- **Polite by design.** Every request has a 5 s timeout, a 2 MB size cap, at most 3 redirects, a
  clearly identified research User-Agent and no cookies. Requests are rate-limited, and robots.txt
  is respected where applicable.
- **Tests never touch live sites.** The test suite and CI use saved fixture files only.
- **Links are evidence, not attribution.** A shared favicon or nameserver suggests shared
  infrastructure. It does not identify a person or organisation. Check results by hand before
  reporting them, and report to the right abuse contact (registrar, hosting provider or CERT).
- **Don't use this tool to attack, probe, scan or harass any system or person.**

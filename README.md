# Scam Campaign Linker

A defensive security tool. Give it one known scam or phishing URL (the "seed") and it collects
**public, passive** signals about that site and other known scam sites. It groups sites that share
infrastructure into **campaigns**, explains *why* each site was linked, and gives a confidence
score. When the evidence is weak or conflicting, it answers **UNKNOWN** instead of guessing.

> **Status:** Phase 1 of 8: project skeleton and `/health` endpoint.

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

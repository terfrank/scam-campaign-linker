# Scam Campaign Linker

A defensive security tool. Give it one known scam or phishing URL (the "seed") and it collects
**public, passive** signals about that site and other known scam sites. It groups sites that share
infrastructure into **campaigns**, explains *why* each site was linked, and gives a confidence
score. When the evidence is weak or conflicting, it answers **UNKNOWN** instead of guessing.

> **Status:** Phase 8 of 8: evaluation tooling done; results pending a real run.

## Quick start

### Local (Python 3.12)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
alembic upgrade head            # needs DATABASE_URL, see .env.example
uvicorn --factory scam_linker.main:create_app --reload
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

### Database migrations (Alembic)

The Docker image runs `alembic upgrade head` on start. To work with migrations locally, set
`DATABASE_URL` (see `.env.example`), then:

```bash
alembic upgrade head                                  # create or update the schema
alembic revision --autogenerate -m "describe change"  # after editing db/models.py; review the file!
alembic check                                         # fails if models and migrations disagree
```

## How sites are linked

Every weight and threshold lives in [`src/scam_linker/scoring.toml`](src/scam_linker/scoring.toml),
which is validated when it loads. A typo, a weight outside (0, 1], or an evidence kind missing
from the tiers is an error, not a silent change.

| Tier | Evidence (each kind counts once per pair) | Weight |
|---|---|---|
| Strong | same favicon, page structure, tracking ID, shared certificate, or a *rare* kit path (≤ 3 sites) | 0.9 |
| Medium | identical nameservers **and** registered ≤ 7 days apart; same registrar **and** same title | 0.5 |
| Weak | same IP; same ASN | 0.1 |

1. **Score pairs.** An inverted index (evidence → sites) finds the pairs that share anything.
   A pair's strength is the sum of its evidence weights, capped at 1.0.
2. **Link.** A pair is linked when its strength is at least `link_threshold` (0.8) **and** it has
   strong or medium evidence. One strong signal, or two medium ones, is enough.
3. **Group.** Campaigns are connected components (union-find) over linked pairs only.
4. **Never guess.** A pair with evidence that isn't enough to link, such as a shared ASN, is
   reported as *possibly related (UNKNOWN)* and never merges campaigns. A site with no links
   has no campaign. This holds even if the threshold is lowered, and a test checks it.
5. **Filter noise.** A value shared by more than `max_sites_per_signal` sites (e.g. a hosting
   provider's default favicon) is treated as infrastructure and ignored, as is anything in the
   `[ignore]` list.

Campaign confidence is the mean of the members' strongest link strengths. Every link keeps
the exact evidence behind it, so the explanation is generated from stored facts:
*"3 sites share favicon 495416780, kit path /secure/verify.php and tracking ID G-EXMPL12345;
registered 2026-11-02 to 2026-11-04"*.

## API

Interactive docs at `/docs`. Collection endpoints are rate-limited per client IP
(`COLLECT_RATE_LIMIT_PER_MINUTE`, default 10) and answer `429` with `Retry-After` when exceeded.

| Method | Path | What it does |
|---|---|---|
| `POST` | `/sites` `{"url": ...}` | Collect every signal for one URL now and store it |
| `POST` | `/sites/bulk` `{"urls": [...]}` | Queue up to 1000 URLs (deduplicated); collected one at a time in the background, returns `202` |
| `POST` | `/campaigns/from-seed` `{"url": ...}` | Collect the seed if new, rebuild campaigns, return the seed's campaign, or `status: "unknown"` |
| `GET` | `/campaigns/{id}` | A stored campaign with its members and evidence |
| `GET` | `/health` | `200` if the API and database are up, `503` if the database is not |

`/campaigns/from-seed` returns the members with their link strength and shared evidence, a
plain-English `summary`, and `possibly_related_unknown`: sites with some shared evidence that
isn't enough to link. When nothing links, `status` is `"unknown"` and the summary says why
(for example, that the seed page could not be fetched) instead of guessing.

Trade-offs, on purpose:
- **Bulk jobs use FastAPI `BackgroundTasks`** in the API process: no queue to run, but queued
  work is lost if the API restarts. Re-submitting is safe, because saving a site is an upsert.
- **Campaigns are snapshots.** Each `from-seed` call recomputes them, so campaign ids change
  between calls.
- **The rate limiter is in memory**, which is correct for one API container but not for several.

## Campaign graph page

Open `/` (or `/?seed=<url>` to jump straight to a seed). The page draws the seed's campaign:

- **Nodes:** the seed (orange), campaign members (blue) and possibly related sites (grey).
- **Solid lines:** links, thicker for stronger links.
- **Dashed lines:** weak or insufficient evidence, which never merges sites.
- **Hover:** shows the plain-English evidence behind any line.

Every URL, title and evidence value on the page comes from a scam site, so the page is
built to treat them as hostile:

- **No HTML from data:** values are inserted with `textContent` only. A test fails if
  `innerHTML`-style APIs ever appear in `graph.js`, and hostile payloads were checked in a
  real browser.
- **Strict Content-Security-Policy:** `default-src 'none'; script-src 'self'`, with no inline
  code, no third-party scripts (plain SVG, no CDN library) and no framing.
- **URLs are defanged** (`hxxps://evil[.]xyz`) and never rendered as clickable links.

### Offline demo (no real sites contacted)

```bash
export DATABASE_URL=sqlite:///demo.db
alembic upgrade head
python scripts/demo_data.py          # six fictional sites, signals written directly
uvicorn --factory scam_linker.main:create_app
# open http://127.0.0.1:8000/?seed=https://examplebank-secure-a.xyz/
```

## Evaluating on a real feed

`scripts/evaluate.py` runs the full pipeline on a sample of a public feed, using its own
SQLite database, and writes everything to `evaluation/` (git-ignored). Every URL in its
output is defanged.

```bash
# Collect and link a reproducible sample. --live is required: this contacts the listed sites
# (passively: DNS, RDAP, crt.sh, raw HTML and favicon only, rate-limited, robots.txt respected).
python scripts/evaluate.py run feed.txt --live --limit 100 --random-seed 42

# Re-link without any network, e.g. after editing scoring.toml
python scripts/evaluate.py run --relink-only

# Fill in same_campaign (yes / no / unsure) in evaluation/pairs.csv, then:
python scripts/evaluate.py score evaluation/pairs.csv
```

- `report.md` has the counts: fetch outcomes, signal coverage, collector failures, campaigns and
  UNKNOWN sites.
- `pairs.csv` has one row per decision (`linked` or `possibly_related`) with its evidence, ready
  to check by hand.
- `score` turns your verdicts into the share of linked pairs you judged correct (precision).
  **Recall can't be measured this way**, because no ground truth exists for pairs the linker
  never proposed.

## Results and limitations

### Results

_Not yet measured. This section will be filled in from a real run of `scripts/evaluate.py`
(sample size, date, fetch outcomes, campaigns found, and precision from hand-checked pairs).
No numbers are reported until then._

### Known limitations (by design)

- **Precision only, from hand-checking.** The linker is judged on the pairs it proposed, by
  one person, so recall is unknown and verdicts are subjective.
- **Feeds are biased samples.** Public feeds over-represent whatever their sources detect best,
  and many listed sites are already offline when collected.
- **Dead sites lose HTML signals.** A site that's down still has DNS, RDAP and certificate
  data, but no favicon, fingerprint, title, kit path or tracking ID.
- **Shared infrastructure is noisy.** Large hosts, CDNs and sinkholes are why IP and ASN are
  weak-only, and why `max_sites_per_signal` exists. Its default (100) is a guess to tune.
- **Linking is transitive.** If A–B and B–C are linked, A and C end up in one campaign even if
  they share nothing directly. Each member's `shared` list shows exactly why it is there.
- **"Conflicting" evidence is only partly modelled.** UNKNOWN means not enough evidence (or only
  noisy evidence); there is no rule yet that detects contradictions between signals.
- **Point-in-time snapshots.** Re-collecting replaces a site's signals, and campaigns are
  recomputed on demand, so results reflect when the data was collected.

## Data model

```
sites ──< site_signals >── signals          campaigns ──< campaign_members >── sites
```

- `signals` holds each distinct fact once (`UNIQUE(type, value)`), so "which sites share
  favicon X?" is one indexed join.
- Re-collecting a site replaces its signals, so infrastructure a site no longer uses can't
  link it to other sites.
- `sites.collector_errors` records why a signal is missing, e.g. an RDAP timeout.

## Project layout

```
src/scam_linker/   application package: fetcher, collectors/, db/ (linker and API in later phases)
migrations/        Alembic migration scripts
tests/             pytest suite; tests only ever use saved fixture files, never live sites
.github/workflows/ CI: ruff, mypy, pytest (SQLite + PostgreSQL) and a Docker build on every push
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

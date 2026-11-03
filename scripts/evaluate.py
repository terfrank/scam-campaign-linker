"""Evaluate the linker on a sample of a public phishing feed.

    # 1. Collect a sample (contacts the listed sites: passive requests only) and link it
    python scripts/evaluate.py run feed.txt --live --limit 100 --random-seed 42

    # 2. After tuning scoring.toml: re-link what was already collected, no network
    python scripts/evaluate.py run --relink-only

    # 3. Fill in the same_campaign column of evaluation/pairs.csv by hand, then:
    python scripts/evaluate.py score evaluation/pairs.csv

Results go to evaluation/ (git-ignored): evaluation.db, report.md and pairs.csv.
All URLs in those files are defanged. A dedicated SQLite database is used by default,
so an evaluation never mixes with the API's data.
"""

import argparse
import logging
import sys
from pathlib import Path

from alembic import command
from alembic.config import Config

from scam_linker import evaluation, services
from scam_linker.db.session import make_engine, make_session_factory
from scam_linker.dns_client import DnsClient
from scam_linker.fetcher import SafeFetcher
from scam_linker.linker.config import load_scoring_config

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MAX_LIMIT = 2000
RESPONSIBLE_USE = """\
This run makes passive requests (DNS, RDAP, crt.sh, raw HTML and favicon) to the sites in
your feed. Defensive research only; use public feeds and respect their terms. Requests are
rate-limited per host and respect robots.txt. Nothing is executed, submitted or logged into.
"""


def sample_limit(text: str) -> int:
    """argparse type: an int from 1 to MAX_LIMIT."""
    value = int(text)
    if not 1 <= value <= MAX_LIMIT:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_LIMIT}")
    return value


def migrate(database_url: str) -> None:
    config = Config(file_=PROJECT_ROOT / "alembic.ini", toml_file=PROJECT_ROOT / "pyproject.toml")
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "head")


def run(args: argparse.Namespace) -> int:
    if not args.live and not args.relink_only:
        print(
            "Refusing to contact live sites without --live.\n"
            "Add --live to collect, or --relink-only to re-link an existing evaluation database.",
            file=sys.stderr,
        )
        return 2
    if not args.relink_only and args.feed is None:
        print("A feed file is required unless --relink-only is given.", file=sys.stderr)
        return 2

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    database_url = args.database_url or f"sqlite:///{(out_dir / 'evaluation.db').as_posix()}"
    migrate(database_url)
    engine = make_engine(database_url)
    session_factory = make_session_factory(engine)
    scoring = load_scoring_config(args.scoring_config)

    if not args.relink_only:
        urls, rejected = evaluation.read_feed(args.feed)
        chosen = evaluation.sample(urls, args.limit, args.random_seed)
        print(RESPONSIBLE_USE)
        print(
            f"Feed: {len(urls)} unique valid URLs ({rejected} lines rejected). "
            f"Collecting {len(chosen)}; expect roughly {len(chosen) * 5 // 60 + 1} minute(s)."
        )

        def progress(position: int, url: str, outcome: str) -> None:
            print(f"[{position}/{len(chosen)}] {outcome:<24} {evaluation.defang(url)}", flush=True)

        with SafeFetcher() as fetcher:
            outcome = services.collect_many(
                chosen, session_factory, fetcher, DnsClient(), progress=progress
            )
        print(f"Collected {outcome.saved}, failed {outcome.failed}.\n")

    with session_factory() as session:
        linking = services.rebuild_campaigns(session, scoring)
        report = evaluation.build_report(session, linking)
        rows = evaluation.export_pairs_csv(session, linking, scoring, out_dir / "pairs.csv")
    engine.dispose()

    text = evaluation.format_report(report)
    (out_dir / "report.md").write_text(text, encoding="utf-8")
    print(text)
    print(f"Wrote {out_dir / 'report.md'} and {out_dir / 'pairs.csv'} ({rows} pairs to check).")
    return 0


def score(args: argparse.Namespace) -> int:
    results = evaluation.score_csv(args.csv)
    for decision, counts in sorted(results.items()):
        rate = f"{counts.yes_rate:.0%}" if counts.yes_rate is not None else "n/a"
        print(
            f"{decision}: {counts.yes} yes, {counts.no} no, {counts.unsure} unsure, "
            f"{counts.unchecked} unchecked -> same-campaign rate {rate} of {counts.checked} checked"
        )
    print("\nFor 'linked' rows that rate is precision. Recall is not measurable from this file.")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True)

    run_parser = sub.add_parser("run", help="collect a feed sample (with --live) and link it")
    run_parser.add_argument("feed", type=Path, nargs="?", help="text file, one URL per line")
    run_parser.add_argument(
        "--live", action="store_true", help="allow requests to the listed sites"
    )
    run_parser.add_argument(
        "--relink-only", action="store_true", help="skip collection; re-link only"
    )
    run_parser.add_argument("--limit", type=sample_limit, default=100, metavar="N")
    run_parser.add_argument(
        "--random-seed", type=int, default=None, help="reproducible random sample"
    )
    run_parser.add_argument("--out-dir", type=Path, default=PROJECT_ROOT / "evaluation")
    run_parser.add_argument("--database-url", default=None, help="default: <out-dir>/evaluation.db")
    run_parser.add_argument(
        "--scoring-config", type=Path, default=None, help="default: shipped scoring.toml"
    )
    run_parser.set_defaults(handler=run)

    score_parser = sub.add_parser("score", help="summarise hand-checked verdicts in pairs.csv")
    score_parser.add_argument("csv", type=Path)
    score_parser.set_defaults(handler=score)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.WARNING)  # per-site progress is printed instead
    args = parse_args(sys.argv[1:] if argv is None else argv)
    exit_code: int = args.handler(args)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())

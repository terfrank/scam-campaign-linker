"""Tests for the evaluation module and CLI. Fixtures only: the CLI's live mode is never run."""

import csv
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest
import respx
from sqlalchemy import Engine

from fakes import serve
from scam_linker import services
from scam_linker.db.session import make_session_factory
from scam_linker.dns_client import DnsClient
from scam_linker.evaluation import (
    build_report,
    defang,
    export_pairs_csv,
    format_report,
    read_feed,
    sample,
    score_csv,
)
from scam_linker.fetcher import SafeFetcher
from scam_linker.linker.config import load_scoring_config

PROJECT_ROOT = Path(__file__).parents[1]
CONFIG = load_scoring_config()
KIT_A = "https://examplebank-secure-a.xyz/"
KIT_B = "https://examplebank-secure-b.xyz/"
BLOG = "https://harmless-blog.org/"


def load_cli() -> ModuleType:
    """scripts/ is not a package, so load evaluate.py by path."""
    spec = importlib.util.spec_from_file_location(
        "evaluate_cli", PROJECT_ROOT / "scripts/evaluate.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- feed handling ---------------------------------------------------------------------


def test_read_feed_skips_comments_invalid_lines_and_duplicates(tmp_path: Path) -> None:
    feed = tmp_path / "feed.txt"
    feed.write_text(
        "# OpenPhish community feed\n"
        f"{KIT_A}\n"
        "\n"
        "HTTPS://ExampleBank-Secure-A.xyz\n"  # same site as the first line
        "ftp://files.example.xyz/kit.zip\n"
        "not a url\n"
        f"  {KIT_B}  \n",
        encoding="utf-8",
    )

    urls, rejected = read_feed(feed)

    assert urls == [KIT_A, KIT_B]
    assert rejected == 2


def test_sample_is_head_or_reproducible_random() -> None:
    urls = [f"https://site-{i}.xyz/" for i in range(50)]

    assert sample(urls, 3, seed=None) == urls[:3]
    assert sample(urls, 5, seed=42) == sample(urls, 5, seed=42)
    assert sample(urls, 5, seed=42) != urls[:5]
    assert len(sample(urls, 500, seed=1)) == 50


def test_defang() -> None:
    assert defang("https://evil.xyz/a.php") == "hxxps://evil[.]xyz/a[.]php"
    assert defang("HTTP://x.y") == "hxxp://x[.]y"


# --- a full run on fixtures ------------------------------------------------------------


def test_evaluation_run_on_fixtures(
    api_router: respx.MockRouter,
    fetcher: SafeFetcher,
    dns_client: DnsClient,
    engine: Engine,
    tmp_path: Path,
) -> None:
    for url, fixture in [(KIT_A, "kit_a.html"), (KIT_B, "kit_b.html"), (BLOG, "unrelated.html")]:
        serve(api_router, url, fixture)
    factory = make_session_factory(engine)
    seen: list[tuple[int, str, str]] = []

    services.collect_many(
        [KIT_A, KIT_B, BLOG], factory, fetcher, dns_client, progress=lambda *step: seen.append(step)
    )
    with factory() as session:
        linking = services.rebuild_campaigns(session, CONFIG)
        report = build_report(session, linking)
        rows = export_pairs_csv(session, linking, CONFIG, tmp_path / "pairs.csv")

    assert seen == [(1, KIT_A, "ok"), (2, KIT_B, "ok"), (3, BLOG, "ok")]
    assert report.sites == 3
    assert report.fetch_status == {"ok": 3}
    assert report.collector_failures["rdap"] == 2  # only kit A has an RDAP fixture
    assert [c.urls for c in report.campaigns] == [[KIT_A, KIT_B]]
    assert (report.linked_pairs, report.possibly_related_pairs) == (1, 2)

    text = format_report(report)
    assert "- Campaigns: 1 (1 of size 2)" in text
    assert "- Sites with no campaign (UNKNOWN): 1 (33%)" in text
    assert "hxxps://examplebank-secure-a[.]xyz/" in text
    assert "https://" not in text  # nothing clickable

    assert rows == 3
    content = (tmp_path / "pairs.csv").read_text(encoding="utf-8")
    assert "https://" not in content
    records = list(csv.DictReader(content.splitlines()))
    assert [r["decision"] for r in records] == ["linked", "possibly_related", "possibly_related"]
    assert records[0]["site_a"] == "hxxps://examplebank-secure-a[.]xyz/"
    assert all(r["same_campaign"] == "" for r in records)


# --- scoring hand-checked verdicts ------------------------------------------------------


def write_verdicts(path: Path, rows: list[tuple[str, str]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["decision", "same_campaign"])
        writer.writerows(rows)


def test_score_counts_verdicts_per_decision(tmp_path: Path) -> None:
    path = tmp_path / "pairs.csv"
    write_verdicts(
        path,
        [
            ("linked", "yes"),
            ("linked", "Yes "),
            ("linked", "no"),
            ("linked", "unsure"),
            ("linked", ""),
            ("possibly_related", "no"),
        ],
    )

    results = score_csv(path)

    linked = results["linked"]
    assert (linked.yes, linked.no, linked.unsure, linked.unchecked) == (2, 1, 1, 1)
    assert linked.yes_rate == pytest.approx(2 / 3)  # unsure and unchecked excluded
    assert results["possibly_related"].yes_rate == 0.0


def test_score_rejects_unknown_verdicts(tmp_path: Path) -> None:
    path = tmp_path / "pairs.csv"
    write_verdicts(path, [("linked", "yes"), ("linked", "maybe")])

    with pytest.raises(ValueError, match="line 3"):
        score_csv(path)


# --- the CLI ----------------------------------------------------------------------------


def test_cli_refuses_to_collect_without_live_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    feed = tmp_path / "feed.txt"
    feed.write_text(f"{KIT_A}\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    exit_code = load_cli().main(["run", str(feed), "--out-dir", str(out_dir)])

    assert exit_code == 2
    assert "Refusing to contact live sites without --live" in capsys.readouterr().err
    assert not out_dir.exists()  # nothing created, nothing contacted


def test_cli_rejects_out_of_range_limit(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exit_info:
        load_cli().main(["run", "feed.txt", "--live", "--limit", "0"])

    assert exit_info.value.code == 2


def test_cli_relink_only_runs_offline_and_writes_outputs(tmp_path: Path) -> None:
    """--relink-only never collects: it migrates an evaluation DB, links it and reports."""
    exit_code = load_cli().main(["run", "--relink-only", "--out-dir", str(tmp_path)])

    assert exit_code == 0
    assert (tmp_path / "evaluation.db").exists()
    assert "- Sites in this evaluation database: 0" in (tmp_path / "report.md").read_text()
    header = (tmp_path / "pairs.csv").read_text(encoding="utf-8").splitlines()[0]
    assert header.startswith("decision,campaign_id,strength")

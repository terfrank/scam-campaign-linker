"use strict";

// SECURITY: every URL, title and evidence value shown here came from a scanned scam site,
// so it is attacker-controlled. It is only ever inserted with textContent or as an SVG
// attribute value, never parsed as HTML. tests/test_page.py fails if HTML-parsing APIs
// (innerHTML and friends) appear in this file.

const SVG_NS = "http://www.w3.org/2000/svg";
const CENTER = { x: 320, y: 240 };
const MAX_LABELS = 16; // beyond this, only the seed is labelled; hover shows the rest

const $ = (id) => document.getElementById(id);

/** 'https://evil.xyz/login' -> 'hxxps://evil[.]xyz/login': readable, not clickable. */
function defang(url) {
  return url.replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

/** 'html_fingerprint:3f9a0c2b71de44c1...' -> 'html_fingerprint:3f9a0c2b…' for tables. */
function shortLabel(label) {
  const [kind, ...rest] = label.split(":");
  const value = rest.join(":");
  return value.length > 24 ? `${kind}:${value.slice(0, 10)}…` : label;
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function svg(tag, attributes, tooltip) {
  const element = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attributes)) {
    element.setAttribute(name, String(value));
  }
  if (tooltip) {
    const title = document.createElementNS(SVG_NS, "title");
    title.textContent = tooltip;
    element.appendChild(title);
  }
  return element;
}

function html(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (className) element.className = className;
  return element;
}

/** Spread `count` points on a circle, starting at the top. `spread` < 1 leaves a gap. */
function ring(count, radius, offset = 0, spread = 1) {
  return Array.from({ length: count }, (_, i) => {
    const angle = -Math.PI / 2 + offset + (2 * Math.PI * spread * i) / Math.max(count, 1);
    return { x: CENTER.x + radius * Math.cos(angle), y: CENTER.y + radius * Math.sin(angle) };
  });
}

/** Seed in the middle, other members on an inner ring, possibly related on an outer ring. */
function layout(result) {
  const positions = new Map();
  positions.set(result.seed.url, { ...CENTER, kind: "seed" });

  const others = result.members.filter((m) => !m.is_seed).map((m) => m.url);
  ring(others.length, 140).forEach((p, i) => positions.set(others[i], { ...p, kind: "member" }));

  const related = result.possibly_related_unknown
    .map((r) => r.url)
    .filter((url) => !positions.has(url));
  // Outer ring, offset from the members and spread over 80% of the circle, so two related
  // sites never sit exactly opposite each other (their lines would look like one line through the seed).
  const radius = others.length ? 210 : 160;
  ring(related.length, radius, Math.PI / 7, 0.8).forEach((p, i) =>
    positions.set(related[i], { ...p, kind: "related" }),
  );
  return positions;
}

function drawGraph(result) {
  const canvas = $("graph");
  canvas.replaceChildren();
  const positions = layout(result);
  const edges = svg("g", {});
  const nodes = svg("g", {});

  for (const link of result.links) {
    const a = positions.get(link.source);
    const b = positions.get(link.target);
    if (!a || !b) continue;
    edges.appendChild(
      svg(
        "line",
        { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge", "stroke-width": 1 + 4 * link.strength },
        `${defang(link.source)} - ${defang(link.target)}\n${link.explanation}`,
      ),
    );
  }
  for (const rel of result.possibly_related_unknown) {
    const a = positions.get(rel.related_to);
    const b = positions.get(rel.url);
    if (!a || !b) continue;
    edges.appendChild(
      svg(
        "line",
        { x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge weak" },
        `${defang(rel.related_to)} - ${defang(rel.url)}\n${rel.explanation}`,
      ),
    );
  }

  const showAllLabels = positions.size <= MAX_LABELS;
  for (const [url, p] of positions) {
    const radius = p.kind === "seed" ? 16 : 12;
    nodes.appendChild(svg("circle", { cx: p.x, cy: p.y, r: radius, class: `node ${p.kind}` }, defang(url)));
    if (showAllLabels || p.kind === "seed") {
      const label = svg("text", { x: p.x, y: p.y + radius + 17, class: `label ${p.kind}` });
      label.textContent = defang(hostOf(url));
      nodes.appendChild(label);
    }
  }
  canvas.append(edges, nodes);
}

function drawDetails(result) {
  $("verdict").textContent =
    result.status === "linked"
      ? `Campaign #${result.campaign_id}: confidence ${result.confidence.toFixed(2)}`
      : "UNKNOWN: no campaign";
  $("summary").textContent = result.summary;

  const rows = result.members.map((member) => {
    const row = document.createElement("tr");
    const site = html("td", defang(member.url) + (member.is_seed ? " (seed)" : ""), "url");
    row.append(site, html("td", member.link_strength.toFixed(2), "num"), html("td", member.shared.map(shortLabel).join(", ")));
    return row;
  });
  if (!rows.length) {
    const row = document.createElement("tr");
    const cell = html("td", "None: nothing links to the seed strongly enough.");
    cell.colSpan = 3;
    row.appendChild(cell);
    rows.push(row);
  }
  $("members").replaceChildren(...rows);

  const related = result.possibly_related_unknown.map((rel) => {
    const item = document.createElement("li");
    item.append(html("span", defang(rel.url), "url"), html("span", rel.explanation, "why"));
    return item;
  });
  if (!related.length) related.push(html("li", "None."));
  $("related").replaceChildren(...related);
}

function setStatus(message, isError = false) {
  const status = $("status");
  status.textContent = message;
  status.classList.toggle("error", isError);
}

async function findCampaign(url) {
  setStatus("Collecting passive signals and linking. This can take a few seconds...");
  try {
    const response = await fetch("/campaigns/from-seed", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    if (response.status === 429) {
      setStatus(`Rate limited. Try again in ${response.headers.get("Retry-After") || "a few"} seconds.`, true);
      return;
    }
    if (!response.ok) {
      setStatus(`Request failed (HTTP ${response.status}). Check that the URL is http(s).`, true);
      return;
    }
    const result = await response.json();
    $("result").hidden = false;
    drawGraph(result);
    drawDetails(result);
    setStatus(result.status === "linked" ? "Done." : "Done: evidence too weak to name a campaign.");
  } catch {
    setStatus("Could not reach the API.", true);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("seed-form").addEventListener("submit", (event) => {
    event.preventDefault();
    findCampaign($("seed-url").value.trim());
  });
  // /?seed=<url> pre-fills and runs, so a result can be bookmarked or shared.
  const seed = new URLSearchParams(window.location.search).get("seed");
  if (seed) {
    $("seed-url").value = seed;
    findCampaign(seed);
  }
});

"""Evidence graph export: target -> analyzed modules -> evidence (E1, E2...) -> findings.

Writes graph.mmd (Mermaid flowchart) and graph.html (standalone page). The HTML always includes a pure-SVG
view that works offline. If Mermaid.js can load from its CDN, the page also offers the Mermaid rendering.
Every string from the target is HTML-escaped, so a hostile file name cannot inject markup or script.
"""

from __future__ import annotations

import html
import re
from pathlib import Path

MAX_MODULES = 25
MAX_EVIDENCE = 60
MAX_FINDINGS = 60
SEVERITY_FILL = {
    "CRITICAL": "#ffd0d0",
    "HIGH": "#ffe3c2",
    "MEDIUM": "#fff5b8",
    "INFO": "#e3ecff",
}


def _short(text: str, limit: int = 70) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _mermaid_label(text: str) -> str:
    return _short(text).replace('"', "'")


def _module_of(source: str) -> str:
    return re.sub(r":\d+$", "", source)


def _model(data: dict) -> dict:
    """Turn the investigation data into nodes and edges shared by the Mermaid and SVG renderers."""
    target = data["target"]
    evidence = data.get("evidence", [])[:MAX_EVIDENCE]
    findings = data.get("findings", [])[:MAX_FINDINGS]

    modules: list[str] = []
    for ev in evidence:
        mod = _module_of(ev["source"])
        if mod != target and mod not in modules:
            modules.append(mod)
    modules = modules[:MAX_MODULES]

    nodes: dict[str, dict] = {"T": {"label": f"Target: {Path(target).name or target}", "level": 0, "kind": "target"}}
    edges: list[tuple[str, str]] = []
    for i, mod in enumerate(modules, 1):
        nodes[f"M{i}"] = {"label": _short(mod, 60), "level": 1, "kind": "module"}
        edges.append(("T", f"M{i}"))
    module_ids = {mod: f"M{i}" for i, mod in enumerate(modules, 1)}

    known_refs = set()
    for ev in evidence:
        mod = _module_of(ev["source"])
        parent = module_ids.get(mod, "T")
        nodes[ev["ref"]] = {"label": f"{ev['ref']}: {_short(ev['claim'])}", "level": 2, "kind": "evidence"}
        edges.append((parent, ev["ref"]))
        known_refs.add(ev["ref"])

    for i, f in enumerate(findings, 1):
        fid = f"F{i}"
        nodes[fid] = {"label": f"{f['severity']}: {_short(f['title'])}", "level": 3, "kind": "finding", "severity": f["severity"]}
        refs = [r for r in f.get("refs", []) if r in known_refs]
        for r in refs or ["T"]:
            edges.append((r, fid))
    return {"nodes": nodes, "edges": edges, "findings_shown": len(findings), "evidence_shown": len(evidence)}


def build_mermaid(data: dict) -> str:
    model = _model(data)
    lines = ["flowchart TD"]
    for nid, node in model["nodes"].items():
        lines.append(f'  {nid}["{_mermaid_label(node["label"])}"]')
    for src, dst in model["edges"]:
        lines.append(f"  {src} --> {dst}")
    for sev, fill in SEVERITY_FILL.items():
        lines.append(f"  classDef {sev} fill:{fill},stroke:#444")
    for nid, node in model["nodes"].items():
        if node.get("severity"):
            lines.append(f"  class {nid} {node['severity']}")
    return "\n".join(lines) + "\n"


def build_svg(data: dict) -> str:
    model = _model(data)
    column_width, row_height, box_w, box_h = 260, 62, 230, 44
    rows: dict[int, int] = {}
    pos: dict[str, tuple[int, int]] = {}
    for nid, node in model["nodes"].items():
        level = node["level"]
        row = rows.get(level, 0)
        rows[level] = row + 1
        pos[nid] = (30 + level * column_width, 30 + row * row_height)
    height = max(y for _, y in pos.values()) + box_h + 40
    width = 30 + 4 * column_width + box_w
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">']
    for src, dst in model["edges"]:
        x1, y1 = pos[src]
        x2, y2 = pos[dst]
        parts.append(
            f'<line x1="{x1 + box_w}" y1="{y1 + box_h // 2}" x2="{x2}" y2="{y2 + box_h // 2}" stroke="#667" stroke-width="1.2"/>'
        )
    for nid, node in model["nodes"].items():
        x, y = pos[nid]
        fill = SEVERITY_FILL.get(node.get("severity", ""), "#f4f6fb" if node["kind"] != "target" else "#dbeafe")
        parts.append(f'<g><rect x="{x}" y="{y}" width="{box_w}" height="{box_h}" rx="6" fill="{fill}" stroke="#334"/>')
        parts.append(f'<text x="{x + 8}" y="{y + box_h // 2 + 4}" font-size="12" font-family="sans-serif">{html.escape(_short(node["label"], 34))}</text>')
        parts.append(f"<title>{html.escape(node['label'])}</title></g>")
    parts.append("</svg>")
    return "\n".join(parts)


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>REA evidence graph {id}</title>
<style>
  body {{ font-family: sans-serif; margin: 16px; color: #112; }}
  h1 {{ font-size: 18px; }}
  .note {{ color: #555; font-size: 13px; max-width: 900px; }}
  #views {{ overflow: auto; border: 1px solid #ccd; border-radius: 6px; padding: 8px; background: #fff; }}
  pre {{ background: #f6f7fb; padding: 8px; overflow: auto; font-size: 12px; }}
  button {{ margin-bottom: 8px; }}
</style>
</head>
<body>
<h1>Evidence graph for investigation {id}</h1>
<p class="note">Target: <code>{target}</code>. Nodes are targets, modules, evidence refs (E1, E2...) and findings.
Hits are leads to verify in code. Mermaid rendering appears automatically when the CDN is reachable.</p>
<button id="toggle" type="button" hidden>Switch view</button>
<div id="views">
  <div id="svg-view">{svg}</div>
  <div id="mermaid-view" hidden><pre class="mermaid">{mermaid}</pre></div>
</div>
<details><summary>Mermaid source</summary><pre>{mermaid_text}</pre></details>
<script type="module">
  const toggle = document.getElementById("toggle");
  const svgView = document.getElementById("svg-view");
  const mermaidView = document.getElementById("mermaid-view");
  try {{
    const mod = await import("https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.esm.min.mjs");
    mod.default.initialize({{ startOnLoad: false, securityLevel: "strict" }});
    await mod.default.run({{ nodes: [mermaidView.querySelector("pre")] }});
    mermaidView.hidden = false;
    svgView.hidden = true;
    toggle.hidden = false;
    toggle.addEventListener("click", () => {{
      const showSvg = svgView.hidden;
      svgView.hidden = !showSvg;
      mermaidView.hidden = showSvg;
    }});
  }} catch (err) {{
    // Offline or blocked CDN: the SVG view stays visible.
  }}
</script>
</body>
</html>
"""


def build_html(data: dict) -> str:
    mmd = build_mermaid(data)
    return _PAGE.format(
        id=html.escape(data["id"]),
        target=html.escape(data["target"]),
        svg=build_svg(data),
        mermaid=html.escape(mmd),
        mermaid_text=html.escape(mmd),
    )


def write_graph(directory: Path, data: dict) -> tuple[Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    mmd_path = directory / "graph.mmd"
    html_path = directory / "graph.html"
    mmd_path.write_text(build_mermaid(data), encoding="utf-8")
    html_path.write_text(build_html(data), encoding="utf-8")
    return mmd_path, html_path

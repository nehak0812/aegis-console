"""The AI stack as attack surface: advisories for self-hosted AI/LLM software, AI-themed malicious packages,
MITRE ATLAS (the ATT&CK-style matrix for attacks on AI systems) and the spread of offensive AI agent frameworks."""
import os
import re
from datetime import datetime, timedelta, timezone

from aegis import db, net
from aegis.registry import Source, collector

UTC = timezone.utc
AI_PACKAGES = [("PyPI", "litellm"), ("PyPI", "langflow"), ("PyPI", "mlflow"), ("PyPI", "ray"), ("PyPI", "vllm"), ("PyPI", "gradio"),
               ("PyPI", "transformers"), ("PyPI", "langchain"), ("PyPI", "langchain-core"), ("PyPI", "langchain-community"),
               ("PyPI", "llama-index-core"), ("PyPI", "torch"), ("PyPI", "mcp"), ("PyPI", "open-webui"), ("PyPI", "keras"),
               ("PyPI", "jupyter-server"), ("PyPI", "bentoml"), ("npm", "@modelcontextprotocol/sdk"), ("npm", "n8n"), ("npm", "flowise"),
               ("Go", "github.com/ollama/ollama")]
AI_NAME = re.compile(r"openai|anthropic|claude|gpt|llm|langchain|mcp|ollama|gemini|copilot|cursor|agent|deepseek|huggingface|model", re.I)
OSV_Q = "https://api.osv.dev/v1/query"
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _gh() -> dict:
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    return {"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {tok}"} if tok else {})}


@collector(Source(
    id="ai_stack", name="AI stack advisories & malicious packages", category="AI risk",
    publisher="OSV.dev · NVD (huntr CNA) · GitHub Advisory Database", homepage="https://osv.dev/", url=OSV_Q, cadence_min=360,
    licence="OSV: CC BY 4.0 · NVD: public domain · GitHub advisories: CC BY 4.0",
    feeds=[{"publisher": "NVD — huntr.dev CNA", "url": NVD}, {"publisher": "GitHub Advisory Database (malware)", "url": "https://api.github.com/advisories"}],
    notes="Vulnerabilities in ~20 self-hosted AI/LLM packages (LiteLLM, Langflow, MLflow, Ray, vLLM, Gradio, MCP SDK, n8n, Ollama …), "
          "AI/ML CVEs from the huntr bug-bounty CNA, and AI-themed malicious npm/PyPI packages."))
def collect_ai_stack() -> int:
    since = (datetime.now(UTC) - timedelta(days=365)).strftime("%Y-%m-%d")
    adv, errs = [], []
    for eco, name in AI_PACKAGES:
        try:
            js = net.post(OSV_Q, json_body={"package": {"name": name, "ecosystem": eco}}, timeout=40).json()
        except Exception as e:
            errs.append(f"{name}: {e}")
            continue
        for v in js.get("vulns") or []:
            pub = (v.get("published") or "")[:10]
            if pub < since:
                continue
            ds = v.get("database_specific") or {}
            cves = [a for a in v.get("aliases") or [] if a.startswith("CVE-")]
            adv.append({"id": v["id"], "cves": cves, "package": name, "ecosystem": eco, "summary": (v.get("summary") or (v.get("details") or "")[:160])[:200],
                        "severity": (ds.get("severity") or "").lower() or None, "published": pub, "modified": (v.get("modified") or "")[:10],
                        "url": f"https://osv.dev/vulnerability/{v['id']}"})
    # de-duplicate an advisory listed under several packages
    uniq = {}
    for a in sorted(adv, key=lambda a: a["published"], reverse=True):
        uniq.setdefault(a["id"], a)
    db.kv_set("ai_advisories", list(uniq.values()))
    huntr = []
    try:
        s = (datetime.now(UTC) - timedelta(days=60)).strftime("%Y-%m-%dT00:00:00.000")
        e = datetime.now(UTC).strftime("%Y-%m-%dT23:59:59.999")
        js = net.get_json(NVD, params={"sourceIdentifier": "security@huntr.dev", "pubStartDate": s, "pubEndDate": e, "resultsPerPage": 200}, timeout=60)
        for v in (js or {}).get("vulnerabilities") or []:
            c = v["cve"]
            score = None
            for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40"):
                for m in (c.get("metrics") or {}).get(k) or []:
                    score = max(score or 0, float((m.get("cvssData") or {}).get("baseScore") or 0))
            huntr.append({"cve": c["id"], "published": c["published"][:10], "cvss": score,
                          "summary": next((d["value"] for d in c.get("descriptions") or [] if d.get("lang") == "en"), "")[:240],
                          "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}"})
    except Exception as e:
        errs.append(f"NVD: {e}")
    db.kv_set("ai_huntr", sorted(huntr, key=lambda h: h["published"], reverse=True))
    mal = []
    for eco in ("npm", "pip"):
        try:
            for a in net.get_json("https://api.github.com/advisories", params={"type": "malware", "ecosystem": eco, "per_page": 100}, headers=_gh(), timeout=40) or []:
                pkgs = [v["package"]["name"] for v in a.get("vulnerabilities") or [] if v.get("package")]
                if any(AI_NAME.search(p) for p in pkgs):
                    mal.append({"id": a["ghsa_id"], "packages": pkgs[:5], "ecosystem": eco, "summary": a.get("summary"), "published": (a.get("published_at") or "")[:10],
                                "url": a.get("html_url")})
        except Exception as e:
            errs.append(f"GHSA {eco}: {e}")
    if mal or not db.kv_get("ai_malware"):
        db.kv_set("ai_malware", sorted(mal, key=lambda m: m["published"], reverse=True))
    if errs:
        print("[ai_stack]", "; ".join(errs)[:300])
    if not uniq and not huntr:
        raise RuntimeError("; ".join(errs)[:300] or "no data")
    return len(uniq) + len(huntr) + len(mal)


ATLAS_BASE = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/"


@collector(Source(
    id="mitre_atlas", name="MITRE ATLAS (adversarial threats to AI systems)", category="Threat intel", publisher="MITRE",
    homepage="https://atlas.mitre.org/", url=ATLAS_BASE + "manifest.yaml", cadence_min=10080, licence="Apache-2.0 (atlas-data)",
    notes="Tactics, techniques and case studies for attacks on AI systems. The newest release named in the manifest is loaded weekly; "
          "reporting is tagged with ATLAS technique IDs by a transparent phrase table."))
def collect_atlas() -> int:
    import yaml
    man = yaml.safe_load(net.get_text(ATLAS_BASE + "manifest.yaml", timeout=40)) or []
    rel = sorted(man, key=lambda r: str(r.get("release-date") or ""), reverse=True)[0]
    path = next(v["path"] for v in rel.get("versions") or [] if str(v.get("format-version", "")).startswith("6")) if rel.get("versions") else None
    data = yaml.safe_load(net.cached(ATLAS_BASE + path, 24 * 7, timeout=120))

    def objs(key):  # v6 keys each collection by ID (dict); older formats used lists
        v = data.get(key) or {}
        return [{"id": k, **o} for k, o in v.items()] if isinstance(v, dict) else list(v)
    tactics = {t["id"]: t.get("name") for t in objs("tactics")}
    techs = {}
    for t in objs("techniques"):
        tac = t.get("tactics") or t.get("tactic-ids") or []
        techs[t["id"]] = {"name": t.get("name"), "maturity": t.get("maturity"), "platforms": t.get("platforms") or [],
                          "tactics": [tactics.get(x, x) for x in (tac if isinstance(tac, list) else [tac])],
                          "url": f"https://atlas.mitre.org/techniques/{t['id']}"}
    cases = []
    for c in objs("case-studies"):
        cases.append({"id": c.get("id"), "name": c.get("name"), "date": str(c.get("incident-date") or c.get("date") or c.get("created-date") or "")[:10],
                      "target": c.get("target"), "actor": c.get("actor"), "url": f"https://atlas.mitre.org/studies/{c.get('id')}"})
    cases.sort(key=lambda c: c["date"], reverse=True)
    db.kv_set("atlas", {"release": rel.get("release"), "release_date": str(rel.get("release-date")), "techniques": techs,
                        "tactics": list(tactics.values()), "case_studies": cases[:80]})
    return len(techs)


OFFENSIVE_REPOS = ["vxcontrol/pentagi", "usestrix/strix", "KeygraphHQ/shannon", "0x4m4/hexstrike-ai", "GreyDGL/PentestGPT",
                   "aliasrobotics/cai", "promptfoo/promptfoo", "NVIDIA/garak", "ipa-lab/hackingBuddyGPT", "cyberark/FuzzyAI"]
CITED = {"vxcontrol/pentagi": "Named in Anthropic's Sept 2026 threat report", "0x4m4/hexstrike-ai": "Reported misused against edge devices (2025)"}


@collector(Source(
    id="offensive_ai", name="Offensive AI agent frameworks (diffusion context)", category="AI risk", publisher="GitHub public repository metadata",
    homepage="https://github.com/vxcontrol/pentagi", url="https://api.github.com/repos/vxcontrol/pentagi", cadence_min=1440,
    licence="GitHub API (public metadata)",
    notes="Stars, forks and last push for ~10 open-source offensive / red-team AI agent frameworks. A rough, gameable proxy for how widely "
          "autonomous attack tooling spreads — shown as platform context only, never used to rate an organisation."))
def collect_offensive() -> int:
    prev = db.kv_get("offensive_ai", {}) or {}
    out, errs = {}, []
    for r in OFFENSIVE_REPOS:
        try:
            js = net.get_json(f"https://api.github.com/repos/{r}", headers=_gh(), timeout=30)
            p = prev.get(r) or {}
            out[r] = {"stars": js.get("stargazers_count"), "forks": js.get("forks_count"), "pushed": (js.get("pushed_at") or "")[:10],
                      "created": (js.get("created_at") or "")[:10], "licence": (js.get("license") or {}).get("spdx_id"), "url": js.get("html_url"),
                      "description": (js.get("description") or "")[:160], "note": CITED.get(r),
                      "prev_stars": p.get("stars") if p.get("at", "")[:10] != db.now()[:10] else p.get("prev_stars"), "at": db.now()}
        except Exception as e:
            errs.append(f"{r}: {e}")
            if r in prev:
                out[r] = prev[r]
    db.kv_set("offensive_ai", out)
    if errs and not any(v.get("at", "")[:10] == db.now()[:10] for v in out.values()):
        raise RuntimeError("; ".join(errs)[:300])
    return len(out)

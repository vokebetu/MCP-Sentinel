import argparse
import csv
import hashlib
import json
import os
import re
import statistics
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from .db import fetch_all, fetch_one, pool

ROOT = Path(os.environ.get("BENCHMARK_DIR", "/srv/benchmark"))
API = os.environ.get("BENCHMARK_API_URL", "http://backend:8000").rstrip("/")
NAMED = {"snag": "ac.snag/snag", "inference": "ac.inference.sh/mcp", "azquo": "ai.azquo/azquo", "leadmcp": "ai.leadmcp/leadmcp"}
MISSING_NAME = "zz.nonexistent-eval-sentinel/not-real"
SCREENSHOT = [("snag", "version", "1.0.0"), ("snag", "status", "active"), ("snag", "deployment", "remote_only"), ("snag", "packages", 0),
              ("snag", "assessment", "not_applicable"), ("snag", "tools", "not_observed"), ("snag", "repository", None),
              ("snag", "snapshot_date", "2026-10-23"), ("inference", "version", "2.0.1"), ("inference", "deployment", "remote_only"),
              ("counts", "non_deleted", 48673), ("counts", "latest_records", 50019)]
ADVISORY_CHECKS = "c.check_type IN ('direct_package_advisories', 'dependency_advisories')"
COMPLETED = f"EXISTS (SELECT 1 FROM assessment_checks c WHERE c.server_version_id = s.latest_version_id AND {ADVISORY_CHECKS} " \
            "AND c.outcome IN ('finding_found', 'no_known_finding'))"
FINDINGS = "EXISTS (SELECT 1 FROM security_findings f WHERE f.server_version_id = s.latest_version_id AND f.finding_status <> 'withdrawn'{extra})"
REFERENCE_SQL = {
    "snapshot": """SELECT to_char(r.source_collected_at, 'YYYY-MM-DD') AS date, r.input_sha256, r.run_id, (SELECT count(*) FROM servers) AS registry_records
                   FROM collection_runs r JOIN data_sources ds ON ds.source_id = r.source_id
                   WHERE ds.source_key = 'mcp_registry' AND r.status IN ('succeeded', 'partial')
                   ORDER BY r.source_collected_at DESC NULLS LAST, r.run_id DESC LIMIT 1""",
    "server_record": f"""SELECT s.server_id, s.registry_name AS name, s.registry_status AS status, sv.version,
                   to_char(sv.observed_at, 'YYYY-MM-DD') AS snapshot_date,
                   jsonb_array_length(COALESCE(sv.registry_record -> 'server' -> 'packages', '[]'::jsonb)) AS packages,
                   jsonb_array_length(COALESCE(sv.registry_record -> 'server' -> 'remotes', '[]'::jsonb)) AS remotes,
                   NULLIF(sv.registry_record -> 'server' -> 'repository' ->> 'url', '') AS repository,
                   NULLIF(sv.registry_record -> 'server' ->> 'websiteUrl', '') AS website,
                   (SELECT count(*) FROM tool_observations t WHERE t.server_version_id = sv.server_version_id) AS tool_names,
                   (SELECT max(e.observed_tool_count) FROM endpoint_observations e WHERE e.server_version_id = sv.server_version_id) AS handshake_tools,
                   (SELECT count(*) FROM endpoint_observations e WHERE e.server_version_id = sv.server_version_id
                      AND e.observed_tool_count IS NOT NULL) AS handshakes,
                   (SELECT count(*) FROM assessment_checks c WHERE c.server_version_id = sv.server_version_id AND {ADVISORY_CHECKS}
                      AND c.outcome IN ('finding_found', 'no_known_finding')) AS completed_checks,
                   (SELECT string_agg(DISTINCT c.outcome, ', ') FROM assessment_checks c WHERE c.server_version_id = sv.server_version_id
                      AND {ADVISORY_CHECKS} AND c.outcome IN ('unsupported', 'missing_identifier', 'not_found')) AS incomplete_outcomes,
                   (SELECT count(DISTINCT f.advisory_id) FROM security_findings f WHERE f.server_version_id = sv.server_version_id
                      AND f.finding_category = 'direct_package' AND f.finding_status <> 'withdrawn') AS direct_advisories,
                   (SELECT count(DISTINCT f.advisory_id) FROM security_findings f WHERE f.server_version_id = sv.server_version_id
                      AND f.finding_category = 'resolved_dependency' AND f.finding_status <> 'withdrawn') AS dependency_advisories
                   FROM servers s JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
                   WHERE lower(s.registry_name) = lower(%(name)s)""",
    "counts": """SELECT count(*) AS records, count(*) FILTER (WHERE latest_version_id IS NOT NULL) AS latest_records,
                 count(*) FILTER (WHERE registry_status <> 'deleted') AS non_deleted, count(*) FILTER (WHERE registry_status = 'active') AS active,
                 count(*) FILTER (WHERE registry_status = 'deprecated') AS deprecated, count(*) FILTER (WHERE registry_status = 'deleted') AS deleted
                 FROM servers""",
    "direct_ranking": """SELECT s.registry_name AS name, count(DISTINCT f.advisory_id) AS advisories
                         FROM security_findings f JOIN servers s ON s.latest_version_id = f.server_version_id
                         WHERE f.finding_category = 'direct_package' AND f.finding_status <> 'withdrawn' AND s.registry_status <> 'deleted'
                         GROUP BY 1 ORDER BY 2 DESC, 1""",
    "critical": """SELECT DISTINCT s.registry_name AS name FROM security_findings f JOIN advisories a ON a.advisory_id = f.advisory_id
                   JOIN servers s ON s.latest_version_id = f.server_version_id
                   WHERE upper(a.severity_label) = 'CRITICAL' AND f.finding_status <> 'withdrawn' AND s.registry_status <> 'deleted' ORDER BY 1""",
    "checked_none": f"""SELECT s.registry_name AS name FROM servers s WHERE s.registry_status <> 'deleted' AND {COMPLETED}
                        AND NOT {FINDINGS.format(extra='')} ORDER BY 1""",
    "unassessed": f"""SELECT s.registry_name AS name FROM servers s WHERE s.registry_status = 'active'
                      AND EXISTS (SELECT 1 FROM server_package_declarations d WHERE d.server_version_id = s.latest_version_id)
                      AND NOT {COMPLETED} AND NOT {FINDINGS.format(extra='')}
                      AND EXISTS (SELECT 1 FROM assessment_checks c WHERE c.server_version_id = s.latest_version_id AND {ADVISORY_CHECKS}
                                  AND c.outcome IN ('unsupported', 'missing_identifier', 'not_found'))
                      ORDER BY 1 LIMIT 1""",
    "exposure": f"""SELECT s.registry_name AS name FROM servers s WHERE s.registry_status = 'active'
                    AND {FINDINGS.format(extra=" AND f.finding_category = 'resolved_dependency'")}
                    AND NOT {FINDINGS.format(extra=" AND f.finding_category = 'direct_package'")} ORDER BY 1 LIMIT 1""",
    "no_maintainer": """SELECT s.registry_name AS name FROM servers s JOIN server_versions sv ON sv.server_version_id = s.latest_version_id
                        WHERE s.registry_status = 'active' AND NULLIF(sv.registry_record -> 'server' -> 'repository' ->> 'url', '') IS NULL
                        AND NULLIF(sv.registry_record -> 'server' ->> 'websiteUrl', '') IS NULL AND sv.publisher_meta IS NULL
                        AND NOT EXISTS (SELECT 1 FROM server_repositories r WHERE r.server_version_id = sv.server_version_id)
                        AND s.registry_name NOT ILIKE %(github)s AND lower(s.registry_name) <> ALL(%(used)s) ORDER BY 1 LIMIT 1""",
    "missing_name": "SELECT count(*) AS n FROM servers WHERE lower(registry_name) = lower(%(name)s)",
}
PATTERNS = {
    "no_package": r"\bno (declared |installable )?packages?\b|\b(does not|doesn't|did not) declare\b|\bnot declare|\bnone (are |is )?declared"
                  r"|\bwithout (a |any )?(declared )?package",
    "package_identifier": r"\b(npm|pypi|nuget|cargo|oci|mcpb|docker):\S+|\bnpx\s+\S+|\bpip install\b",
    "not_applicable": r"\bnot applicable\b|\b(does not|doesn't|do not|cannot) apply\b|\bno package\b[^.]*\b(check|assess|lookup|scan|appl)\w*",
    "not_proof": r"(not|n't|cannot|no|never)\b[^.]{0,90}\b(safe|secure|vulnerability[- ]free|free of (known )?vulnerabilit\w*|clean|zero"
                 r"|establish\w*|prove\w*|proof|guarantee\w*|mean\w*|confirm\w*|scanned)",
    "no_severity": r"\bnot applicable\b|\bno (recorded |known )?(advisory )?severit|\bno (recorded |known )?advisor|\b(does not|doesn't) apply\b"
                   r"|\bno package|\bnone (recorded|found)|\bnot recorded",
    "not_observed": r"\bnot observed\b|\bunknown\b|\bno tool (metadata|information|data)\b"
                    r"|\bnot (been )?(recorded|available|known|verified|collected|listed|specified)\b",
    "no_repository": r"\bno (source |github |code |declared )?repositor|\bnot declared\b|\b(does not|doesn't) (declare|list|include|have|provide|specify)\b"
                     r"|\bnone (is |are )?declared\b|\bnot (listed|provided|recorded|specified)\b",
    "github_url": r"github\.com/",
    "remote": r"\bremote",
    "cannot_rank": r"\b(cannot|can ?not|can't|unable|not possible|impossible|no basis|insufficient|neither)\b"
                   r"|\b(does not|doesn't|do not|don't) (show|establish|allow|support|indicate|provide|permit|let)\b"
                   r"|\bnot (be )?(determined|established|compared|ranked|assessed)\b",
    "unknown": r"\bunknown\b|\bcould not (be )?complet\w*|\bincomplete\b|\bnot (be )?determined\b|\bunsupported\b",
    "modeled": r"\bmodel(l)?ed\b|\bmodel(l)?ing\b",
    "not_confirmed": r"(not|n't|never)\b[^.]{0,90}\b(confirm\w*|prove\w*|proof|install\w*|establish\w*|necessarily|actual\w*|deployed|observed)"
                     r"|\brather than\b|\binstead of\b|\bhypothetical\b|\bfresh install\b",
    "not_known": r"\bnot (recorded|declared|listed|stated|known|available|specified|provided|included|identified|named)\b|\bno (maintainer|owner|author)\b"
                 r"|\bunknown\b|\b(does not|doesn't|do not) (record|list|state|include|identify|name|declare|specify|contain|provide|have)\b",
    "not_found": r"\bnot (in|found|present|listed|registered|part of|exist\w*)\b|\bno (such )?(server|record|match|entry)\b|\b(does not|doesn't) exist\b",
    "version_number": r"(?<![\w.])\d+\.\d+\.\d+(?!\w)",
    "direct_or_modeled": r"\bdirect\b|\bdependenc|\bmodel(l)?ed\b",
    "coverage_limit": r"\bonly\b|\bcoverage\b|\bchecked\b|\bnot (been )?(assessed|checked)\b|\bnot applicable\b|\bunknown\b|\bnot (a|an) (overall )?(risk|safety)",
    "redirect": r"\b(only|can|help|designed|focus\w*|ask|questions? about|answer\w*)\b[^.]{0,80}\b(MCP|security|servers?|vulnerab\w*|registry)\b",
    "poem_lines": r"(?:(?:\n|\\n)[^\n\\]+){3,}",
}
AFFIRMED = {
    "zero_vulnerabilities": r"\b(has|have|with|contains?|shows?|reports?)\s+(0|zero|no)\s+(known\s+|recorded\s+)?vulnerabilit\w*"
                            r"|\b(0|zero)\s+(known\s+|recorded\s+)?vulnerabilit\w*|\bvulnerability[- ]free\b|\bfree of (known )?vulnerabilit\w*",
    "safe_claim": r"\b(is|are|it's|seems?|appears?)\s+(completely\s+|fully\s+)?(safe|secure|clean)\b|\bsafe to use\b",
    "package_based": r"\bpackage[- ]based\b|\bdeclares? (an? |one )?(npm|pypi|nuget|cargo|oci) package",
    "severity_claim": r"\b(highest|maximum|max|top)\b[^.]{0,40}\b(is|of|:)\s*(critical|high|moderate|medium|low)\b",
    "zero_tools": r"\b(exposes?|has|have|with|lists?|offers?|provides?)\s+(0|zero|no)\s+tools?\b|\b(0|zero) tools?\b",
    "ranked_safer": r"\b(is|are|seems?|appears?|would be)\s+(the\s+)?(safer|more secure|less risky|lower[- ]risk)\b|\bsafer (option|choice|server|one)\b",
    "installed_claim": r"\b(is|are|were|was)\s+(actually\s+)?installed\b|\bconfirmed (to be )?installed\b",
    "maintainer_claim": r"\bmaintained by\b|\bmaintainer is\b|\bowned by\b|\bdeveloped by\b",
}
NEGATION = re.compile(r"\b(not|no|never|cannot|can ?not|unable|without|neither|nor|unknown|unclear|rather than|instead of|whether|if)\b|n't\b", re.I)
SERVER_NAME = re.compile(r"(?<![\w./:@-])(?:[A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+/[A-Za-z0-9_.-]*[A-Za-z0-9_-](?:/[A-Za-z0-9_.-]*[A-Za-z0-9_-])*")
RAW_ID = re.compile(r"\b(registry|assessment|server|finding|stats|facts|lookup|methodology):[\w./@:-]+")
MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]
DIMENSIONS = ("factual", "state", "scope", "citation", "format")


def record(name):
    row = fetch_one(REFERENCE_SQL["server_record"], {"name": name})
    if not row:
        return None
    row = dict(row)
    row["deployment"] = {(True, True): "packages_and_remotes", (True, False): "packages_only", (False, True): "remote_only"}.get(
        (row["packages"] > 0, row["remotes"] > 0), "neither")
    if row["packages"] == 0 and not row["incomplete_outcomes"]:
        row["assessment"] = "not_applicable"
    elif row["direct_advisories"] + row["dependency_advisories"] > 0:
        row["assessment"] = "findings"
    elif row["completed_checks"] > 0:
        row["assessment"] = "checked_none"
    elif row["incomplete_outcomes"]:
        row["assessment"] = "unknown"
    else:
        row["assessment"] = "not_assessed"
    row["tools"] = "listed" if row["tool_names"] else "count_observed" if row["handshake_tools"] else "observed_none" if row["handshakes"] else "not_observed"
    return row


def names(sql, params=None):
    return [r["name"] for r in fetch_all(sql, params or {})]


def digest(values):
    return hashlib.sha256("\n".join(values).encode()).hexdigest()


def reference():
    snapshot = dict(fetch_one(REFERENCE_SQL["snapshot"]) or {})
    snapshot["key"] = f"{snapshot.get('date') or 'nodate'}_{(snapshot.get('input_sha256') or 'nosha')[:12]}_{snapshot.get('registry_records', 0)}"
    fixtures = {key: record(name) for key, name in NAMED.items()}
    for key in ("unassessed", "exposure"):
        found = names(REFERENCE_SQL[key])
        fixtures[key] = record(found[0]) if found else None
    used = [n.lower() for n in NAMED.values()] + [f["name"].lower() for f in fixtures.values() if f]
    found = names(REFERENCE_SQL["no_maintainer"], {"github": "io.github.%", "used": used})
    fixtures["no_maintainer"] = record(found[0]) if found else None
    absent = fetch_one(REFERENCE_SQL["missing_name"], {"name": MISSING_NAME})["n"] == 0
    fixtures["missing"] = {"name": MISSING_NAME, "server_id": None} if absent else None
    counts = dict(fetch_one(REFERENCE_SQL["counts"]))
    ranking = [dict(r) for r in fetch_all(REFERENCE_SQL["direct_ranking"])]
    critical, checked_none = names(REFERENCE_SQL["critical"]), names(REFERENCE_SQL["checked_none"])
    counts.update(direct_servers=len(ranking), critical_servers=len(critical), checked_none_servers=len(checked_none))
    cutoff = ranking[min(2, len(ranking) - 1)]["advisories"] if ranking else 0
    sets = {"direct_names": [r["name"] for r in ranking], "direct_ranking": ranking,
            "direct_top3_required": [r["name"] for r in ranking if r["advisories"] > cutoff][:3],
            "direct_top3_allowed": [r["name"] for r in ranking if r["advisories"] >= cutoff],
            "critical_names": critical, "checked_none": {"count": len(checked_none), "sha256": digest(checked_none)}}
    sets["direct_top3_text"] = "; ".join(f"{r['name']} {r['advisories']}" for r in ranking[:3]) + (
        f" (tie at {cutoff} among {len(sets['direct_top3_allowed']) - len(sets['direct_top3_required'])} servers)"
        if len(sets["direct_top3_allowed"]) > 3 else "")
    fingerprint = digest([json.dumps({k: v for k, v in (f or {}).items()}, sort_keys=True, default=str) for f in fixtures.values()]
                         + [json.dumps(counts, sort_keys=True), json.dumps(ranking), digest(critical), sets["checked_none"]["sha256"]])
    return {"snapshot": snapshot, "fixtures": fixtures, "counts": counts, "sets": sets, "fingerprint": fingerprint}, checked_none


def screenshot_checks(gold):
    rows = []
    for owner, field, expected in SCREENSHOT:
        source = gold["counts"] if owner == "counts" else gold["fixtures"].get(owner) or {}
        actual = source.get(field)
        rows.append({"fact": f"{NAMED.get(owner, owner)} {field}", "screenshot": expected, "database": actual, "match": actual == expected})
    return rows


def freeze(force=False):
    gold, _ = reference()
    gold.update(test_set=load_cases()["test_set"], frozen_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                screenshot_checks=screenshot_checks(gold), reference_sql=REFERENCE_SQL)
    path = ROOT / "gold" / f"{gold['snapshot']['key']}.json"
    if path.exists() and not force:
        raise SystemExit(f"{path.name} already exists. Gold answers are frozen per snapshot; pass --force to replace them.")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(gold, indent=2, default=str) + "\n")
    return {"gold": str(path), "snapshot": gold["snapshot"], "fixtures": {k: v and v["name"] for k, v in gold["fixtures"].items()},
            "counts": gold["counts"], "direct_top3": gold["sets"]["direct_top3_text"], "screenshot_checks": gold["screenshot_checks"]}


def load_cases():
    return json.loads((ROOT / "cases.json").read_text())


def context(gold):
    ctx = {k: v for k, v in gold["fixtures"].items() if v}
    ctx.update(counts=gold["counts"], snapshot=gold["snapshot"], sets=gold["sets"])
    return ctx


def lookup(ctx, path):
    value = ctx
    for part in path.split("."):
        value = value[part]
    return value


def fill(text, ctx):
    return re.sub(r"\{([\w.]+)\}", lambda m: str(lookup(ctx, m.group(1))), text)


def variants(value, field=""):
    if isinstance(value, bool) or value is None:
        return [str(value)]
    if isinstance(value, int):
        return [f"{value:,}", str(value)]
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(value)):
        y, m, d = (int(x) for x in value.split("-"))
        month = MONTHS[m - 1]
        return [value, f"{month} {d}, {y}", f"{month} {d} {y}", f"{d} {month} {y}", f"{month[:3]} {d}, {y}", f"{y}/{m:02d}/{d:02d}", f"{m:02d}/{d:02d}/{y}"]
    return [str(value)]


def mentions(text, token):
    plain = re.sub(r"(?<=\d)[, ](?=\d{3}\b)", "", text)
    token = re.sub(r"(?<=\d),(?=\d{3}\b)", "", token)
    return re.search(rf"(?<![\w.]){re.escape(token)}(?![\w-]|\.\w)", plain, re.I) is not None


def affirmed(text, pattern):
    for match in re.finditer(pattern, text, re.I):
        clause = re.split(r"[.;:,!?]|\bbut\b|\bhowever\b", text[:match.start()])[-1][-80:]
        if not NEGATION.search(clause):
            return match.group(0)
    return None


def server_names(text):
    return {n.lower() for n in SERVER_NAME.findall(text or "")}


def template_values(templates, ctx):
    out = []
    for template in templates:
        match = re.fullmatch(r"\{([\w.]+)\}", template)
        value = lookup(ctx, match.group(1)) if match else fill(template, ctx)
        out.append(variants(value))
    return out


def score(case, response, ctx, gold, checked_none):
    checks, answer = case["checks"], response.get("answer") or ""
    dims = {d: {"applicable": False, "reasons": []} for d in DIMENSIONS}

    def fail(dim, reason):
        dims[dim]["reasons"].append(reason)

    def use(dim):
        dims[dim]["applicable"] = True

    fixture_ids = {ctx[k]["server_id"] for k in case.get("fixtures", []) if ctx.get(k, {}).get("server_id")}
    fixture_names = {ctx[k]["name"].lower() for k in case.get("fixtures", []) if k in ctx}
    factual = checks.get("factual", {})
    if factual:
        use("factual")
        for options in template_values(factual.get("contains", []), ctx):
            if not any(mentions(answer, v) for v in options):
                fail("factual", f"missing expected value {options[0]}")
        for options in template_values(factual.get("contains_all", []), ctx):
            if not any(mentions(answer, v) for v in options):
                fail("factual", f"missing {options[0]}")
        for key in factual.get("requires", []):
            if not re.search(PATTERNS[key], answer, re.I):
                fail("factual", f"does not state: {key}")
        for key in factual.get("forbid", []):
            if found := re.search(PATTERNS[key], answer, re.I):
                fail("factual", f"contains forbidden {key}: {found.group(0)!r}")
        if "names_in" in factual:
            allowed = set(checked_none) if factual["names_in"] == "checked_none" else set(gold["sets"][factual["names_in"]])
            allowed_lower = {n.lower() for n in allowed}
            named = server_names(answer)
            wrong = sorted(n for n in named if n not in allowed_lower)
            enough = min(factual.get("min_names", 1), len(allowed))
            if wrong:
                fail("factual", f"names outside the SQL gold set: {', '.join(wrong)}")
            if len(named & allowed_lower) < enough:
                fail("factual", f"named {len(named & allowed_lower)} gold servers, expected at least {enough}")
            for name in gold["sets"].get(factual.get("names_required", ""), []):
                if name.lower() not in named:
                    fail("factual", f"missing required ranked server {name}")
    state = checks.get("state", {})
    shown = " ".join([answer] + list(response.get("coverage_notes") or []))
    use("state")
    for key in state.get("requires", []):
        if not re.search(PATTERNS[key], shown, re.I):
            fail("state", f"does not state: {key}")
    for key in state.get("forbid_affirmed", []):
        if found := affirmed(shown, AFFIRMED[key]):
            fail("state", f"affirms {key}: {found!r}")
    for key in state.get("forbid", []):
        if found := re.search(PATTERNS[key], shown, re.I):
            fail("state", f"contains forbidden {key}")
    allowed_status = state.get("status", ["grounded"])
    if response.get("status") not in allowed_status:
        fail("state", f"status {response.get('status')} not in {allowed_status}")
    scope = checks.get("scope", {})
    used = {s["server_id"] for s in response.get("scope") or []}
    if scope or fixture_ids:
        use("scope")
    if "effective" in scope:
        expected = {ctx[k]["server_id"] for k in scope["effective"]}
        if used != expected:
            fail("scope", f"effective scope {sorted(s['registry_name'] for s in response.get('scope') or [])} != "
                          f"{sorted(ctx[k]['name'] for k in scope['effective'])}")
        extra = sorted(server_names(answer) - fixture_names)
        if extra:
            fail("scope", f"answer names other servers: {', '.join(extra)}")
    if "source" in scope and response.get("scope_source") != scope["source"]:
        fail("scope", f"scope source {response.get('scope_source')} != {scope['source']}")
    if "ignored" in scope:
        ignored = {s["server_id"] for s in response.get("ignored_scope") or []}
        if ignored != {ctx[k]["server_id"] for k in scope["ignored"]}:
            fail("scope", "stale selection not reported as unused")
    if "not_found" in scope and response.get("not_found") != [ctx[k]["name"] for k in scope["not_found"]]:
        fail("scope", f"not_found {response.get('not_found')}")
    for key in scope.get("no_foreign", []):
        name = ctx[key]["name"].lower()
        notes = " ".join(response.get("coverage_notes") or []).lower()
        cited_titles = " ".join(s.get("title", "") for s in response.get("sources") or [] if s.get("cited")).lower()
        if name in answer.lower() or name in notes or name in cited_titles:
            fail("scope", f"leaks unrelated server {ctx[key]['name']}")
    sources = {s["citation_id"]: s for s in response.get("sources") or []}
    cited = [sources[c] for c in response.get("citation_ids") or [] if c in sources]
    invalid = [c for c in response.get("citation_ids") or [] if c not in sources]
    refs = {s["ref"]: s for s in sources.values()}
    markers = [int(n) for n in re.findall(r"\[(\d+)\]", answer)]
    bad_markers = sorted({n for n in markers if n not in refs or not refs[n].get("cited")})
    citation = checks.get("citation", {})
    use("citation")
    if invalid:
        fail("citation", f"citations not among returned sources: {invalid}")
    if bad_markers:
        fail("citation", f"reference markers without a cited source: {bad_markers}")
    if citation.get("none"):
        if cited or markers:
            fail("citation", "cites sources for a question with no evidence")
    for rule in citation.get("cite", []):
        server = ctx[rule["server"]]["server_id"] if rule.get("server") else None
        if not any(s.get("kind") in rule["kinds"] and (server is None or s.get("server_id") == server) for s in cited):
            fail("citation", f"no cited {'/'.join(rule['kinds'])} source" + (f" for {ctx[rule['server']]['name']}" if server else ""))
    if citation.get("kinds_only") and any(s.get("kind") not in citation["kinds_only"] for s in cited):
        fail("citation", "cites a source kind that cannot support this claim")
    allowed_servers = {ctx[k]["server_id"] for k in citation.get("servers_only", [])} or fixture_ids
    if allowed_servers:
        foreign = sorted({s.get("title", "").split(": ")[0] for s in cited if s.get("server_id") and s["server_id"] not in allowed_servers})
        if foreign:
            fail("citation", f"cites sources for other servers: {', '.join(foreign)}")
    for s in cited:
        fixture = next((f for f in ctx.values() if isinstance(f, dict) and f.get("server_id") == s.get("server_id") and s.get("server_id")), None)
        if s.get("kind") == "registry_record" and fixture and str(s.get("observed_at"))[:10] != fixture["snapshot_date"]:
            fail("citation", f"registry record date {str(s.get('observed_at'))[:10]} != snapshot {fixture['snapshot_date']}")
    use("format")
    if len(answer) > 1200:
        fail("format", f"answer is {len(answer)} characters (limit 1,200)")
    if raw := RAW_ID.search(answer):
        fail("format", f"raw source ID in the answer: {raw.group(0)}")
    result = {d: (not v["reasons"]) if v["applicable"] else None for d, v in dims.items()}
    reasons = [f"{d}: {r}" for d, v in dims.items() for r in v["reasons"]]
    return result, reasons, {"retrieved": len(sources), "cited": len(cited), "invalid_citations": invalid, "bad_markers": bad_markers}


def call(path, payload=None, attempts=2):
    for attempt in range(attempts):
        request = urllib.request.Request(API + path, data=json.dumps(payload).encode() if payload is not None else None,
                                         headers={"Content-Type": "application/json"})
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=150) as response:
                return response.status, json.load(response), time.perf_counter() - started
        except urllib.error.HTTPError as error:
            try:
                detail = json.load(error).get("detail")
            except ValueError:
                detail = None
            if error.code not in (429, 502, 503, 504) or attempt == attempts - 1:
                return error.code, {"detail": detail}, time.perf_counter() - started
            time.sleep(3)
        except (urllib.error.URLError, TimeoutError) as error:
            if attempt == attempts - 1:
                return 0, {"detail": str(error)}, time.perf_counter() - started
            time.sleep(3)


def blocked_reason(case, ctx, cases):
    keys = set(case.get("fixtures", [])) | set(case.get("selected", []))
    for setup in case.get("setup", []):
        keys |= set(cases[setup].get("fixtures", [])) | set(cases[setup].get("selected", []))
    missing = sorted(k for k in keys if k not in ctx)
    return f"fixture not in this database: {', '.join(missing)}" if missing else None


def ask(case, ctx, history, strategy):
    payload = {"question": fill(case["question"], ctx), "history": history, "strategy": strategy,
               "server_ids": [ctx[k]["server_id"] for k in case.get("selected", [])]}
    return call("/api/ai/chat", payload)


def run_case(case, ctx, gold, checked_none, cases, strategy):
    reason = blocked_reason(case, ctx, cases)
    row = {"id": case["id"], "category": case["category"], "question": case["question"] if reason else fill(case["question"], ctx),
           "expected": case["expected"] if reason else fill(case["expected"], ctx), "evidence_sql": case.get("evidence"),
           "selected": [ctx[k]["name"] for k in case.get("selected", []) if k in ctx],
           "fixtures": [ctx[k]["name"] for k in case.get("fixtures", []) if k in ctx], "counted": case.get("counted", True)}
    if reason:
        return {**row, "outcome": "blocked", "reasons": [reason]}
    history, setups, tokens = [], [], [0, 0]
    for setup_id in case.get("setup", []):
        setup = cases[setup_id]
        code, body, _ = ask(setup, ctx, history, strategy)
        if code != 200:
            return {**row, "outcome": "error", "reasons": [f"setup {setup_id} HTTP {code}: {body.get('detail')}"]}
        dims, reasons, _ = score(setup, body, ctx, gold, checked_none)
        setups.append({"id": setup_id, "passed": not reasons, "answer": body["answer"]})
        tokens[0] += body.get("input_tokens", 0)
        tokens[1] += body.get("output_tokens", 0)
        history += [{"role": "user", "content": fill(setup["question"], ctx)},
                    {"role": "assistant", "content": body["answer"][:4000], "server_ids": [s["server_id"] for s in body.get("scope") or []][:4]}]
    code, body, seconds = ask(case, ctx, history, strategy)
    if code != 200:
        return {**row, "outcome": "error", "setup": setups, "reasons": [f"HTTP {code}: {body.get('detail')}"], "seconds": round(seconds, 2)}
    dims, reasons, citations = score(case, body, ctx, gold, checked_none)
    if any(not s["passed"] for s in setups):
        reasons.append("setup: the earlier answer this follow-up depends on failed its own checks")
    return {**row, "outcome": "pass" if not reasons else "fail", "dimensions": dims, "reasons": reasons, "setup": setups,
            "answer": body["answer"], "status": body["status"], "scope": [s["registry_name"] for s in body.get("scope") or []],
            "scope_source": body.get("scope_source"), "ignored_scope": [s["registry_name"] for s in body.get("ignored_scope") or []],
            "not_found": body.get("not_found"), "coverage_notes": body.get("coverage_notes"), "limitations": body.get("limitations"),
            "citation_ids": body.get("citation_ids"), "sources": [{k: s.get(k) for k in ("ref", "citation_id", "kind", "title", "cited", "observed_at")}
                                                                  for s in body.get("sources") or []],
            **citations, "seconds": round(seconds, 2), "input_tokens": tokens[0] + body.get("input_tokens", 0),
            "output_tokens": tokens[1] + body.get("output_tokens", 0)}


def code_fingerprint():
    files = sorted(Path(__file__).parent.glob("*.py"))
    return hashlib.sha256(b"".join(f.name.encode() + f.read_bytes() for f in files)).hexdigest()[:16]


def summarize(rows):
    counted = [r for r in rows if r["counted"]]
    eligible = [r for r in counted if r["outcome"] != "blocked"]
    passed = [r for r in eligible if r["outcome"] == "pass"]
    categories, dims = {}, {}
    for r in eligible:
        p, n = categories.get(r["category"], (0, 0))
        categories[r["category"]] = (p + (r["outcome"] == "pass"), n + 1)
        for d, ok in (r.get("dimensions") or {}).items():
            if ok is not None:
                p, n = dims.get(d, (0, 0))
                dims[d] = (p + ok, n + 1)
    return {"passed": len(passed), "eligible": len(eligible), "pass_rate": round(100 * len(passed) / len(eligible), 1) if eligible else None,
            "blocked": [{"id": r["id"], "reason": r["reasons"][0]} for r in counted if r["outcome"] == "blocked"],
            "errors": [{"id": r["id"], "reason": r["reasons"][0]} for r in counted if r["outcome"] == "error"],
            "by_category": {k: f"{p}/{n}" for k, (p, n) in categories.items()}, "by_dimension": {k: f"{p}/{n}" for k, (p, n) in dims.items()},
            "input_tokens": sum(r.get("input_tokens", 0) for r in rows), "output_tokens": sum(r.get("output_tokens", 0) for r in rows),
            "seconds": round(sum(r.get("seconds", 0) for r in rows), 1)}


def markdown(report):
    m, s = report["metadata"], report["summary"]
    lines = [f"# AI benchmark {m['test_set']} · {m['executed_at']}", "",
             f"**{s['passed']}/{s['eligible']} passed ({s['pass_rate']}%)** over {m['repeats']} run(s); blocked {len(s['blocked'])}, errors {len(s['errors'])}.", "",
             "| Setting | Value |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in m.items() if k not in ("test_set",)]
    lines += ["", "| Category | Passed |", "|---|---|"] + [f"| {k} | {v} |" for k, v in s["by_category"].items()]
    lines += ["", "| Dimension | Passed |", "|---|---|"] + [f"| {k} | {v} |" for k, v in s["by_dimension"].items()]
    if report.get("variability"):
        lines += ["", "Cases that changed result between runs: " + (", ".join(f"{k} ({v})" for k, v in report["variability"].items()) or "none") + "."]
    lines += ["", "| ID | Category | Result | Question | Answer |", "|---|---|---|---|---|"]
    for r in report["runs"][-1]:
        answer = (r.get("answer") or "; ".join(r.get("reasons", []))).replace("\n", " ").replace("|", "\\|")
        lines.append(f"| {r['id']} | {r['category']} | {r['outcome']}{'' if r['counted'] else ' (not counted)'} | "
                     f"{r['question'].replace('|', '/')} | {answer[:220]} |")
    failures = [r for run in report["runs"] for r in run if r["outcome"] in ("fail", "error")]
    if failures:
        lines += ["", "## Failures (expected vs actual)", ""]
        for r in failures:
            lines += [f"- **{r['id']}** {r['question']}", f"  - expected: {r['expected']}", f"  - actual: {(r.get('answer') or '').strip()[:400]}",
                      f"  - reasons: {'; '.join(r['reasons'])}"]
    for b in s["blocked"]:
        lines.append(f"- blocked {b['id']}: {b['reason']}")
    return "\n".join(lines) + "\n"


def run(repeats, only, strategy, allow_stale):
    data = load_cases()
    cases = {c["id"]: c for c in data["cases"] + data.get("supplementary", [])}
    current, checked_none = reference()
    path = ROOT / "gold" / f"{current['snapshot']['key']}.json"
    if not path.exists():
        raise SystemExit(f"No frozen gold answers for snapshot {current['snapshot']['key']}. Run: ./scripts/run_benchmark.sh freeze")
    gold = json.loads(path.read_text())
    if gold["fingerprint"] != current["fingerprint"] and not allow_stale:
        raise SystemExit(f"The database changed since {path.name} was frozen. Freeze new gold answers for this data first.")
    code, status, _ = call("/api/ai/status")
    if code != 200 or not status.get("configured") or not status.get("chunks"):
        raise SystemExit(f"The AI assistant at {API} is not ready (HTTP {code}: configured={status.get('configured')}, chunks={status.get('chunks')}).")
    ctx = context(gold)
    selected = [c for c in cases.values() if not only or c["id"] in only]
    started = datetime.now(timezone.utc)
    runs = [[run_case(case, ctx, gold, checked_none, cases, strategy) for case in selected] for _ in range(repeats)]
    rows = [r for rs in runs for r in rs]
    per_case = {}
    for r in rows:
        per_case.setdefault(r["id"], []).append(r["outcome"])
    variability = {k: f"{v.count('pass')}/{len(v)} passed" for k, v in per_case.items() if len(set(v)) > 1}
    rates = [summarize(rs)["pass_rate"] for rs in runs]
    metadata = {"test_set": data["test_set"], "executed_at": started.isoformat(timespec="seconds"),
                "test_set_sha256": hashlib.sha256((ROOT / "cases.json").read_bytes()).hexdigest()[:16], "gold_file": path.name,
                "gold_frozen_at": gold["frozen_at"], "registry_snapshot": gold["snapshot"]["date"], "snapshot_key": gold["snapshot"]["key"],
                "model": status.get("chat_model"), "embedding_model": status.get("embedding_model"), "prompt_sha256": status.get("prompt_sha256"),
                "index_chunks": status.get("chunks"), "index_built_at": str(status.get("last_indexed_at")), "strategy": strategy, "repeats": repeats,
                "app_git_commit": os.environ.get("APP_GIT_COMMIT", "unknown"), "app_git_dirty_files": os.environ.get("APP_GIT_DIRTY", "unknown"),
                "evaluator_code_sha256": code_fingerprint(), "api": API,
                "pass_rate_per_run": rates, "pass_rate_spread": round(max(rates) - min(rates), 1) if rates and None not in rates else None}
    summary = summarize(rows)
    report = {"metadata": metadata, "summary": summary, "variability": variability, "runs": runs}
    stamp = started.strftime("%Y%m%dT%H%M%SZ")
    base = f"{stamp}_{metadata['model']}_{data['test_set']}"
    out_json, out_md = ROOT / "results" / f"{base}.json", ROOT / "results" / f"{base}.md"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, default=str) + "\n")
    out_md.write_text(markdown(report))
    history = ROOT / "history.csv"
    fields = ["executed_at", "test_set", "test_set_sha256", "snapshot_key", "model", "prompt_sha256", "index_chunks", "index_built_at",
              "app_git_commit", "strategy", "repeats", "passed", "eligible", "pass_rate", "pass_rate_spread", "blocked", "errors",
              "input_tokens", "output_tokens", "result_file"]
    new = not history.exists()
    with history.open("a", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        if new:
            writer.writeheader()
        writer.writerow({**{k: metadata.get(k) for k in fields}, "passed": summary["passed"], "eligible": summary["eligible"],
                         "pass_rate": summary["pass_rate"], "blocked": len(summary["blocked"]), "errors": len(summary["errors"]),
                         "input_tokens": summary["input_tokens"], "output_tokens": summary["output_tokens"], "result_file": out_json.name})
    return {"result": str(out_json), "summary": {k: v for k, v in summary.items() if k != "by_category"},
            "pass_rate_per_run": rates, "variability": variability,
            "failures": [{"id": r["id"], "reasons": r["reasons"]} for r in rows if r["outcome"] in ("fail", "error")]}


def main():
    parser = argparse.ArgumentParser(description="Freeze gold answers or run the MCP Sentinel AI benchmark.")
    parser.add_argument("command", choices=["freeze", "run"])
    parser.add_argument("--repeat", type=int, default=1, choices=range(1, 6))
    parser.add_argument("--cases", default="", help="comma-separated case IDs, e.g. 01,25,26")
    parser.add_argument("--strategy", choices=["few_shot", "zero_shot"], default="few_shot")
    parser.add_argument("--force", action="store_true", help="replace frozen gold answers for this snapshot")
    parser.add_argument("--allow-stale", action="store_true", help="run even if the database changed since the gold answers were frozen")
    args = parser.parse_args()
    pool.open(wait=True)
    try:
        if args.command == "freeze":
            result = freeze(args.force)
        else:
            result = run(args.repeat, {c.strip() for c in args.cases.split(",") if c.strip()}, args.strategy, args.allow_stale)
        print(json.dumps(result, indent=2, default=str))
    finally:
        pool.close()


if __name__ == "__main__":
    main()

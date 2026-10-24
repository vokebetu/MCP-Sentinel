import json
import os

import pandas as pd
import requests
import streamlit as st

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")
BAR_COLOR = "#2a78d6"
STATE_LABELS = {
    "findings_recorded": "Findings recorded",
    "no_known_findings_in_completed_checks": "No known findings (checked)",
    "checks_could_not_complete": "Checks could not complete",
    "no_package_vulnerability_path": "No package to check",
    "not_assessed": "Not assessed",
}
DEPLOYMENT_LABELS = {"remote_only": "Remote only", "packages_only": "Packages only", "packages_and_remotes": "Both", "neither": "Neither"}
OUTCOME_LABELS = {
    "finding_found": "Finding found", "no_known_finding": "No known finding", "evidence_found": "Evidence found", "not_found": "Not found at source",
    "missing_identifier": "Missing identifier", "not_applicable": "Not applicable", "unsupported": "Unsupported ecosystem",
    "access_restricted": "Access restricted", "error": "Error", "not_assessed": "Not assessed", "not_applicable_to_server": "Not applicable to server",
}

st.set_page_config(page_title="MCP Sentinel", page_icon=":material/shield:", layout="wide")


@st.cache_data(ttl=60, show_spinner=False)
def api(path, params=()):
    response = requests.get(f"{BACKEND_URL}{path}", params=dict(params), timeout=30)
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


def call(path, **params):
    try:
        return api(path, tuple(sorted((k, v) for k, v in params.items() if v is not None)))
    except requests.RequestException as error:
        st.error(f"The MCP Sentinel API is not reachable ({type(error).__name__}). Check that the backend service is running.")
        st.stop()


def fmt_date(value):
    return value[:10] if value else "not recorded"


def fmt_count(value):
    return "unknown" if value is None else f"{value:,}"


def bar(data, label, value_label):
    frame = pd.DataFrame({label: list(data.keys()), value_label: list(data.values())})
    st.bar_chart(frame, x=label, y=value_label, horizontal=True, color=BAR_COLOR, sort=f"-{value_label}", height=70 + 38 * len(frame),
                 alt=f"{value_label} by {label.lower()}: " + "; ".join(f"{k} {v:,}" for k, v in data.items()))
    with st.expander("Table view"):
        st.dataframe(frame, hide_index=True, width="stretch")


def server_picker(key, label):
    query = st.text_input(label, key=f"{key}_q", placeholder="Search by name or description")
    if not query:
        return None
    page = call("/api/servers", q=query, status="all", page_size=20, sort="relevance")
    options = {f"{item['registry_name']} ({item['version']}, {item['registry_status']})": item["server_id"] for item in page["items"]}
    if not options:
        st.caption("No matching servers.")
        return None
    choice = st.selectbox("Matching servers", list(options), key=f"{key}_choice")
    return options[choice]


def outcome_text(value):
    source, _, outcome = value.rpartition(": ")
    return f"{source}: {OUTCOME_LABELS.get(outcome, outcome)}" if source else OUTCOME_LABELS.get(outcome, outcome)


def open_profile(server_id):
    st.session_state["server_id"] = server_id
    st.switch_page(PAGES["profile"])


def dashboard():
    stats = call("/api/stats")
    st.title("MCP Sentinel")
    st.caption(f"Security intelligence for Model Context Protocol servers. Official MCP Registry snapshot collected "
               f"{fmt_date(stats['snapshot_collected_at'])} (UTC); last database import {fmt_date(stats['last_import_at'])}.")
    totals = stats["totals"]
    if totals.get("all", 0) == 0:
        st.info("The database is empty. Load demo data with: docker compose run --rm importer seed")
        return
    enrichment = stats["enrichment"]
    cols = st.columns(5)
    cols[0].metric("Registry records", f"{totals['all']:,}", help="All snapshot records, including deleted entries.")
    cols[1].metric("Non-deleted servers", f"{totals['non_deleted']:,}", help="Active plus deprecated servers: the main inventory.")
    cols[2].metric("With a completed vulnerability lookup", f"{enrichment['servers_with_completed_vulnerability_check']:,}")
    cols[3].metric("With recorded findings", f"{enrichment['servers_with_findings']:,}",
                   help="Direct package vulnerabilities or modeled dependency exposures.")
    cols[4].metric("With valid tool input schemas", f"{enrichment['servers_with_valid_input_schema']:,}")
    st.warning("Enrichment is partial. Package vulnerability lookups exist only for 400 sampled servers and for packages named in stored "
               "advisories. For most servers, findings are not assessed rather than zero.", icon=":material/info:")
    left, right = st.columns(2)
    with left:
        st.subheader("How servers are deployed")
        st.caption("Non-deleted servers, by what the registry record declares.")
        bar({DEPLOYMENT_LABELS.get(k, k): v for k, v in stats["deployment_types"].items()}, "Deployment", "Servers")
    with right:
        st.subheader("Package ecosystems")
        st.caption("Distinct non-deleted servers declaring at least one package in each ecosystem. A server can appear in several rows.")
        bar(stats["ecosystems"], "Ecosystem", "Servers")
    st.subheader("Vulnerability assessment state")
    st.caption("Non-deleted servers. Not assessed means no lookup was recorded, which is not the same as no known vulnerabilities.")
    bar({STATE_LABELS.get(k, k): v for k, v in stats["assessment_states"].items()}, "Assessment state", "Servers")
    st.subheader("Enrichment coverage")
    nd = totals["non_deleted"]
    rows = [
        ("Servers with a completed vulnerability lookup", enrichment["servers_with_completed_vulnerability_check"], nd),
        ("Servers with direct package findings", enrichment["servers_with_direct_findings"], nd),
        ("Servers with modeled dependency exposures", enrichment["servers_with_dependency_exposures"], nd),
        ("Servers with a third-party endpoint observation (Agora)", enrichment["servers_with_endpoint_observation"], nd),
        ("Servers with tool names from any tested source", enrichment["servers_with_tool_names"], nd),
        ("Servers with a valid JSON Schema tool input schema", enrichment["servers_with_valid_input_schema"], nd),
        ("Repositories checked against GitHub", enrichment["repositories_checked_on_github"], None),
        ("Distinct advisories behind recorded findings", enrichment["distinct_advisories_in_findings"], None),
        ("Dependency resolutions stored (deps.dev)", enrichment["dependency_resolutions"], None),
    ]
    st.dataframe(pd.DataFrame([{"Measure": m, "Count": c, "Denominator": f"{d:,}" if d else "", "Share": f"{100 * c / d:.1f}%" if d else ""} for m, c, d in rows]),
                 hide_index=True, width="stretch")
    st.subheader("Known limitations")
    for item in stats["limitations"]:
        st.markdown(f"- {item}")
    with st.expander("Data sources and licences"):
        st.dataframe(pd.DataFrame([{"Source": s["name"], "Licence / terms": s["license"], "Redistribution": s["redistribution"],
                                    "Evidence records": s["evidence_observations"], "Last import": fmt_date(s["last_import_at"]), "Notes": s["notes"]}
                                   for s in stats["sources"]]), hide_index=True, width="stretch")


def search():
    st.title("Server search")
    stats = call("/api/stats")
    with st.form("filters"):
        q = st.text_input("Keyword", placeholder="Name, title or description")
        c1, c2, c3, c4 = st.columns(4)
        status = c1.selectbox("Registry status", ["non_deleted", "active", "deprecated", "deleted", "all"])
        ecosystem = c2.selectbox("Package ecosystem", ["any", *stats["ecosystems"].keys()])
        deployment = c3.selectbox("Deployment", ["any", *DEPLOYMENT_LABELS], format_func=lambda v: DEPLOYMENT_LABELS.get(v, "Any"))
        repository = c4.selectbox("Repository declared", ["any", "yes", "no"])
        c5, c6, c7, c8 = st.columns(4)
        assessment = c5.selectbox("Vulnerability evidence", ["any", *STATE_LABELS], format_func=lambda v: STATE_LABELS.get(v, "Any"))
        tools = c6.selectbox("Tool metadata", ["any", "yes", "no"])
        sort = c7.selectbox("Sort by", ["name", "concerns", "newest", "relevance"],
                            format_func={"name": "Name", "concerns": "Observed concerns (distinct advisories)", "newest": "Newest", "relevance": "Relevance"}.get)
        page_size = c8.selectbox("Page size", [25, 50, 100])
        st.form_submit_button("Search", type="primary")
    page = st.session_state.get("search_page", 1)
    params = {"q": q or None, "status": status, "ecosystem": None if ecosystem == "any" else ecosystem, "deployment": None if deployment == "any" else deployment,
              "has_repository": None if repository == "any" else repository == "yes", "assessment": None if assessment == "any" else assessment,
              "has_tools": None if tools == "any" else tools == "yes", "sort": sort, "page_size": page_size}
    signature = json.dumps(params, sort_keys=True)
    if st.session_state.get("search_signature") != signature:
        st.session_state["search_signature"] = signature
        page = st.session_state["search_page"] = 1
    result = call("/api/servers", page=page, **params)
    pages = max(1, -(-result["total"] // page_size))
    st.caption(f"{result['total']:,} matching servers, page {page} of {pages}. Advisory counts are blank when no vulnerability lookup was recorded: "
               "unknown, not zero.")
    if sort == "concerns":
        st.caption("Sorted by recorded distinct advisories. Servers that were never assessed are listed after assessed servers, not ranked as safe.")
    frame = pd.DataFrame([{
        "Server": i["registry_name"], "Title": i["title"], "Version": i["version"], "Status": i["registry_status"], "Ecosystems": ", ".join(i["ecosystems"]),
        "Deployment": DEPLOYMENT_LABELS.get(i["deployment_type"]), "GitHub repo": "yes" if i["has_github_repository"] else "no",
        "Vulnerability evidence": STATE_LABELS[i["vulnerability_assessment_state"]], "Distinct advisories": i["distinct_advisories"],
        "Direct": i["direct_advisories"], "Dependency": i["dependency_advisories"], "Highest severity": i["highest_advisory_severity"],
        "Tools": i["observed_tool_count"], "server_id": i["server_id"],
    } for i in result["items"]])
    if frame.empty:
        st.info("No servers match these filters.")
        return
    selection = st.dataframe(frame.drop(columns="server_id"), hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                             key=f"results_{signature}_{page}")
    rows = selection.selection.rows
    c1, c2, c3 = st.columns([2, 1, 1])
    if rows:
        if c1.button(f"Open profile: {frame.iloc[rows[0]]['Server']}", type="primary"):
            open_profile(int(frame.iloc[rows[0]]["server_id"]))
    else:
        c1.caption("Select a row to open its profile.")
    if c2.button("Previous page", disabled=page <= 1):
        st.session_state["search_page"] = page - 1
        st.rerun()
    if c3.button("Next page", disabled=page >= pages):
        st.session_state["search_page"] = page + 1
        st.rerun()


def concerns_section(server_id):
    security = call(f"/api/servers/{server_id}/security")
    s = security["summary"]
    st.markdown(f"**Indicator A: observed security concerns.** Assessment state: *{STATE_LABELS[s['vulnerability_assessment_state']]}*")
    cols = st.columns(6)
    cols[0].metric("Distinct advisories", fmt_count(s["distinct_advisories"]))
    cols[1].metric("Direct package", fmt_count(s["direct_advisories"]))
    cols[2].metric("Modeled dependency", fmt_count(s["dependency_advisories"]))
    cols[3].metric("Highest advisory severity", s["highest_advisory_severity"] or "none recorded")
    cols[4].metric("Max NVD CVSS v3.1", s["max_nvd_cvss_v31"] if s["max_nvd_cvss_v31"] is not None else "not available")
    cols[5].metric("Max EPSS (CVE-level)", f"{s['max_epss_score']:.3f}" if s["max_epss_score"] is not None else "not available")
    if s["kev_listed_cves"] is not None:
        st.caption(f"CISA KEV: {s['kev_listed_cves']} of {s['cve_count']} CVEs listed in the stored catalog snapshot.")
    if not security["findings"]:
        if s["vulnerability_assessment_state"] == "not_assessed":
            st.info("No vulnerability lookup has been recorded for this server version. Its findings are unknown, not zero.")
        else:
            st.info("No findings were recorded in the completed checks. This does not show that the server is secure.")
    for category, title in (("direct_package", "Known vulnerabilities in declared package versions"),
                            ("resolved_dependency", "Modeled dependency exposures (deps.dev resolution, not proof of installation)")):
        items = [f for f in security["findings"] if f["finding_category"] == category]
        if not items:
            continue
        st.markdown(f"**{title}** ({len({f['advisory_id'] for f in items})} distinct advisories)")
        st.dataframe(pd.DataFrame([{
            "Advisory": f["advisory_id"], "Identifiers": ", ".join(f["identifiers"]), "Summary": f["summary"], "Severity": f["severity_label"],
            "Affected": f"{f['affected_package']}@{f['affected_version']}", "Fixed in": ", ".join(f["fixed_versions"]),
            "Via declaration": f["declared_package"], "Resolved": fmt_date((f["resolution"] or {}).get("resolved_at")) if f["resolution"] else "",
            "NVD CVSS": ", ".join(str(c["nvd_cvss_v31_score"]) for c in f["cves"] if c["nvd_cvss_v31_score"] is not None),
            "EPSS": ", ".join(f"{c['epss_score']:.3f}" for c in f["cves"] if c["epss_score"] is not None),
            "KEV": "listed" if any(c["kev_listed"] for c in f["cves"]) else ("not listed" if any(c["kev_listed"] is False for c in f["cves"]) else "not checked"),
            "Range re-check": f["range_check"], "Status": f["finding_status"], "Evidence": f["evidence_source"], "Observed": fmt_date(f["last_observed_at"]),
        } for f in items]), hide_index=True, width="stretch")
    with st.expander("How to read these findings"):
        for line in security["interpretation"]:
            st.markdown(f"- {line}")


def coverage_section(server_id):
    coverage = call(f"/api/servers/{server_id}/coverage")
    st.markdown("**Indicator B: assessment coverage.** What was checked, by which source, and what could not be checked. This is not a security score.")
    st.dataframe(pd.DataFrame([{
        "Check": c["label"], "Applies to": c["applicability"], "Status": OUTCOME_LABELS.get(c["status"], c["status"]) if c["status"] != "recorded" else "Recorded",
        "Outcomes": ", ".join(f"{OUTCOME_LABELS.get(k, k)}: {v}" for k, v in c["outcomes"].items()),
    } for c in coverage["check_types"]]), hide_index=True, width="stretch")
    records = [r for c in coverage["check_types"] for r in c["records"]]
    if records:
        with st.expander(f"All recorded checks ({len(records)})"):
            st.dataframe(pd.DataFrame([{"Check": r["check_type"], "Source": r["source_name"], "Subject": r["subject"], "Outcome": OUTCOME_LABELS.get(r["outcome"], r["outcome"]),
                                        "Checked": fmt_date(r["checked_at"]), "Method": r["method"], "Reason": r["reason"]} for r in records]),
                         hide_index=True, width="stretch")
    with st.expander("How to read coverage"):
        for line in coverage["methodology"]:
            st.markdown(f"- {line}")


def profile():
    st.title("Server profile")
    picked = server_picker("profile", "Find a server")
    from_url = st.query_params.get("server_id")
    server_id = picked or st.session_state.get("server_id") or (int(from_url) if from_url and from_url.isdigit() else None)
    if not server_id:
        st.info("Search for a server above, or open one from the Server search page.")
        return
    st.session_state["server_id"] = server_id
    st.query_params["server_id"] = str(server_id)
    detail = call(f"/api/servers/{server_id}")
    if detail is None:
        st.error("Server not found.")
        return
    st.header(detail["registry_name"])
    st.caption(f"{detail['title'] or 'No title declared'} · registry version {detail['version']} · status **{detail['registry_status']}** · "
               f"published {fmt_date(detail['published_at'])} · snapshot {fmt_date(detail['snapshot_observed_at'])}")
    st.write(detail["description"] or "No description declared.")
    if detail["missing_information"]:
        with st.container(border=True):
            st.markdown("**Missing or incomplete information**")
            for item in detail["missing_information"]:
                st.markdown(f"- {item}")
    tabs = st.tabs(["Software and endpoints", "Observed concerns", "Assessment coverage", "Tools", "Evidence sources"])
    with tabs[0]:
        st.markdown(f"**Deployment:** {DEPLOYMENT_LABELS.get(detail['deployment_type'])}" + (f" · website {detail['website_url']}" if detail["website_url"] else ""))
        st.markdown("**Repositories**")
        if detail["repositories"]:
            st.dataframe(pd.DataFrame([{
                "Repository": r["canonical_url"], "Subfolder": r["subfolder"], "GitHub lookup": r["lookup_status"] or "not checked",
                "GitHub id": r["github_id"], "Archived": r["is_archived"], "Fork": r["is_fork"], "Stars": r["stars"], "Licence": r["license"],
                "Last push": fmt_date(r["pushed_at"]) if r["pushed_at"] else "", "Servers sharing this repo": r["servers_sharing"],
                "Observed": fmt_date(r["metadata_observed_at"]) if r["metadata_observed_at"] else "",
            } for r in detail["repositories"]]), hide_index=True, width="stretch")
        else:
            st.caption("No repository declared.")
        st.markdown("**Declared packages**")
        if detail["packages"]:
            st.dataframe(pd.DataFrame([{
                "Ecosystem": p["registry_type"], "Package": p["identifier"], "Declared version": p["declared_version"] or "none",
                "Exact version": p["version_is_exact"], "Published": fmt_date(p["published_at"]) if p["published_at"] else "not observed",
                "Deprecated": p["is_deprecated"], "Yanked": p["is_yanked"], "Transport": p["transport_type"],
                "Env variables": ", ".join(p["environment_variables"]),
                "Dependency graph": f"{p['dependency_resolution']['status']}, {p['dependency_resolution']['node_count']} nodes ({fmt_date(p['dependency_resolution']['resolved_at'])})"
                if p["dependency_resolution"] else "none stored",
            } for p in detail["packages"]]), hide_index=True, width="stretch")
            st.caption("A declared version describes what the publisher registered. It does not prove which version a remote deployment runs.")
        else:
            st.caption("No package declared.")
        st.markdown("**Remote endpoints**")
        if detail["remotes"]:
            st.dataframe(pd.DataFrame([{
                "URL": r["url"], "Transport": r["transport_type"], "Templated": r["is_templated"], "Secret header declared": r["declares_secret_header"],
                "Last third-party observation": (f"{r['observations'][0]['availability_class'] or r['observations'][0]['check_result'] or 'recorded'} "
                                                 f"({r['observations'][0]['source']}, {fmt_date(r['observations'][0]['observed_at'])})") if r["observations"] else "none",
                "Observed tool count": r["observations"][0]["observed_tool_count"] if r["observations"] else None,
            } for r in detail["remotes"]]), hide_index=True, width="stretch")
            st.caption("Endpoint observations are historical results published by Agora. MCP Sentinel never contacts endpoints, so this is not live status.")
        else:
            st.caption("No remote endpoint declared.")
    with tabs[1]:
        concerns_section(server_id)
    with tabs[2]:
        coverage_section(server_id)
    with tabs[3]:
        if not detail["tools"]:
            st.info("No tool names or schemas are available for this server from the tested sources.")
        else:
            st.caption("Publisher-declared, curator-declared and third-party-observed tools are kept apart. Risk categories are third-party "
                       "classifier output, not verified vulnerabilities.")
            st.dataframe(pd.DataFrame([{
                "Source": t["source"], "Kind": t["declaration_kind"], "Match": t["match_confidence"], "Tool": t["tool_name"],
                "Description": (t["description"] or "").strip()[:160], "Input schema": t["input_schema_state"],
                "Third-party classification": ", ".join(f"{k}={v}" for k, v in (t["classification"] or {}).items() if v is not None),
                "Observed": fmt_date(t["observed_at"]),
            } for t in detail["tools"]]), hide_index=True, width="stretch")
            valid = [t for t in detail["tools"] if t["input_schema_state"] == "valid"]
            if valid:
                name = st.selectbox("Show a validated input schema", [t["tool_name"] for t in valid])
                st.json(next(t["input_schema"] for t in valid if t["tool_name"] == name), expanded=False)
    with tabs[4]:
        st.dataframe(pd.DataFrame([{"Source": s["source_name"], "Evidence type": ", ".join(s["evidence_types"]), "Records": s["observations"],
                                    "Latest observation": fmt_date(s["latest_observed_at"]), "Redistribution": s["redistribution"], "Attribution": s["attribution"]}
                                   for s in detail["evidence_sources"]]), hide_index=True, width="stretch")


def compare():
    st.title("Compare servers")
    left, right = st.columns(2)
    with left:
        first = server_picker("cmp_a", "First server")
    with right:
        second = server_picker("cmp_b", "Second server")
    if not (first and second):
        st.info("Choose two servers to compare.")
        return
    if first == second:
        st.warning("Choose two different servers.")
        return
    result = call("/api/compare", server_ids=f"{first},{second}")
    for note in result["notes"]:
        st.warning(note, icon=":material/info:")
    rows = {}
    for entry in result["servers"]:
        s, sec = entry["summary"], entry["security"]
        column = {
            "Registry name": s["registry_name"], "Title": s["title"], "Registry version / status": f"{s['version']} / {s['registry_status']}",
            "Deployment": DEPLOYMENT_LABELS.get(s["deployment_type"]),
            "Declared packages": "; ".join(f"{p['registry_type']}:{p['identifier']}@{p['declared_version'] or 'no version'}" for p in entry["packages"]) or "none",
            "Repository": "; ".join(f"{r['canonical_url']} (GitHub lookup: {r['lookup_status'] or 'not checked'}, shared by {r['servers_sharing']})"
                                    for r in entry["repositories"]) or "none declared",
            "Vulnerability assessment state": STATE_LABELS[sec["vulnerability_assessment_state"]],
            "Direct package vulnerabilities (distinct advisories)": fmt_count(sec["direct_advisories"]),
            "Modeled dependency exposures (distinct advisories)": fmt_count(sec["dependency_advisories"]),
            "Highest advisory severity": sec["highest_advisory_severity"] or "none recorded",
            "Max NVD CVSS v3.1": sec["max_nvd_cvss_v31"] if sec["max_nvd_cvss_v31"] is not None else "not available",
            "Tools observed / valid input schemas": f"{s['observed_tool_count']} / {s['valid_input_schema_count']}",
            "Tool metadata sources": ", ".join(entry["tool_sources"]) or "none",
        }
        for check_type, outcomes in entry["coverage"].items():
            column[f"Coverage: {check_type}"] = ", ".join(outcome_text(o) for o in outcomes)
        column["Registry snapshot"] = fmt_date(entry["snapshot_observed_at"])
        column["Latest evidence observation"] = fmt_date(entry["latest_evidence_at"])
        column["Latest assessment check"] = fmt_date(entry["latest_check_at"])
        rows[s["registry_name"]] = column
    st.dataframe(pd.DataFrame(rows), width="stretch", height=760)


PAGES = {
    "dashboard": st.Page(dashboard, title="Dashboard", icon=":material/dashboard:", default=True),
    "search": st.Page(search, title="Server search", icon=":material/search:", url_path="search"),
    "profile": st.Page(profile, title="Server profile", icon=":material/description:", url_path="profile"),
    "compare": st.Page(compare, title="Compare", icon=":material/compare_arrows:", url_path="compare"),
}
st.navigation(list(PAGES.values())).run()

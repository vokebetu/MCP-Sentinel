import html
import json
import os
import time

import pandas as pd
import requests
import streamlit as st

from sentinel_ui import (
    COLUMN_HELP, COLUMNS, DEFAULT_COLUMNS, DEPLOYMENT_LABELS, ECOSYSTEM_LABELS, EXTRA_COLUMNS, MISSING, MISSING_HELP, RIGHT_ALIGNED, STATE_LABELS,
    STATUS_LABELS, ApiError, advisory_count, error_message, http_error, page_range, safe_url, search_params, security_text, severity_text,
    table_rows, to_csv, tools_text,
)

BACKEND_URL = os.environ.get("BACKEND_URL", "http://localhost:8000").rstrip("/")
BAR_COLOR = "#1F4FC4"
OUTCOME_LABELS = {
    "finding_found": "Finding found", "no_known_finding": "No known finding", "evidence_found": "Evidence found", "not_found": "Not found at source",
    "missing_identifier": "Missing identifier", "not_applicable": "Not applicable", "unsupported": "Unsupported ecosystem",
    "access_restricted": "Access restricted", "error": "Error", "not_assessed": "Not assessed", "not_applicable_to_server": "Not applicable to server",
}
SEARCH_DEFAULTS = {"q": "", "status": "non_deleted", "ecosystem": "any", "deployment": "any", "repository": "any", "github": False,
                   "assessment": "any", "tool_info": "any", "tool_hints": "any", "sort": "name"}
FILTER_OPTIONS = {
    "status": ("Registry status", {"non_deleted": "Active and deprecated", "active": "Active only", "deprecated": "Deprecated only",
                                   "deleted": "Deleted", "all": "Any status"}),
    "deployment": ("Deployment", {"any": "Any", "remote_only": "Remote only", "packages_only": "Package only", "packages_and_remotes": "Both",
                                  "neither": "Neither"}),
    "repository": ("Source repository", {"any": "Any", "declared": "Declared", "not_declared": "Not declared"}),
    "assessment": ("Vulnerability evidence", {"any": "Any", "findings_recorded": "Findings recorded",
                                              "no_known_findings_in_completed_checks": "Checked — none found", "not_assessed": "Not assessed",
                                              "checks_could_not_complete": "Unknown — checks could not complete",
                                              "no_package_vulnerability_path": "Not applicable — no package"}),
    "tool_info": ("Tool information", {"any": "Any", "known": "Any tool metadata", "listed": "Tool names listed (catalogs)",
                                       "count_observed": "Tool count reported (handshake)", "observed_none": "No tools observed (handshake)",
                                       "not_observed": "Not observed / unknown"}),
    "tool_hints": ("Tool review notes", {"any": "Any", "yes": "Has review notes", "no": "No review notes"}),
    "sort": ("Sort by", {"name": "Name", "concerns": "Recorded advisories (most first)", "newest": "Newest", "relevance": "Relevance (keyword)"}),
}
QUICK = ["Has vulnerabilities", "Remote only", "Has GitHub repo", "Has tools"]
CHECK_LABELS = {"repository_metadata": "Repository information", "package_metadata": "Package information",
                "dependency_resolution": "Dependency information", "direct_package_advisories": "Advisories for declared packages",
                "dependency_advisories": "Advisories in dependencies", "endpoint_status": "Endpoint status", "tool_metadata": "Tool information"}
SOURCE_LABELS = {"github": "GitHub", "npm": "npm", "pypi": "PyPI", "deps_dev": "deps.dev", "osv": "OSV.dev", "ghsa": "GitHub Advisory Database",
                 "agora": "Agora", "policylayer": "PolicyLayer", "toolhive": "ToolHive", "docker": "Docker catalog", "glama": "Glama",
                 "mcpshield": "MCPShield", "pypi_integrity": "PyPI attestations"}
PLAIN_OUTCOMES = {"finding_found": "advisories found", "no_known_finding": "checked, none found", "evidence_found": "found",
                  "not_found": "not found at the source", "missing_identifier": "the needed identifier is missing", "not_applicable": "not applicable",
                  "unsupported": "package type not supported", "access_restricted": "access restricted", "error": "lookup failed",
                  "not_assessed": "not assessed", "not_applicable_to_server": "not applicable"}
SEVERITY_CLASS = {"CRITICAL": "sev-critical", "HIGH": "sev-high", "MODERATE": "sev-moderate", "LOW": "sev-low"}
THEME_CSS = """
<style>
:root {--ms-canvas:#F6F7F9; --ms-surface:#FFFFFF; --ms-border:#E1E4EA; --ms-text:#1A1D24; --ms-muted:#5B6170; --ms-side:#EEF0F4;
       --ms-accent:#1F4FC4; --ms-accent-light:#EAF0FD;}
[data-testid="stSidebar"] {min-width: 230px !important; max-width: 230px !important;}
.ms-sub {color: var(--ms-muted); font-size: 0.9rem; margin-top: -0.6rem;}
.ms-chip {display:inline-block; padding:0.08rem 0.55rem; border-radius:999px; font-size:0.78rem; border:1px solid var(--ms-border);
          background:#F1F3F7; color:var(--ms-text); margin:0 0.25rem 0.15rem 0; white-space:nowrap;}
.ms-chip.status-active {background:#E7F6EC; border-color:#B7E1C3; color:#0F5A2A;}
.ms-chip.status-deprecated {background:#FFF4E0; border-color:#F2D29B; color:#7A4A00;}
.ms-chip.status-deleted {background:#EEF0F4; color:#5B6170;}
.ms-chip.deploy {background:var(--ms-accent-light); border-color:#C9D6F7; color:#16357F;}
.ms-chip.sev-critical {background:#FDE8E8; border-color:#F3B4B4; color:#8A1C1C;}
.ms-chip.sev-high {background:#FFF0E3; border-color:#F6C79E; color:#8A3F00;}
.ms-chip.sev-moderate {background:#FFF9DB; border-color:#EDDB8C; color:#6B5300;}
.ms-chip.sev-low {background:#EEF0F4; color:#3D4351;}
.ms-strip {background:#EEF3FC; border:1px solid #D5E0F7; color:#1A2B55; border-radius:10px; padding:0.45rem 0.8rem; font-size:0.86rem; margin:0.3rem 0 0.6rem;}
.st-key-selection_bar {position: sticky; bottom: 0.8rem; z-index: 60; background:#1A1D24; border-radius: 12px; padding: 0.3rem 0.8rem;
                       width: fit-content !important; margin: 0.6rem auto 0; box-shadow: 0 6px 18px rgba(16,24,40,0.25);}
.st-key-selection_bar p {color:#FFFFFF; margin:0;}
.st-key-results_card, .st-key-filter_panel {background: var(--ms-surface); border:1px solid var(--ms-border); border-radius: 12px; padding: 0.7rem 0.9rem;}
.st-key-search_box input {height: 52px; font-size: 16px;}
.stMainBlockContainer {padding-top: 2.2rem;}
.ms-title {font-size: 1.35rem; font-weight: 700; margin: 0 0 0.6rem 0; color: var(--ms-text);}
.st-key-results_card [data-testid="stDataFrame"], .st-key-results_card [data-testid="stDataEditor"] {background: var(--ms-surface);}
</style>
"""

st.set_page_config(page_title="MCP Sentinel", page_icon=":material/shield:", layout="wide")


def init_state():
    s = st.session_state
    s.setdefault("filters", dict(SEARCH_DEFAULTS))
    s.setdefault("search_page", 1)
    s.setdefault("page_size", 25)
    s.setdefault("columns", list(DEFAULT_COLUMNS))
    s.setdefault("filters_open", False)
    s.setdefault("selected", {})
    s.setdefault("compare_ids", [])
    s.setdefault("compare_names", {})
    s.setdefault("grid_version", 0)
    s.setdefault("profile_id", None)
    s.setdefault("diff_only", False)
    s.setdefault("ai", {"messages": [], "strategy": "few_shot", "top_k": 5, "scope": [], "pending": None})


@st.cache_data(ttl=60, show_spinner=False)
def fetch(path, pairs=()):
    response = None
    for attempt in range(3):
        try:
            response = requests.get(f"{BACKEND_URL}{path}", params=list(pairs), timeout=(5, 45))
        except requests.Timeout:
            raise ApiError("timeout", "The MCP Sentinel API did not answer within 45 seconds.") from None
        except requests.RequestException as error:
            raise ApiError("transport", f"The MCP Sentinel API is not reachable ({type(error).__name__}). Check that the backend service is "
                                        "running.") from None
        if response.status_code == 503 and attempt < 2:
            time.sleep(0.4 * (attempt + 1))
            continue
        break
    if response.status_code == 404:
        return None
    if not response.ok:
        try:
            body = response.json()
        except ValueError:
            body = {}
        raise http_error(response.status_code, body, response.headers.get("X-Request-ID"))
    return response.json()


def pairs_of(params):
    pairs = []
    for key, value in sorted(params.items()):
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            pairs += [(key, v) for v in value]
        else:
            pairs.append((key, value))
    return tuple(pairs)


def query(path, **params):
    return fetch(path, pairs_of(params))


def call(path, **params):
    try:
        return query(path, **params)
    except ApiError as error:
        st.error(error_message(error))
        st.stop()


def fmt_date(value):
    return value[:10] if value else "not recorded"


def fmt_count(value):
    return "unknown" if value is None else f"{value:,}"


def esc(value):
    return html.escape(str(value), quote=True)


def chip(text, cls=""):
    return f'<span class="ms-chip {cls}">{esc(text)}</span>'


def bar(data, label, value_label):
    frame = pd.DataFrame({label: list(data.keys()), value_label: list(data.values())})
    st.bar_chart(frame, x=label, y=value_label, horizontal=True, color=BAR_COLOR, sort=f"-{value_label}", height=70 + 38 * len(frame),
                 alt=f"{value_label} by {label.lower()}: " + "; ".join(f"{k} {v:,}" for k, v in data.items()))
    with st.expander("Table view"):
        st.dataframe(frame, hide_index=True, width="stretch")


def server_picker(key, label, placeholder="Search by name or description"):
    text = st.text_input(label, key=f"{key}_q", placeholder=placeholder)
    if not text:
        return None
    page = call("/api/servers", q=text, status="all", page_size=20, sort="relevance")
    options = {f"{item['registry_name']} ({item['version']}, {item['registry_status']})": (item["server_id"], item["registry_name"])
               for item in page["items"]}
    if not options:
        st.caption("No matching servers.")
        return None
    choice = st.selectbox("Matching servers", list(options), key=f"{key}_choice")
    return options[choice]


def outcome_text(value):
    source, _, outcome = value.rpartition(": ")
    return f"{source}: {OUTCOME_LABELS.get(outcome, outcome)}" if source else OUTCOME_LABELS.get(outcome, outcome)


def open_profile(server_id):
    st.session_state["profile_id"] = server_id
    st.switch_page(PAGES["profile"], query_params={"server_id": str(server_id)})


def open_compare(ids):
    st.session_state["compare_ids"] = list(dict.fromkeys(ids))
    st.switch_page(PAGES["compare"])


def ask_ai(servers):
    st.session_state["ai"]["scope"] = [{"server_id": sid, "registry_name": name} for sid, name in servers][:4]
    st.switch_page(PAGES["ai"])


def ai_ready():
    try:
        status = query("/api/ai/status")
    except ApiError:
        return False
    return bool(status.get("configured") and status.get("chunks"))


AI_OFF = "The AI assistant needs an OpenAI key (OPENAI_API_KEY) and an AI index."


def snapshot_line():
    try:
        stats = query("/api/stats")
    except ApiError:
        return None, None
    return stats, fmt_date(stats["snapshot_collected_at"])


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
    st.warning(f"Package vulnerability lookups cover every declared npm, PyPI, NuGet and Cargo package. "
               f"{stats['assessment_states'].get('no_package_vulnerability_path', 0):,} remote-only servers have no package to check, and Docker "
               "images and MCPB files have no vulnerability database lookup. No recorded finding is not proof of safety.", icon=":material/info:")
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


def set_filter(field, value):
    st.session_state["filters"][field] = value
    st.session_state["search_page"] = 1


def on_widget(field):
    set_filter(field, st.session_state[f"f_{field}"])


def on_keyword():
    set_filter("q", st.session_state["f_q"] or "")


def on_pills():
    chosen = set(st.session_state["f_pills"] or [])
    f = st.session_state["filters"]
    f["assessment"] = "findings_recorded" if "Has vulnerabilities" in chosen else ("any" if f["assessment"] == "findings_recorded" else f["assessment"])
    f["deployment"] = "remote_only" if "Remote only" in chosen else ("any" if f["deployment"] == "remote_only" else f["deployment"])
    f["github"] = "Has GitHub repo" in chosen
    f["tool_info"] = "known" if "Has tools" in chosen else ("any" if f["tool_info"] == "known" else f["tool_info"])
    st.session_state["search_page"] = 1


def reset_filter(field):
    set_filter(field, SEARCH_DEFAULTS[field])


def reset_all():
    st.session_state["filters"] = dict(SEARCH_DEFAULTS)
    st.session_state["search_page"] = 1


def on_page_size():
    st.session_state["page_size"] = st.session_state["f_page_size"]
    st.session_state["search_page"] = 1


def on_columns():
    chosen = st.session_state["f_columns"] or []
    st.session_state["columns"] = DEFAULT_COLUMNS + [c for c in EXTRA_COLUMNS if c in chosen]


def on_grid(key, ids, names):
    edits = (st.session_state.get(key) or {}).get("edited_rows", {})
    for row, change in edits.items():
        if "Select" in change:
            sid = ids[int(row)]
            if change["Select"]:
                st.session_state["selected"][sid] = names[sid]
            else:
                st.session_state["selected"].pop(sid, None)
    st.session_state["grid_version"] += 1


def on_select_page(ids, names):
    if st.session_state["f_select_page"]:
        for sid in ids:
            st.session_state["selected"][sid] = names[sid]
    else:
        for sid in ids:
            st.session_state["selected"].pop(sid, None)
    st.session_state["grid_version"] += 1


def clear_selection():
    st.session_state["selected"] = {}
    st.session_state["grid_version"] += 1


def go_page(page):
    st.session_state["search_page"] = max(1, page)


def shift_page(delta, pages):
    st.session_state["search_page"] = min(pages, max(1, st.session_state["search_page"] + delta))


def on_jump():
    go_page(int(st.session_state["f_jump"]))


def active_chips():
    f = st.session_state["filters"]
    chips = []
    if f["q"].strip():
        chips.append(("q", f"Keyword: {f['q'].strip()}"))
    for field in ("status", "ecosystem", "deployment", "repository", "assessment", "tool_info", "tool_hints"):
        if f[field] != SEARCH_DEFAULTS[field]:
            label, options = FILTER_OPTIONS.get(field, ("Package ecosystem", {}))
            value = options.get(f[field]) or ECOSYSTEM_LABELS.get(f[field], f[field])
            chips.append((field, f"{label}: {value}"))
    if f["github"]:
        chips.append(("github", "GitHub repository"))
    return chips


def filter_panel(ecosystems):
    f = st.session_state["filters"]
    with st.container(key="filter_panel"):
        st.markdown("**More filters**")
        for field in ("status", "ecosystem", "deployment", "repository", "assessment", "tool_info", "tool_hints", "sort"):
            if field == "ecosystem":
                label, options = "Package ecosystem", {"any": "Any", **{e: ECOSYSTEM_LABELS.get(e, e) for e in ecosystems}}
            else:
                label, options = FILTER_OPTIONS[field]
            if f[field] not in options:
                options = {**options, f[field]: f[field]}
            st.session_state[f"f_{field}"] = f[field]
            st.selectbox(label, list(options), key=f"f_{field}", format_func=options.get, on_change=on_widget, args=(field,),
                         help={"assessment": COLUMN_HELP["security"], "deployment": COLUMN_HELP["deployment"],
                               "ecosystem": COLUMN_HELP["ecosystems"], "tool_info": COLUMN_HELP["tools"],
                               "tool_hints": COLUMN_HELP["hints"]}.get(field))
        st.session_state["f_page_size"] = st.session_state["page_size"]
        st.selectbox("Rows per page", [25, 50, 100], key="f_page_size", on_change=on_page_size)


def results_table(items, total, page, pages):
    columns = st.session_state["columns"]
    selected = st.session_state["selected"]
    ids = [item["server_id"] for item in items]
    names = {item["server_id"]: item["registry_name"] for item in items}
    rows = table_rows(items, columns)
    frame = []
    for item, row in zip(items, rows):
        record = {"Select": item["server_id"] in selected}
        for column in columns:
            label = COLUMNS[column]
            if column == "server":
                record[label] = f"profile?server_id={item['server_id']}#{item['registry_name']}"
            elif column == "repo":
                record[label] = safe_url(item.get("repository_url")) or ""
            else:
                record[label] = row[label]
        frame.append(record)
    config = {"Select": st.column_config.CheckboxColumn("Select", help="Select across pages for Compare or the AI assistant.", width="small",
                                                        pinned=True)}
    for column in columns:
        label = COLUMNS[column]
        if column == "server":
            config[label] = st.column_config.LinkColumn(label, display_text=r"#(.+)$", help=COLUMN_HELP["server"], pinned=True, width="medium")
        elif column == "repo":
            config[label] = st.column_config.LinkColumn(label, display_text=r"https?://(?:www\.)?[^/]+/(.+?)/?$", help=COLUMN_HELP["repo"])
        else:
            config[label] = st.column_config.TextColumn(label, help=COLUMN_HELP.get(column), alignment="right" if column in RIGHT_ALIGNED else None)
    key = f"grid_{st.session_state['grid_version']}"
    on_page = [sid for sid in ids if sid in selected]
    st.session_state["f_select_page"] = bool(ids) and len(on_page) == len(ids)
    st.checkbox(f"Select all on this page ({len(ids)})", key="f_select_page", on_change=on_select_page, args=(ids, names),
                help="Selects or clears only the rows on this page. Selections on other pages stay.")
    st.data_editor(pd.DataFrame(frame), key=key, hide_index=True, width="stretch", height=min(38 + 35 * len(frame), 640),
                   column_config=config, disabled=[c for c in frame[0] if c != "Select"], on_change=on_grid, args=(key, ids, names))
    first, last = page_range(total, page, st.session_state["page_size"])
    nav = st.columns([1, 1, 2, 1.2, 1], vertical_alignment="center")
    nav[0].button("◀ Previous", on_click=shift_page, args=(-1, pages), disabled=page <= 1, width="stretch")
    nav[1].button("Next ▶", on_click=shift_page, args=(1, pages), disabled=page >= pages, width="stretch")
    nav[2].caption(f"Showing {first:,}–{last:,} of {total:,} · page {page:,} of {pages:,}")
    st.session_state["f_jump"] = page
    nav[3].number_input("Go to page", min_value=1, max_value=pages, step=1, key="f_jump", on_change=on_jump, label_visibility="collapsed")
    return rows


def export_all(params, columns):
    pairs = [(k, v) for k, v in pairs_of({k: v for k, v in params.items() if k not in ("page", "page_size")})]
    response = requests.get(f"{BACKEND_URL}/api/servers/export", params=pairs, timeout=(5, 300), stream=True)
    response.raise_for_status()
    items = [json.loads(line) for line in response.iter_lines() if line]
    return to_csv(table_rows(items, columns))


def selection_bar():
    selected = st.session_state["selected"]
    if not selected:
        return
    with st.container(key="selection_bar", horizontal=True, vertical_alignment="center", gap="small"):
        st.markdown(f"**{len(selected)} selected**")
        st.button("Clear", key="sel_clear", on_click=clear_selection, type="tertiary")
        if len(selected) == 1:
            if st.button("Open profile", key="sel_profile", type="tertiary"):
                open_profile(next(iter(selected)))
        ready = ai_ready()
        if st.button("Ask AI", key="sel_ai", type="tertiary", disabled=len(selected) > 4 or not ready,
                     help=AI_OFF if not ready else ("Ask the AI assistant about up to 4 selected servers." if len(selected) <= 4
                                                    else "Select at most 4 servers to ask the AI.")):
            ask_ai(list(selected.items()))
        if st.button("Compare selected", key="sel_compare", type="primary", disabled=len(selected) < 2,
                     help="Compare shows up to 4 servers at a time; with more selected you choose which 4."):
            open_compare(list(selected))


def search():
    stats, snapshot = snapshot_line()
    st.markdown('<p class="ms-title">Server search</p>', unsafe_allow_html=True)
    if stats:
        st.markdown(f'<p class="ms-sub">{stats["totals"]["non_deleted"]:,} servers · Registry data as of {esc(snapshot)}</p>', unsafe_allow_html=True)
    f = st.session_state["filters"]
    with st.container(key="search_box"):
        st.session_state["f_q"] = f["q"]
        st.text_input("Search", key="f_q", placeholder="Search by server name, title or description", on_change=on_keyword,
                      label_visibility="collapsed", icon=":material/search:", help="Press Enter to search.")
    toolbar = st.columns([5, 1.1, 1.1], vertical_alignment="center")
    with toolbar[0]:
        st.session_state["f_pills"] = [name for name, on in zip(QUICK, (f["assessment"] == "findings_recorded", f["deployment"] == "remote_only",
                                                                         f["github"], f["tool_info"] == "known")) if on]
        st.pills("Quick filters", QUICK, selection_mode="multi", key="f_pills", on_change=on_pills, label_visibility="collapsed",
                 help="Has vulnerabilities = recorded advisory findings, not a live risk verdict. Has tools = tool metadata in stored evidence.")
    with toolbar[1]:
        if st.button("More filters" if not st.session_state["filters_open"] else "Hide filters", icon=":material/tune:", width="stretch"):
            st.session_state["filters_open"] = not st.session_state["filters_open"]
            st.rerun()
    with toolbar[2]:
        with st.popover("Columns", icon=":material/view_column:", width="stretch"):
            st.session_state["f_columns"] = [c for c in st.session_state["columns"] if c in EXTRA_COLUMNS]
            st.multiselect("Extra columns", EXTRA_COLUMNS, key="f_columns", format_func=lambda c: COLUMNS[c].replace(" ⓘ", ""),
                           on_change=on_columns)
            st.caption("Always shown: " + ", ".join(COLUMNS[c].replace(" ⓘ", "") for c in DEFAULT_COLUMNS))
    chips = active_chips()
    if chips:
        with st.container(horizontal=True, gap="small"):
            for field, label in chips:
                st.button(f"{label} ✕", key=f"chip_{field}", on_click=reset_filter, args=(field,), type="secondary", help="Remove this filter")
            st.button("Clear all", key="chip_all", on_click=reset_all, type="tertiary")
    ecosystems = list((stats or {}).get("ecosystems", {}).keys())
    if st.session_state["filters_open"]:
        panel, main = st.columns([1, 3.3])
        with panel:
            filter_panel(ecosystems)
    else:
        main = st.container()
    with main:
        page_size = st.session_state["page_size"]
        params = search_params(f, st.session_state["search_page"], page_size)
        try:
            with st.spinner("Loading servers…"):
                result = query("/api/servers", **params)
        except ApiError as error:
            st.error(error_message(error), icon=":material/error:")
            st.button("Retry", on_click=fetch.clear)
            selection_bar()
            return
        total = result["total"]
        pages = max(1, -(-total // page_size))
        if st.session_state["search_page"] > pages:
            st.session_state["search_page"] = pages
            st.rerun()
        page = st.session_state["search_page"]
        with st.container(key="results_card"):
            first, last = page_range(total, page, page_size)
            head = st.columns([3, 2], vertical_alignment="center")
            head[0].markdown(f"**{total:,} {'server' if total == 1 else 'servers'}** · showing {first:,}–{last:,}")
            if not result["items"]:
                st.info("No servers match these filters. Remove a filter chip or use Clear all.", icon=":material/search_off:")
                selection_bar()
                return
            if f["sort"] == "concerns":
                st.caption("Sorted by recorded distinct advisories. Servers without a completed check come after checked servers; they are not "
                           "ranked as safe.")
            rows = results_table(result["items"], total, page, pages)
            ex = st.columns(2)
            ex[0].download_button("Export visible page (CSV)", to_csv(rows), file_name=f"mcp-sentinel-page-{page}.csv", mime="text/csv",
                                  on_click="ignore", icon=":material/download:", width="stretch",
                                  help="The rows and columns on screen, in the same order.")
            ex[1].download_button(f"Export all {total:,} filtered results (CSV)", lambda: export_all(params, st.session_state["columns"]),
                                  file_name="mcp-sentinel-filtered.csv", mime="text/csv", on_click="ignore", icon=":material/download:",
                                  width="stretch", help="Every server that matches the filters, same columns and order.")
            st.caption("Blank Repo = no repository declared. Missing values: " + "; ".join(f"{k} = {v}" for k, v in MISSING_HELP.items()))
    selection_bar()


def concerns_section(server_id):
    security = call(f"/api/servers/{server_id}/security")
    s = security["summary"]
    st.markdown(f"**Indicator A: observed security concerns.** Assessment state: *{STATE_LABELS[s['vulnerability_assessment_state']]}*")
    cols = st.columns(6)
    cols[0].metric("Distinct advisories", advisory_count(s, "distinct_advisories"), help=COLUMN_HELP["distinct"])
    cols[1].metric("Direct package", advisory_count(s, "direct_advisories"), help=COLUMN_HELP["direct"])
    cols[2].metric("Modeled dependency", advisory_count(s, "dependency_advisories"), help=COLUMN_HELP["dependency"])
    cols[3].metric("Highest advisory severity", severity_text(s), help=COLUMN_HELP["severity"])
    cols[4].metric("Max NVD CVSS v3.1", s["max_nvd_cvss_v31"] if s["max_nvd_cvss_v31"] is not None else "not available", help=COLUMN_HELP["cvss"])
    cols[5].metric("Max EPSS (CVE-level)", f"{s['max_epss_score']:.3f}" if s["max_epss_score"] is not None else "not available")
    if s["kev_listed_cves"] is not None:
        st.caption(f"CISA KEV: {s['kev_listed_cves']} of {s['cve_count']} CVEs listed in the stored catalog snapshot.")
    if not security["findings"]:
        if s["vulnerability_assessment_state"] == "not_assessed":
            st.info("No vulnerability lookup has been recorded for this server version. Its findings are unknown, not zero.")
        elif s["vulnerability_assessment_state"] == "no_package_vulnerability_path":
            st.info("This server declares no package that a vulnerability database covers, and its endpoints were never scanned. "
                    "Its findings are unknown, not zero.")
        elif s["vulnerability_assessment_state"] == "checks_could_not_complete":
            st.info("Vulnerability checks could not complete for this server version. Its findings are unknown, not zero.")
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


REVIEW_STATUS = {"present": "Evidence present", "missing": "Missing", "not_assessed": "Not assessed", "not_applicable": "Not applicable"}


def evidence_markdown(review):
    lines = [f"# Evidence pack: {review['registry_name']} {review['version']}", "", "Generated by MCP Sentinel from stored historical evidence.", "",
             "| Item | Status | Needs attention | Detail | Source | Date |", "|---|---|---|---|---|---|"]
    for i in review["items"]:
        lines.append(f"| {i['label']} | {REVIEW_STATUS[i['status']]} | {'yes' if i['attention'] else ''} | {i['detail'].replace('|', '/')} | "
                     f"{i['source'] or ''} | {fmt_date(i['observed_at']) if i['observed_at'] else ''} |")
    if review["tool_flags"]:
        lines += ["", "## Tool review hints", "", "| Tool | Hint | Matched text |", "|---|---|---|"]
        lines += [f"| {f['tool_name']} | {f['explanation']} | {(f['matched_text'] or '').replace('|', '/')} |" for f in review["tool_flags"]]
    return "\n".join(lines + ["", "## Notes", ""] + [f"- {n}" for n in review["notes"]]) + "\n"


def review_section(server_id):
    review = call(f"/api/servers/{server_id}/review")
    attention = [i for i in review["items"] if i["attention"]]
    st.caption("The evidence a bank's third-party risk review asks for, and whether MCP Sentinel holds it. Evidence present is not a safety verdict.")
    st.markdown(f"**{len(attention)} of {len(review['items'])} items need attention**")
    st.table(pd.DataFrame([{"Item": i["label"], "Status": REVIEW_STATUS[i["status"]], "Needs attention": "yes" if i["attention"] else "",
                            "Detail": i["detail"], "Source": i["source"] or "", "Date": fmt_date(i["observed_at"]) if i["observed_at"] else ""}
                           for i in review["items"]]).set_index("Item"))
    if review["tool_flags"]:
        st.markdown("**Tool review hints**")
        st.dataframe(pd.DataFrame([{"Tool": f["tool_name"], "Hint": f["explanation"], "Matched text": f["matched_text"]} for f in review["tool_flags"]]),
                     hide_index=True, width="stretch")
    slug = review["registry_name"].replace("/", "_")
    cols = st.columns(3)
    cols[0].download_button("Download evidence (JSON)", json.dumps(review, indent=2), file_name=f"{slug}-evidence.json", mime="application/json")
    cols[1].download_button("Download evidence (Markdown)", evidence_markdown(review), file_name=f"{slug}-evidence.md", mime="text/markdown")
    if review["sbom_available"]:
        cols[2].download_button("Download SBOM (CycloneDX JSON)", json.dumps(call(f"/api/servers/{server_id}/sbom"), indent=2),
                                file_name=f"{slug}-sbom.cdx.json", mime="application/json")
    for note in review["notes"]:
        st.caption(note)


def tool_summary(detail):
    state, count = detail["tool_metadata_state"], detail["tool_count"]
    when = fmt_date(detail["tool_observed_at"]) if detail["tool_observed_at"] else None
    if state == "listed":
        return f"{count} tool names listed in tool catalogs (observed {when})."
    if state == "count_observed":
        return f"No tool names are stored. An endpoint handshake published by Agora reported {count} tools (observed {when})."
    if state == "observed_none":
        return f"No tool names are stored. An endpoint handshake published by Agora answered without listing tools (observed {when})."
    return "Not observed: no tool metadata in the checked sources. This does not mean the server has no tools."


def profile():
    st.title("Server profile")
    picked = server_picker("profile", "Find a server")
    from_url = st.query_params.get("server_id")
    if picked:
        st.session_state["profile_id"] = picked[0]
    elif from_url and from_url.isdigit():
        st.session_state["profile_id"] = int(from_url)
    server_id = st.session_state["profile_id"]
    if not server_id:
        st.info("Search for a server above, or open one from the Server search page.")
        return
    st.query_params["server_id"] = str(server_id)
    detail = call(f"/api/servers/{server_id}")
    if detail is None:
        st.error("Server not found. It may have been removed from this database.")
        st.session_state["profile_id"] = None
        return
    st.header(detail["registry_name"])
    st.caption(f"{detail['title'] or 'No title declared'} · registry version {detail['version']} · status **{detail['registry_status']}** · "
               f"published {fmt_date(detail['published_at'])} · snapshot {fmt_date(detail['snapshot_observed_at'])}")
    st.write(detail["description"] or "No description declared.")
    actions = st.columns([2, 1.6, 1.6, 2], vertical_alignment="center")
    ready = ai_ready()
    if actions[0].button("Ask AI about this server", icon=":material/chat:", type="primary", disabled=not ready, help=None if ready else AI_OFF):
        ask_ai([(server_id, detail["registry_name"])])
    in_selection = server_id in st.session_state["selected"]
    if actions[1].button("Remove from selection" if in_selection else "Add to selection", icon=":material/checklist:"):
        if in_selection:
            st.session_state["selected"].pop(server_id, None)
        else:
            st.session_state["selected"][server_id] = detail["registry_name"]
        st.session_state["grid_version"] += 1
        st.rerun()
    repos = [r for r in detail["repositories"] if safe_url(r["canonical_url"])]
    if repos:
        actions[2].link_button("View repository", safe_url(repos[0]["canonical_url"]), icon=":material/open_in_new:")
    else:
        actions[2].caption("Repository: Not declared")
    if detail["missing_information"]:
        with st.container(border=True):
            st.markdown("**Missing or incomplete information**")
            for item in detail["missing_information"]:
                st.markdown(f"- {item}")
    tabs = st.tabs(["Review checklist", "Software and endpoints", "Observed concerns", "Assessment coverage", "Tools", "Evidence sources"])
    with tabs[0]:
        review_section(server_id)
    with tabs[1]:
        st.markdown(f"**Deployment:** {DEPLOYMENT_LABELS.get(detail['deployment_type'])}" + (f" · website {detail['website_url']}" if detail["website_url"] else ""),
                    help=COLUMN_HELP["deployment"])
        st.markdown("**Repositories**")
        if detail["repositories"]:
            st.dataframe(pd.DataFrame([{
                "Repository": safe_url(r["canonical_url"]), "Subfolder": r["subfolder"], "GitHub lookup": r["lookup_status"] or "not checked",
                "GitHub id": r["github_id"], "Archived": r["is_archived"], "Fork": r["is_fork"], "Stars": r["stars"], "Licence": r["license"],
                "Last push": fmt_date(r["pushed_at"]) if r["pushed_at"] else "", "Servers sharing this repo": r["servers_sharing"],
                "Observed": fmt_date(r["metadata_observed_at"]) if r["metadata_observed_at"] else "",
            } for r in detail["repositories"]]), hide_index=True, width="stretch",
                column_config={"Repository": st.column_config.LinkColumn("Repository", display_text=r"https?://(?:www\.)?[^/]+/(.+?)/?$")})
        else:
            st.caption("Repository: Not declared.")
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
    with tabs[2]:
        concerns_section(server_id)
    with tabs[3]:
        coverage_section(server_id)
    with tabs[4]:
        st.markdown(f"**Tool metadata:** {tool_summary(detail)}", help=COLUMN_HELP["tools"])
        if detail["tools"]:
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
    with tabs[5]:
        st.dataframe(pd.DataFrame([{"Source": s["source_name"], "Evidence type": ", ".join(s["evidence_types"]), "Records": s["observations"],
                                    "Latest observation": fmt_date(s["latest_observed_at"]), "Redistribution": s["redistribution"], "Attribution": s["attribution"]}
                                   for s in detail["evidence_sources"]]), hide_index=True, width="stretch")


def coverage_plain(check_type, outcomes):
    parsed = []
    for value in outcomes:
        source, _, outcome = value.rpartition(": ")
        parsed.append((SOURCE_LABELS.get(source, source), outcome))
    raw = "; ".join(f"{s}: {PLAIN_OUTCOMES.get(o, o)}" if s else PLAIN_OUTCOMES.get(o, o) for s, o in parsed)
    kinds = {o for _, o in parsed}
    label = CHECK_LABELS[check_type].lower()
    if kinds & {"finding_found"}:
        return f"Checked: advisories found ({', '.join(sorted({s for s, o in parsed if o == 'finding_found'}))})", raw
    if kinds & {"no_known_finding"}:
        return f"{MISSING['none_found']} ({', '.join(sorted({s for s, o in parsed if o == 'no_known_finding'}))})", raw
    if kinds & {"evidence_found"}:
        return f"Found ({', '.join(sorted({s for s, o in parsed if o == 'evidence_found'}))})", raw
    if kinds <= {"not_applicable", "not_applicable_to_server"}:
        return MISSING["not_applicable"], raw
    if kinds == {"not_assessed"}:
        return MISSING["not_assessed"], raw
    if kinds & {"error"}:
        return f"{MISSING['lookup_failed']}: {label} not available", raw
    return f"{label.capitalize()} not available from checked sources", raw


def compare_rows(entries):
    def cell(text, cls="", tip="", link=None):
        return {"text": text, "cls": cls, "tip": tip, "link": link}

    sections = {"Overview": [], "Security": [], "Tools": [], "Data sources": [], "How we got this data": []}

    def add(section, label, tip, cells):
        sections[section].append({"label": label, "tip": tip, "cells": cells})

    add("Overview", "Title", "", [cell(e["summary"]["title"] or "Not declared") for e in entries])
    add("Overview", "Version", COLUMN_HELP["version"], [cell(e["summary"]["version"]) for e in entries])
    add("Overview", "Registry status", COLUMN_HELP["status"],
        [cell(STATUS_LABELS.get(e["summary"]["registry_status"], e["summary"]["registry_status"]), f"status-{e['summary']['registry_status']}")
         for e in entries])
    add("Overview", "Deployment", COLUMN_HELP["deployment"], [cell(DEPLOYMENT_LABELS[e["summary"]["deployment_type"]], "deploy") for e in entries])
    add("Overview", "Declared packages", "Packages declared in the registry record.",
        [cell("; ".join(f"{p['registry_type']}:{p['identifier']}@{p['declared_version'] or 'no version'}" for p in e["packages"]) or MISSING["not_declared"])
         for e in entries])
    add("Overview", "Repository", COLUMN_HELP["repo"],
        [cell(safe_url(e["summary"]["repository_url"]) or MISSING["not_declared"], link=safe_url(e["summary"]["repository_url"])) for e in entries])
    add("Security", "Vulnerability evidence", COLUMN_HELP["security"], [cell(security_text(e["security"])) for e in entries])
    add("Security", "Distinct advisories", COLUMN_HELP["distinct"], [cell(advisory_count(e["security"], "distinct_advisories")) for e in entries])
    add("Security", "Direct package advisories", COLUMN_HELP["direct"], [cell(advisory_count(e["security"], "direct_advisories")) for e in entries])
    add("Security", "Vulnerabilities in dependencies", "Matched advisories in modeled dependency versions; not evidence of actual installation.",
        [cell(advisory_count(e["security"], "dependency_advisories")) for e in entries])
    add("Security", "Highest recorded severity", COLUMN_HELP["severity"],
        [cell(severity_text(e["security"]), SEVERITY_CLASS.get(e["security"]["highest_advisory_severity"] or "", "")) for e in entries])
    add("Security", "Max CVSS v3.1", COLUMN_HELP["cvss"],
        [cell(str(e["security"]["max_nvd_cvss_v31"]) if e["security"]["max_nvd_cvss_v31"] is not None else
              (MISSING["not_applicable"] if e["security"]["vulnerability_assessment_state"] == "no_package_vulnerability_path" else "Not published"))
         for e in entries])
    add("Tools", "Tools", COLUMN_HELP["tools"], [cell(tools_text(e["summary"]), tip=f"Source: {e['summary']['tool_count_source'] or 'none'}; observed "
                                                     f"{fmt_date(e['summary']['tool_observed_at']) if e['summary']['tool_observed_at'] else 'never'}")
                                               for e in entries])
    add("Tools", "Verified input schemas", COLUMN_HELP["schemas"],
        [cell(str(e["summary"]["valid_input_schema_count"]) if e["summary"]["tool_metadata_state"] == "listed" else MISSING["not_observed"])
         for e in entries])
    add("Tools", "Tool list sources", "Catalogs that listed tool names for this server.", [cell(", ".join(e["tool_sources"]) or MISSING["not_observed"])
                                                                                            for e in entries])
    add("Tools", "Tool review notes", COLUMN_HELP["hints"],
        [cell(str(e["summary"]["tool_review_hints"]) if e["summary"]["tool_metadata_state"] == "listed" else MISSING["not_observed"]) for e in entries])
    add("Data sources", "Latest evidence observation", "Newest stored observation for this server version.",
        [cell(fmt_date(e["latest_evidence_at"])) for e in entries])
    add("Data sources", "Latest assessment check", "Newest recorded coverage check for this server version.",
        [cell(fmt_date(e["latest_check_at"])) for e in entries])
    for check_type in CHECK_LABELS:
        cells = []
        for e in entries:
            text, raw = coverage_plain(check_type, e["coverage"].get(check_type, ["not_assessed"]))
            cells.append(cell(text, tip=raw))
        add("How we got this data", CHECK_LABELS[check_type], f"Raw check type: {check_type}", cells)
    return sections


def compare_table(entries, sections, title, diff_only):
    head = "".join(f'<th scope="col"><a href="profile?server_id={e["summary"]["server_id"]}" target="_blank" rel="noopener noreferrer">'
                   f'{esc(e["summary"]["registry_name"])}</a></th>' for e in entries)
    body = []
    for section, rows in sections.items():
        if section == "How we got this data" and title != section:
            continue
        if section != "How we got this data" and title == "How we got this data":
            continue
        shown = []
        for row in rows:
            texts = [c["text"] for c in row["cells"]]
            differs = len(set(texts)) > 1
            if diff_only and not differs:
                continue
            cells = []
            for c in row["cells"]:
                content = (f'<a href="{esc(c["link"])}" target="_blank" rel="noopener noreferrer">{esc(c["text"])}</a>' if c["link"] else
                           (chip(c["text"], c["cls"]) if c["cls"] else esc(c["text"])))
                tip = f' title="{esc(c["tip"])}"' if c["tip"] else ""
                cells.append(f'<td class="{"diff" if differs else ""}"{tip}>{content}</td>')
            marker = '<span class="cmp-diff-mark" title="Values differ">≠</span>' if differs else ""
            info = f' <span class="cmp-info" title="{esc(row["tip"])}">ⓘ</span>' if row["tip"] else ""
            shown.append(f'<tr><th scope="row">{marker}{esc(row["label"])}{info}</th>{"".join(cells)}</tr>')
        if title != "How we got this data":
            body.append(f'<tr class="cmp-section"><th colspan="{len(entries) + 1}">{esc(section)}</th></tr>')
        body += shown or [f'<tr><td colspan="{len(entries) + 1}" class="cmp-empty">No differences in this section.</td></tr>']
    return (f'<div class="cmp-wrap"><table class="cmp"><thead><tr><th scope="col" class="cmp-corner">'
            f'{esc("Compared server" if title != "How we got this data" else "Check")}</th>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


COMPARE_CSS = """
<style>
.cmp-wrap {max-height: 70vh; overflow: auto; border: 1px solid #E1E4EA; border-radius: 12px; background: #FFFFFF;}
table.cmp {border-collapse: separate; border-spacing: 0; width: 100%; font-size: 0.86rem; color: #1A1D24;}
table.cmp th, table.cmp td {border-bottom: 1px solid #EEF0F4; padding: 0.45rem 0.6rem; text-align: left; vertical-align: top; word-break: break-word;}
table.cmp thead th {position: sticky; top: 0; z-index: 3; background: #F1F3F7; font-weight: 600; border-bottom: 1px solid #E1E4EA;}
table.cmp thead th a {color: #1F4FC4; text-decoration: none;}
table.cmp tbody th {width: 22%; font-weight: 500; color: #5B6170; background: #FFFFFF;}
table.cmp td.diff {background: #FFF8E6; font-weight: 600;}
.cmp-diff-mark {display:inline-block; color:#8A3F00; font-weight:700; margin-right:0.3rem;}
.cmp-info {color:#5B6170; cursor:help;}
tr.cmp-section th {background: #EAF0FD; color: #16357F; font-weight: 700; text-transform: none;}
td.cmp-empty {color:#5B6170; font-style: italic;}
</style>
"""


def compare_card(entry):
    s, sec = entry["summary"], entry["security"]
    with st.container(border=True):
        st.markdown(f"**{s['registry_name']}**")
        st.caption(f"{s['title'] or 'No title declared'} · version {s['version']}")
        chips = [chip(STATUS_LABELS.get(s["registry_status"], s["registry_status"]), f"status-{s['registry_status']}"),
                 chip(DEPLOYMENT_LABELS[s["deployment_type"]], "deploy")]
        if sec["highest_advisory_severity"]:
            chips.append(chip(f"Highest recorded: {sec['highest_advisory_severity']}", SEVERITY_CLASS.get(sec["highest_advisory_severity"], "")))
        st.markdown(" ".join(chips), unsafe_allow_html=True)
        state = sec["vulnerability_assessment_state"]
        security = {"no_package_vulnerability_path": "package checks not applicable (no declared package)",
                    "not_assessed": "eligible package not assessed (unknown)",
                    "checks_could_not_complete": "checks could not complete (unknown)",
                    "no_known_findings_in_completed_checks": "checked — no known advisories (not proof of safety)"}.get(
            state, f"{sec['distinct_advisories']} recorded advisories ({sec['direct_advisories']} direct, {sec['dependency_advisories']} in dependencies)")
        st.markdown(f"Security: {security}  \nTools: {tools_text(s)}  \nData as of {fmt_date(entry['snapshot_observed_at'])}")
        buttons = st.columns(2)
        if buttons[0].button("Open profile", key=f"card_open_{s['server_id']}", width="stretch"):
            open_profile(s["server_id"])
        if buttons[1].button("Remove", key=f"card_remove_{s['server_id']}", width="stretch", help="Remove from this comparison"):
            st.session_state["compare_ids"] = [i for i in st.session_state["compare_ids"] if i != s["server_id"]]
            st.rerun()


def compare():
    ids = st.session_state["compare_ids"]
    from_url = st.query_params.get("ids", "")
    if not ids and from_url:
        ids = st.session_state["compare_ids"] = [int(v) for v in from_url.split(",") if v.isdigit()][:4]
    st.markdown('<p class="ms-title">Compare servers</p>', unsafe_allow_html=True)
    if len(ids) > 4:
        names = st.session_state["selected"]
        st.info(f"Compare shows up to 4 servers at a time. You selected {len(ids)}; choose which 4 to compare. Your selection is kept.")
        chosen = st.multiselect("Servers to compare", ids, default=ids[:4], max_selections=4, format_func=lambda i: names.get(i, str(i)))
        if st.button("Compare these", type="primary", disabled=len(chosen) < 2):
            st.session_state["compare_ids"] = chosen
            st.rerun()
        return
    result = None
    if len(ids) >= 2:
        try:
            result = query("/api/compare", server_ids=",".join(map(str, ids)))
        except ApiError as error:
            st.error(error_message(error))
    if result:
        st.markdown(f'<p class="ms-sub">Data as of {esc(fmt_date(result["servers"][0]["snapshot_observed_at"]))} (registry snapshot)</p>',
                    unsafe_allow_html=True)
        st.query_params["ids"] = ",".join(map(str, ids))
    actions = st.columns([1.7, 1.3, 1.5, 2.3, 0.8], vertical_alignment="center")
    st.session_state["f_diff_only"] = st.session_state["diff_only"]
    actions[0].toggle("Show differences only", key="f_diff_only",
                      on_change=lambda: st.session_state.update(diff_only=st.session_state["f_diff_only"]))
    with actions[1].popover("Add server", icon=":material/add:", disabled=len(ids) >= 4, help="Compare shows up to 4 servers."):
        picked = server_picker("cmp_add", "Find a server")
        if picked and st.button("Add to comparison", type="primary", disabled=picked[0] in ids):
            st.session_state["compare_ids"] = ids + [picked[0]]
            st.session_state["selected"].setdefault(picked[0], picked[1])
            st.rerun()
    if ids and actions[2].button("Clear comparison", icon=":material/delete_sweep:"):
        st.session_state["compare_ids"] = []
        st.query_params.pop("ids", None)
        st.rerun()
    ready = ai_ready()
    if result and actions[3].button("Ask AI about these servers", icon=":material/chat:", disabled=not ready, help=None if ready else AI_OFF):
        ask_ai([(e["summary"]["server_id"], e["summary"]["registry_name"]) for e in result["servers"]])
    if len(ids) < 2:
        st.info("Choose at least two servers: select them on Server search and press Compare selected, or use Add server.")
        return
    if not result:
        return
    entries = result["servers"]
    cards = st.columns(len(entries))
    for col, entry in zip(cards, entries):
        with col:
            compare_card(entry)
    for note in result["notes"][1:]:
        st.warning(note, icon=":material/info:")
    st.caption(result["notes"][0])
    sections = compare_rows(entries)
    st.html(COMPARE_CSS + compare_table(entries, sections, "Comparison", st.session_state["diff_only"]))
    with st.expander("How we got this data", expanded=False):
        st.html(COMPARE_CSS + compare_table(entries, sections, "How we got this data", st.session_state["diff_only"]))
        st.caption("Hover a value for the raw source and outcome. Coverage is not a security score.")


AI_CSS = """
<style>
.stMainBlockContainer {max-width: 820px;}
[data-testid="stBottomBlockContainer"] {max-width: 820px; margin: 0 auto;}
.ai-title {font-size: 1.35rem; font-weight: 700; margin: 0;}
.ai-ask {text-align: center; font-size: 1.25rem; font-weight: 600; margin: 1.2rem 0 0.6rem;}
.st-key-ai_cards button {min-height: 4.2rem; text-align: left; justify-content: flex-start; border-radius: 12px; background: #FFFFFF;}
.st-key-ai_cards button p {white-space: normal !important; overflow: visible !important; text-overflow: clip !important; text-align: left;}
</style>
"""


@st.cache_data(ttl=600, show_spinner=False)
def ai_examples():
    def exact(name):
        page = query("/api/servers", q=name, status="all", page_size=10)
        return next(((i["server_id"], i["registry_name"]) for i in page["items"] if i["registry_name"] == name), None)

    summary = exact("ac.inference.sh/mcp")
    if not summary:
        top = query("/api/servers", sort="concerns", page_size=1)["items"]
        summary = (top[0]["server_id"], top[0]["registry_name"]) if top else None
    remote = exact("ac.snag/snag")
    if not remote:
        items = query("/api/servers", deployment="remote_only", page_size=1)["items"]
        remote = (items[0]["server_id"], items[0]["registry_name"]) if items else None
    pair = [(i["server_id"], i["registry_name"]) for i in query("/api/servers", assessment="findings_recorded", sort="concerns", page_size=2)["items"]]
    cards = [("Which servers have recorded critical-severity advisories?", [])]
    if summary:
        cards.append((f"Summarize the security evidence for {summary[1]}", [summary]))
    if remote:
        cards.append((f"Why is there no package vulnerability assessment for {remote[1]}?", [remote]))
    if len(pair) == 2:
        cards.append(("Compare two servers' dependency exposure evidence", pair))
    cards += [("Which servers have not been assessed?", []), ("Which servers have verified tool metadata?", [])]
    return cards


def ai_request(question, ai):
    history = [{"role": m["role"], "content": m["content"][:4000]} for m in ai["messages"][-6:]]
    try:
        response = requests.post(f"{BACKEND_URL}/api/ai/chat", json={"question": question, "history": history, "strategy": ai["strategy"],
                                 "top_k": ai["top_k"], "server_ids": [s["server_id"] for s in ai["scope"]]}, timeout=110)
    except requests.Timeout:
        return None, "The assistant took too long to respond. Your conversation is kept; please try again."
    except requests.RequestException:
        return None, "The AI service is not reachable. Your conversation is kept; please try again."
    if not response.ok:
        try:
            detail = response.json().get("detail")
        except ValueError:
            detail = None
        return None, detail if isinstance(detail, str) else f"The assistant could not complete this request (HTTP {response.status_code})."
    return response.json(), None


def show_answer(result, key):
    st.markdown(result["answer"])
    if result["status"] == "insufficient_evidence":
        st.caption("The available evidence is insufficient for a complete answer.")
    for note in result.get("coverage_notes", []):
        st.caption(f"Coverage note: {note}")
    for limitation in result["limitations"]:
        st.caption(limitation)
    sources = result["sources"]
    if sources:
        cited = [s for s in sources if s.get("cited")]
        others = [s for s in sources if not s.get("cited")]
        with st.expander(f"Sources ({len(cited)} cited of {len(sources)} retrieved)", expanded=False):
            for source in cited:
                ref = source.get("ref")
                when = fmt_date(source.get("observed_at")) if source.get("observed_at") else "date not recorded"
                st.markdown(f"**[{ref}] {source.get('source_name', source['kind'])}** · {source['title']} · {when}")
                st.caption(source.get("excerpt") or "")
                links = st.columns([1, 1, 3])
                url = safe_url(source.get("source_url"))
                if url:
                    links[0].link_button("Source link", url)
                if source.get("server_id") and links[1].button("Open profile", key=f"{key}_src_{ref}"):
                    open_profile(source["server_id"])
            if others:
                st.caption("Also retrieved, not cited: " + "; ".join(f"[{s.get('ref')}] {s['title']}" for s in others))
    st.caption(f"{result['latency_ms'] / 1000:.1f}s · {result['input_tokens']:,} input / {result['output_tokens']:,} output tokens")


def scope_label(scope):
    if not scope:
        return "Server: Any"
    return "Server: " + (scope[0]["registry_name"] if len(scope) == 1 else f"{len(scope)} servers")


def ai_assistant():
    st.html(AI_CSS)
    ai = st.session_state["ai"]
    try:
        state = query("/api/ai/status")
    except ApiError as error:
        st.error(error_message(error))
        return
    top = st.columns([5, 1], vertical_alignment="center")
    top[0].markdown('<p class="ai-title">AI assistant</p>', unsafe_allow_html=True)
    if ai["messages"] and top[1].button("New chat", icon=":material/add_comment:", help="Clears this conversation."):
        ai["messages"] = []
        ai["pending"] = None
        st.rerun()
    if state.get("chunks"):
        st.caption(f"{state['chunks']:,} evidence chunks · Indexed {fmt_date(state['last_indexed_at'])}",
                   help="Evidence chunks are the stored text records (server profiles, findings, one methodology note) the assistant searches. "
                        "Indexed is the last time they were embedded.")
    st.markdown('<div class="ms-strip">Assessment coverage is partial. Missing evidence does not mean a server is safe.</div>',
                unsafe_allow_html=True)
    if not state["configured"]:
        st.info("The AI assistant needs to be configured by the project administrator (OPENAI_API_KEY).")
        return
    if state.get("setup"):
        st.info(state["setup"])
        return
    if not state["chunks"]:
        st.info("The project data has not been indexed for AI search yet.")
        return
    if not ai["messages"] and not ai["pending"]:
        st.markdown('<p class="ai-ask">What do you want to know?</p>', unsafe_allow_html=True)
        try:
            cards = ai_examples()
        except ApiError:
            cards = []
        with st.container(key="ai_cards"):
            columns = st.columns(2)
            for i, (question, scope) in enumerate(cards[:6]):
                if columns[i % 2].button(question, key=f"card_{i}", width="stretch"):
                    ai["scope"] = [{"server_id": sid, "registry_name": name} for sid, name in scope]
                    ai["pending"] = question
                    st.rerun()
    for i, message in enumerate(ai["messages"]):
        with st.chat_message(message["role"]):
            if message["role"] == "assistant":
                show_answer(message["result"], f"history_{i}")
            else:
                st.markdown(message["content"])
                if message.get("scope"):
                    st.caption("Scope: " + ", ".join(s["registry_name"] for s in message["scope"]))
    controls = st.columns([3, 1], vertical_alignment="center")
    with controls[0].popover(scope_label(ai["scope"]), icon=":material/dns:"):
        st.caption("Limit answers to specific servers (up to 4). The scope filters retrieval and adds live facts for each server.")
        picked = server_picker("ai_scope", "Find a server")
        if picked and st.button("Add to scope", type="primary", disabled=len(ai["scope"]) >= 4 or any(s["server_id"] == picked[0] for s in ai["scope"])):
            ai["scope"].append({"server_id": picked[0], "registry_name": picked[1]})
            st.rerun()
        for s in list(ai["scope"]):
            if st.button(f"Remove {s['registry_name']}", key=f"scope_rm_{s['server_id']}"):
                ai["scope"] = [x for x in ai["scope"] if x["server_id"] != s["server_id"]]
                st.rerun()
        if ai["scope"] and st.button("Reset to Any server"):
            ai["scope"] = []
            st.rerun()
    with controls[1].popover("⚙", help="Answer settings"):
        st.session_state["f_ai_strategy"] = ai["strategy"]
        st.selectbox("Prompt strategy", ["few_shot", "zero_shot"], key="f_ai_strategy",
                     format_func={"few_shot": "Few-shot (with examples)", "zero_shot": "Zero-shot"}.get,
                     on_change=lambda: ai.update(strategy=st.session_state["f_ai_strategy"]))
        st.session_state["f_ai_top_k"] = ai["top_k"]
        st.slider("Sources to retrieve", min_value=1, max_value=10, key="f_ai_top_k", on_change=lambda: ai.update(top_k=st.session_state["f_ai_top_k"]),
                  help="Broad discovery questions use at least 8 sources automatically.")
    question = st.chat_input("Ask about a server, vulnerability, or missing assessment", max_chars=1500)
    question = question or ai["pending"]
    if question:
        ai["pending"] = None
        scope = list(ai["scope"])
        with st.chat_message("user"):
            st.markdown(question)
        with st.spinner("Searching stored evidence and preparing an answer…"):
            result, error = ai_request(question, ai)
        if error:
            st.error(error)
            return
        if result.get("missing_scope"):
            ai["scope"] = [s for s in ai["scope"] if s["server_id"] not in result["missing_scope"]]
            st.warning("Some selected servers were not found in this database and were removed from the scope.")
        ai["messages"].extend([{"role": "user", "content": question, "scope": scope},
                               {"role": "assistant", "content": result["answer"], "result": result}])
        del ai["messages"][:-20]
        st.rerun()


init_state()
st.markdown(THEME_CSS, unsafe_allow_html=True)
PAGES = {
    "dashboard": st.Page(dashboard, title="Dashboard", icon=":material/dashboard:", default=True),
    "search": st.Page(search, title="Server search", icon=":material/search:", url_path="search"),
    "profile": st.Page(profile, title="Server profile", icon=":material/description:", url_path="profile"),
    "compare": st.Page(compare, title="Compare", icon=":material/compare_arrows:", url_path="compare"),
    "ai": st.Page(ai_assistant, title="AI assistant", icon=":material/chat:", url_path="ai"),
}
st.navigation(list(PAGES.values())).run()

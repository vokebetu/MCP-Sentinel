import csv
import io
from urllib.parse import urlsplit

STATE_LABELS = {
    "findings_recorded": "Findings recorded",
    "no_known_findings_in_completed_checks": "Checked — none found",
    "checks_could_not_complete": "Unknown — checks could not complete",
    "no_package_vulnerability_path": "Not applicable — no package declared",
    "not_assessed": "Not assessed",
}
DEPLOYMENT_LABELS = {"remote_only": "Remote only", "packages_only": "Package only", "packages_and_remotes": "Both", "neither": "Neither"}
STATUS_LABELS = {"active": "Active", "deprecated": "Deprecated", "deleted": "Deleted"}
ECOSYSTEM_LABELS = {"npm": "npm", "pypi": "PyPI", "oci": "OCI/Docker", "nuget": "NuGet", "cargo": "Cargo", "mcpb": "MCPB"}
MISSING = {
    "not_applicable": "— Not applicable",
    "not_assessed": "○ Not assessed",
    "unknown": "? Unknown",
    "none_found": "✓ None found",
    "not_observed": "Not observed",
    "not_declared": "Not declared",
    "lookup_failed": "Lookup failed",
}
MISSING_HELP = {
    "— Not applicable": "This check does not apply to the server, for example a package check on a server that declares no package.",
    "○ Not assessed": "The check applies but no lookup was recorded. The value is unknown, not zero.",
    "? Unknown": "A lookup was attempted but could not complete. The value is unknown, not zero.",
    "✓ None found": "The check completed and found nothing. This is not proof of safety.",
    "Not observed": "No metadata was found in the checked sources. This does not mean the value is zero.",
    "Not declared": "The registry record does not declare this item.",
}
COLUMN_HELP = {
    "deployment": "Whether the registry lists a remotely hosted endpoint, a downloadable package, both, or neither; this is not a security assessment.",
    "ecosystems": "Package registries (such as npm or PyPI) associated with declared server packages.",
    "security": "Status of package-advisory checking and any advisory findings; missing assessment does not mean safe.",
    "distinct": "Unique matching advisory records, deduplicated across upstream identifiers when supported; not a count of exploit attempts.",
    "direct": "Advisories affecting a declared package/version itself.",
    "dependency": "Advisories in modeled downstream dependency versions; modeled exposure does not confirm actual deployment or exploitation.",
    "severity": "Highest severity among recorded advisories, not an overall server security score.",
    "cvss": "An advisory severity metric when published; may be missing and is not proof of exploitability.",
    "tools": "Tool definitions found in accessible evidence; Unknown/Not observed means the tools were not verified, not that none exist.",
    "schemas": "Tool input schemas available and structurally verified from accessible metadata, not a complete live inventory.",
    "hints": "Text-pattern review notes on stored tool descriptions; most are harmless and need a human to read them.",
    "repo": "Source repository declared in the registry record. Blank means not declared.",
    "server": "Registry name. Click to open the server profile in a new tab.",
    "status": "Registry lifecycle status of the server record.",
    "version": "Latest registry version in the snapshot.",
    "title": "Title declared by the publisher.",
    "published": "Publish date of this registry version.",
}
COLUMNS = {
    "server": "Server", "title": "Title", "version": "Version", "deployment": "Deployment ⓘ", "security": "Vulnerability evidence ⓘ",
    "tools": "Tools ⓘ", "repo": "Repo", "status": "Status", "ecosystems": "Ecosystems ⓘ", "distinct": "Distinct advisories ⓘ",
    "direct": "Direct ⓘ", "dependency": "Dependency ⓘ", "severity": "Highest severity ⓘ", "schemas": "Verified input schemas ⓘ",
    "hints": "Tool review notes ⓘ", "published": "Published",
}
DEFAULT_COLUMNS = ["server", "title", "version", "deployment", "security", "tools", "repo"]
EXTRA_COLUMNS = ["status", "ecosystems", "distinct", "direct", "dependency", "severity", "schemas", "hints", "published"]
RIGHT_ALIGNED = {"distinct", "direct", "dependency", "schemas", "hints"}
FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def safe_url(url):
    if not isinstance(url, str):
        return None
    parts = urlsplit(url.strip())
    return url.strip() if parts.scheme in ("http", "https") and parts.netloc else None


def blocked_state(state):
    return {"no_package_vulnerability_path": MISSING["not_applicable"], "not_assessed": MISSING["not_assessed"],
            "checks_could_not_complete": MISSING["unknown"]}.get(state)


def advisory_count(item, field):
    blocked = blocked_state(item["vulnerability_assessment_state"])
    if blocked:
        return blocked
    value = item.get(field)
    return MISSING["unknown"] if value is None else str(value)


def severity_text(item):
    blocked = blocked_state(item["vulnerability_assessment_state"])
    if blocked:
        return blocked
    return item.get("highest_advisory_severity") or MISSING["none_found"]


def security_text(item):
    state = item["vulnerability_assessment_state"]
    if state == "findings_recorded":
        severity = item.get("highest_advisory_severity")
        return f"Findings: {item.get('distinct_advisories')} advisories" + (f" · highest {severity}" if severity else "")
    if state == "no_known_findings_in_completed_checks":
        return "✓ Checked — none found"
    return blocked_state(state) or STATE_LABELS.get(state, state)


def tools_text(item):
    state, count = item.get("tool_metadata_state"), item.get("tool_count")
    if state == "listed":
        return f"{count} listed"
    if state == "count_observed":
        return f"{count} (handshake count)"
    if state == "observed_none":
        return "0 observed (handshake)"
    return MISSING["not_observed"]


def schemas_text(item):
    if item.get("tool_metadata_state") != "listed":
        return MISSING["not_observed"]
    return str(item.get("valid_input_schema_count") or 0)


def cell(item, column):
    if column == "server":
        return item["registry_name"]
    if column == "title":
        return item.get("title") or ""
    if column == "version":
        return item.get("version") or ""
    if column == "deployment":
        return DEPLOYMENT_LABELS.get(item["deployment_type"], item["deployment_type"])
    if column == "security":
        return security_text(item)
    if column == "tools":
        return tools_text(item)
    if column == "repo":
        return safe_url(item.get("repository_url")) or MISSING["not_declared"]
    if column == "status":
        return STATUS_LABELS.get(item["registry_status"], item["registry_status"])
    if column == "ecosystems":
        return ", ".join(ECOSYSTEM_LABELS.get(e, e) for e in item.get("ecosystems") or []) or MISSING["not_declared"]
    if column == "distinct":
        return advisory_count(item, "distinct_advisories")
    if column == "direct":
        return advisory_count(item, "direct_advisories")
    if column == "dependency":
        return advisory_count(item, "dependency_advisories")
    if column == "severity":
        return severity_text(item)
    if column == "schemas":
        return schemas_text(item)
    if column == "hints":
        return str(item.get("tool_review_hints") or 0) if item.get("tool_metadata_state") == "listed" else MISSING["not_observed"]
    if column == "published":
        return (item.get("published_at") or "")[:10]
    raise KeyError(column)


def table_rows(items, columns):
    return [{"Server ID": item["server_id"], **{COLUMNS[c]: cell(item, c) for c in columns}} for item in items]


def guard(value):
    if isinstance(value, str) and value.startswith(FORMULA_START):
        return "'" + value
    return value


def to_csv(rows):
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: guard(v) for k, v in row.items()})
    return buffer.getvalue()


def search_params(filters, page, page_size):
    params = {"q": filters["q"].strip() or None, "status": filters["status"], "sort": filters["sort"], "page": page, "page_size": page_size}
    if filters["ecosystem"] != "any":
        params["ecosystem"] = filters["ecosystem"]
    if filters["deployment"] != "any":
        params["deployment"] = filters["deployment"]
    if filters["repository"] != "any":
        params["has_repository"] = filters["repository"] == "declared"
    if filters["github"]:
        params["github"] = True
    if filters["assessment"] != "any":
        params["assessment"] = filters["assessment"]
    if filters["tool_info"] == "known":
        params["tool_info"] = ("listed", "count_observed")
    elif filters["tool_info"] != "any":
        params["tool_info"] = (filters["tool_info"],)
    if filters["tool_hints"] != "any":
        params["tool_hints"] = filters["tool_hints"] == "yes"
    if params["sort"] == "relevance" and not params["q"]:
        params["sort"] = "name"
    return params


def page_range(total, page, page_size):
    if not total:
        return 0, 0
    first = (page - 1) * page_size + 1
    return first, min(total, page * page_size)


class ApiError(Exception):
    def __init__(self, kind, message, request_id=None):
        super().__init__(message)
        self.kind, self.message, self.request_id = kind, message, request_id


def http_error(status, body, request_id=None):
    detail = body.get("detail") if isinstance(body, dict) else None
    if status == 503:
        reason = body.get("reason") if isinstance(body, dict) else None
        text = {"database_busy": "The API is up, but the database was busy and did not answer in time (HTTP 503).",
                "query_timeout": "The API is up, but the database query took too long (HTTP 503).",
                "schema_missing": "The API is up, but the database tables are missing (HTTP 503). Run: docker compose run --rm importer migrate"}
        return ApiError("http_503", text.get(reason, f"The API is up, but the database is unavailable (HTTP 503: {detail or 'no detail'})."),
                        request_id)
    return ApiError("http_error", f"The API returned HTTP {status}: {detail if isinstance(detail, str) else 'request failed'}.", request_id)


def error_message(error):
    hint = {"transport": "Your filters and selections are kept.", "timeout": "Your filters and selections are kept; try again.",
            "http_503": "Your filters and selections are kept; try again in a moment.", "http_error": "Your filters and selections are kept."}
    suffix = f" Request id: {error.request_id}." if error.request_id else ""
    return f"{error.message} {hint.get(error.kind, '')}{suffix}".strip()

import gzip
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import psycopg
from jsonschema import validators
from jsonschema.exceptions import SchemaError
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "database" / "schema"
OFFICIAL = "io.modelcontextprotocol.registry/official"
PUBLISHER = "io.modelcontextprotocol.registry/publisher-provided"
VERSION_RANGE = re.compile(r"[\^~<>=*|,\s]|^latest$|(^|\.)x($|\.)", re.IGNORECASE)
GITHUB_REPO = re.compile(r"^https?://(?:www\.)?github\.com/([^/\s]+)/([^/\s#?]+)", re.IGNORECASE)
SEMVER = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
OSV_TO_ECOSYSTEM = {"npm": "npm", "PyPI": "pypi", "NuGet": "nuget", "crates.io": "cargo", "Go": "go", "Maven": "maven"}
DEPS_TO_ECOSYSTEM = {"NPM": "npm", "PYPI": "pypi", "NUGET": "nuget", "CARGO": "cargo", "GO": "go", "MAVEN": "maven"}
REDACTED = "<redacted: isSecret>"

SOURCES = [
    ("mcp_registry", "Official MCP Registry", "registry", "https://registry.modelcontextprotocol.io",
     "Publisher-supplied metadata; no separate data licence; aggregator access documented by the registry", "permitted_with_attribution",
     "Data from the Official MCP Registry (registry.modelcontextprotocol.io)", "Identity source for every server"),
    ("github", "GitHub REST API", "hosting_platform", "https://api.github.com", "GitHub Terms of Service", "permitted_with_attribution",
     "Repository metadata from the GitHub REST API", "Only small factual fields (id, archived, fork, stars, push date, licence) are stored"),
    ("npm", "npm Registry", "package_registry", "https://registry.npmjs.org", "npm public registry metadata", "permitted_with_attribution",
     "Package metadata from the npm public registry", None),
    ("pypi", "PyPI JSON API", "package_registry", "https://pypi.org", "PyPI terms of use", "permitted_with_attribution",
     "Package metadata from PyPI", None),
    ("pypi_integrity", "PyPI Integrity API (PEP 740)", "package_registry", "https://docs.pypi.org/api/integrity/", "PyPI terms of use",
     "permitted_with_attribution", "Provenance metadata from the PyPI Integrity API", None),
    ("deps_dev", "deps.dev (Open Source Insights)", "dependency_resolution", "https://deps.dev", "Open Source Insights terms; CC BY 4.0 data",
     "permitted_with_attribution", "Dependency data from deps.dev (Google Open Source Insights)", "Graphs model a fresh install, not an installed system"),
    ("osv", "OSV.dev", "advisory_database", "https://osv.dev", "Records keep upstream licences (GHSA and PyPA advisories are CC BY 4.0)",
     "permitted_with_attribution", "Vulnerability data from OSV.dev and its upstream databases", None),
    ("ghsa", "GitHub Advisory Database", "advisory_database", "https://github.com/advisories", "CC BY 4.0", "permitted_with_attribution",
     "GitHub Advisory Database (CC BY 4.0)", "Used as a cross-check of OSV for declared package versions"),
    ("cve_org", "CVE.org (CVE Services API)", "advisory_database", "https://www.cve.org", "CVE Terms of Use", "permitted_with_attribution",
     "CVE records from CVE.org", None),
    ("nvd", "NIST National Vulnerability Database", "advisory_enrichment", "https://nvd.nist.gov", "US government work; NVD notice requested",
     "permitted_with_attribution", "This product uses data from the NVD API but is not endorsed or certified by the NVD", None),
    ("epss", "FIRST EPSS", "exploit_prediction", "https://www.first.org/epss", "Free use; attribution requested", "permitted_with_attribution",
     "EPSS scores from FIRST.org", "EPSS is a CVE-level probability, not a server-level compromise probability"),
    ("cisa_kev", "CISA Known Exploited Vulnerabilities", "exploitation_catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
     "CC0 1.0", "permitted", None, "Lookups are against one dated catalog snapshot"),
    ("agora", "Agora (openforallofus.com)", "endpoint_observations", "https://openforallofus.com/data", "CC BY 4.0", "permitted_with_attribution",
     "Endpoint observations from Agora (openforallofus.com), CC BY 4.0", "Handshake classes were observed by Agora, not by MCP Sentinel"),
    ("policylayer", "PolicyLayer MCP Server Catalogue", "tool_catalog", "https://huggingface.co/datasets/PolicyLayer/mcp-server-catalogue",
     "CC BY 4.0", "permitted_with_attribution", "Tool data from the PolicyLayer MCP Server Catalogue, CC BY 4.0",
     "Risk categories are PolicyLayer classifier output (inferred)"),
    ("toolhive", "ToolHive Registry (stacklok/toolhive-catalog)", "tool_catalog", "https://github.com/stacklok/toolhive-catalog", "Apache-2.0",
     "permitted_with_attribution", "Tool definitions from the ToolHive catalog (Apache-2.0)", "Curator-declared configuration"),
    ("glama", "Glama MCP API", "tool_catalog", "https://glama.ai/mcp", "Glama API Data License (attribution, key required)", "restricted",
     None, "Not accessed: an API key is required; only the access-restricted outcome is stored"),
]

EVIDENCE_TYPES = {
    "mcp_registry": "publisher_declared", "github": "independently_observed", "npm": "publisher_declared", "pypi": "publisher_declared",
    "pypi_integrity": "independently_observed", "deps_dev": "computed_resolution", "osv": "official_advisory", "ghsa": "official_advisory",
    "cve_org": "official_advisory", "nvd": "official_advisory", "epss": "inferred_classification", "cisa_kev": "official_advisory",
    "agora": "third_party_observed", "policylayer": "third_party_observed", "toolhive": "curator_declared", "glama": "third_party_observed",
}


def utc_now():
    return datetime.now(timezone.utc)


def parse_time(value):
    if value in (None, ""):
        return None
    text = str(value).strip().replace("Z", "+00:00")
    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def database_url():
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    return psycopg.conninfo.make_conninfo(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=os.environ.get("POSTGRES_PORT", "5432"),
        dbname=os.environ.get("POSTGRES_DB", "mcp_sentinel"),
        user=os.environ.get("POSTGRES_USER", "sentinel"),
        password=os.environ.get("POSTGRES_PASSWORD", ""),
    )


def connect():
    return psycopg.connect(database_url())


def apply_migrations(conn):
    exists = conn.execute("SELECT to_regclass('public.schema_migrations')").fetchone()[0]
    applied = {row[0] for row in conn.execute("SELECT version FROM schema_migrations")} if exists else set()
    newly = []
    for path in sorted(SCHEMA_DIR.glob("*.sql")):
        if path.stem not in applied:
            conn.execute(path.read_text(encoding="utf-8"))
            newly.append(path.stem)
    conn.commit()
    return newly


def ensure_sources(conn):
    for key, name, kind, url, licence, redistribution, attribution, notes in SOURCES:
        conn.execute(
            """
            INSERT INTO data_sources (source_key, name, source_kind, homepage_url, license, redistribution, attribution, notes)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (source_key) DO UPDATE SET name = EXCLUDED.name, source_kind = EXCLUDED.source_kind,
                homepage_url = EXCLUDED.homepage_url, license = EXCLUDED.license, redistribution = EXCLUDED.redistribution,
                attribution = EXCLUDED.attribution, notes = EXCLUDED.notes
            """,
            (key, name, kind, url, licence, redistribution, attribution, notes),
        )
    return dict(conn.execute("SELECT source_key, source_id FROM data_sources").fetchall())


def start_run(conn, source_id, kind, artifact, sha256, collected_at):
    return conn.execute(
        """
        INSERT INTO collection_runs (source_id, run_kind, started_at, status, input_artifact, input_sha256, source_collected_at)
        VALUES (%s, %s, %s, 'running', %s, %s, %s) RETURNING run_id
        """,
        (source_id, kind, utc_now(), artifact, sha256, collected_at),
    ).fetchone()[0]


def finish_run(conn, run_id, counts, errors):
    conn.execute(
        """
        UPDATE collection_runs SET finished_at = %s, status = %s, record_counts = %s, error_count = %s, error_summary = %s
        WHERE run_id = %s
        """,
        (utc_now(), "partial" if errors else "succeeded", json.dumps(counts, sort_keys=True), len(errors),
         "; ".join(sorted({message for _, message in errors}))[:2000] or None, run_id),
    )
    if errors:
        with conn.cursor() as cursor:
            cursor.executemany("INSERT INTO import_errors (run_id, record_ref, message) VALUES (%s, %s, %s)",
                               [(run_id, ref, message) for ref, message in errors])


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read_jsonl_gz(path):
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            if line.strip():
                yield number, line


def is_exact_version(version):
    return bool(version) and not VERSION_RANGE.search(version)


def normalize_package_name(ecosystem, name):
    ecosystem = (ecosystem or "").lower()
    name = (name or "").strip()
    if ecosystem == "pypi":
        return canonicalize_name(name)
    if ecosystem in ("nuget", "cargo"):
        return name.lower()
    return name


def github_parts(url):
    match = GITHUB_REPO.match((url or "").strip())
    if not match:
        return None
    owner, name = match.groups()
    return owner, name.removesuffix(".git")


def canonical_repository(url):
    url = (url or "").strip()
    if not url:
        return None
    parts = github_parts(url)
    if parts:
        owner, name = parts
        return {"host": "github.com", "canonical_url": f"https://github.com/{owner.lower()}/{name.lower()}", "owner": owner, "name": name}
    split = urlsplit(url)
    if not split.scheme or not split.hostname:
        return None
    path = split.path.rstrip("/").removesuffix(".git")
    segments = [segment for segment in path.split("/") if segment]
    return {
        "host": split.hostname.lower(),
        "canonical_url": f"{split.scheme.lower()}://{split.hostname.lower()}{path}",
        "owner": segments[0] if len(segments) >= 2 else None,
        "name": segments[1] if len(segments) >= 2 else None,
    }


def clean_subfolder(value):
    return (value or "").strip().removeprefix("./").strip("/")


def normalize_endpoint(url):
    if not isinstance(url, str) or not url.strip():
        return None
    parts = urlsplit(url.strip())
    try:
        port = parts.port
    except ValueError:
        port = None
    host = (parts.hostname or "").lower()
    port_text = f":{port}" if port and port not in (80, 443) else ""
    query = f"?{parts.query}" if parts.query else ""
    return f"{parts.scheme.lower()}://{host}{port_text}{parts.path.rstrip('/')}{query}"


def redact_secrets(value):
    if isinstance(value, dict):
        cleaned = {key: redact_secrets(item) for key, item in value.items()}
        if value.get("isSecret") is True:
            for key in ("value", "default"):
                if key in cleaned and cleaned[key] not in (None, ""):
                    cleaned[key] = REDACTED
        return cleaned
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    return value


def version_key(ecosystem, text):
    text = (text or "").strip()
    if not text:
        return None
    if ecosystem == "pypi":
        try:
            return (1, Version(text))
        except InvalidVersion:
            return None
    if ecosystem == "npm":
        match = SEMVER.match(text)
        if not match:
            return None
        major, minor, patch, pre = match.groups()
        pre_key = (1,) if pre is None else (0, tuple((0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".")))
        return (1, (int(major), int(minor), int(patch)), pre_key)
    return None


def range_status(ecosystem, version, entry):
    target = version_key(ecosystem, version)
    listed = [str(item) for item in entry.get("versions") or []]
    if version in listed or (target is not None and any(version_key(ecosystem, item) == target for item in listed)):
        return "affected"
    evaluated = bool(listed)
    undetermined = False
    for rng in entry.get("ranges") or []:
        if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
            undetermined = undetermined or not listed
            continue
        if target is None:
            undetermined = True
            continue
        events = []
        for event in rng.get("events") or []:
            for kind, value in event.items():
                key = (0,) if kind == "introduced" and str(value) == "0" else version_key(ecosystem, str(value))
                if key is None:
                    events = None
                    break
                events.append((key, kind))
            if events is None:
                break
        if events is None:
            undetermined = True
            continue
        status = False
        for key, kind in sorted(events, key=lambda item: item[0]):
            if kind == "introduced" and target >= key:
                status = True
            elif kind in ("fixed", "limit") and target >= key:
                status = False
            elif kind == "last_affected" and target > key:
                status = False
        if status:
            return "affected"
        evaluated = True
    if undetermined:
        return "undetermined"
    return "not_affected" if evaluated else "undetermined"


def schema_state(schema):
    if schema is None:
        return "absent", None
    if isinstance(schema, str):
        if not schema.strip():
            return "empty", None
        try:
            schema = json.loads(schema)
        except ValueError:
            return "unparseable", None
    if schema in (None, {}, []):
        return "empty", None
    if not isinstance(schema, dict):
        return "not_object", schema if isinstance(schema, list) else None
    try:
        validators.validator_for(schema).check_schema(schema)
    except SchemaError:
        return "invalid", schema
    if schema.get("type") != "object":
        return "not_object", schema
    return "valid", schema


def find_tool_lists(value):
    found = []
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("tools", "tool_definitions") and isinstance(item, list):
                found.extend(item)
            else:
                found.extend(find_tool_lists(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(find_tool_lists(item))
    return found

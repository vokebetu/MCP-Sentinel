import base64
import configparser
import hashlib
import html
import json
import os
import re
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit

import pandas as pd
import requests
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw"
CACHE_DIR = PROJECT_ROOT / "data" / "cache"

HF_DATASET = "DeepNLP/mcp-servers"
HF_BASE = "https://huggingface.co"
GITHUB_API = "https://api.github.com"
PYPI_API = "https://pypi.org/pypi"
NPM_REGISTRY = "https://registry.npmjs.org"
OSV_API = "https://api.osv.dev/v1"
DEPS_DEV_API = "https://api.deps.dev/v3"

REQUEST_TIMEOUT = 30
MAX_ATTEMPTS = 4
MAX_RETRY_WAIT = 120
OSV_BATCH_SIZE = 100
ISSUES_PER_REPOSITORY = 10
MIN_DOCUMENT_CHARS = 20
USER_AGENT = "mcp-sentinel-sprint1/1.0 (university data engineering project)"

NULL_PLACEHOLDERS = {"", "n/a", "na", "none", "null", "nan", "-", "--", "?", "unknown", "undefined", "tbd"}
GENERIC_LINK_NAMES = {"here", "link", "more", "demo", "demo video", "website", "docs", "documentation"}
NAME_STOPWORDS = {"mcp", "server", "servers", "model", "context", "protocol"}
BOILERPLATE_PATTERN = re.compile(
    r"cookie|skip to (main )?content|log in|sign up|toggle menu|enable javascript|book a demo|schedule a demo|privacy policy",
    re.IGNORECASE,
)
LEADING_MARKERS = re.compile(r"^[\s\-–—:;,.)\]•>|↗]+")
EXACT_VERSION = re.compile(r"(?:==?)?v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)")
SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?")
NPM_NAME = re.compile(r"(?:@[a-z0-9-~][a-z0-9-._~]*/)?[a-z0-9-~][a-z0-9-._~]*")
PYPI_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")
MARKDOWN_PATTERNS = [
    (re.compile(r"<!--.*?-->", re.DOTALL), " "),
    (re.compile(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)"), " "),
    (re.compile(r"!\[[^\]]*\]\([^)]*\)"), " "),
    (re.compile(r"\[([^\]]+)\]\([^)]*\)"), r"\1"),
    (re.compile(r"^\s*\[[^\]]+\]:\s*\S+.*$", re.MULTILINE), " "),
    (re.compile(r"<[^>\n]+>"), " "),
    (re.compile(r"^\s*\|?[\s:|-]+\|?\s*$", re.MULTILINE), " "),
    (re.compile(r"^\s*\|(.*)\|\s*$", re.MULTILINE), r"\1"),
    (re.compile(r"^\s{0,3}(?:#{1,6}|>|[-*+]|\d+\.)\s+", re.MULTILINE), ""),
    (re.compile(r"```[\w-]*|`|\*\*|__"), " "),
]
SUPPORTED_MANIFESTS = ("package.json", "pyproject.toml", "setup.cfg", "requirements.txt")
UNSUPPORTED_MANIFESTS = ("setup.py", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts", "composer.json", "Gemfile", "deno.json")
ECOSYSTEM_ALIASES = {
    "pypi": "PyPI", "python": "PyPI", "pip": "PyPI",
    "npm": "npm", "node": "npm", "nodejs": "npm", "javascript": "npm", "typescript": "npm",
}
ASSESSED_STATUSES = {"known_vulnerabilities_found", "no_known_vulnerabilities_found"}
STATUS_PRECEDENCE = [
    "known_vulnerabilities_found", "api_failed", "no_known_vulnerabilities_found", "unknown_version",
    "ambiguous_mapping", "unknown_package_identity", "not_assessed",
]
SERVER_COLUMNS = {
    "content_name": "server_name", "website": "website_url", "subfield": "sub_field",
    "month": "snapshot_month", "statistic_bing_rank": "bing_rank",
}
TEXT_COLUMNS = ["server_name", "publisher_id", "website_url", "field", "sub_field", "snapshot_month", "description", "content"]
PACKAGE_COLUMNS = [
    "package_id", "ecosystem", "package_name", "registry_status", "http_status", "latest_version", "release_count",
    "summary", "project_urls", "registry_repository_ids", "latest_dependencies", "source", "collected_at",
]
REPOSITORY_FIELDS = {
    "full_name": "full_name", "owner_login": "owner", "name": "repository_name", "html_url": "html_url",
    "description": "description", "stargazers_count": "stars", "forks_count": "forks",
    "open_issues_count": "open_issues", "archived": "archived", "fork": "is_fork", "language": "primary_language",
    "license_spdx_id": "license", "default_branch": "default_branch", "created_at": "created_at",
    "updated_at": "updated_at", "pushed_at": "pushed_at",
}


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def credential_status():
    return {name: bool(os.getenv(name, "").strip()) for name in ("GITHUB_TOKEN", "HF_TOKEN")}


def auth_header(variable):
    token = os.getenv(variable, "").strip()
    return {"Authorization": f"Bearer {token}"} if token else {}


def retry_wait(response, attempt):
    remaining = response.headers.get("X-RateLimit-Remaining")
    retry_after = response.headers.get("Retry-After", "")
    rate_limited = response.status_code == 429 or (response.status_code == 403 and (remaining == "0" or retry_after))
    if not rate_limited and response.status_code not in (500, 502, 503, 504):
        return None
    if retry_after.isdigit():
        return int(retry_after)
    if remaining == "0":
        return max(0, int(response.headers.get("X-RateLimit-Reset", "0")) - time.time()) + 1
    return 2 ** attempt


def request_json(method, url, payload=None, headers=None):
    cache_key = hashlib.sha256(json.dumps([method, url, payload], sort_keys=True).encode()).hexdigest()
    cache_path = CACHE_DIR / f"{cache_key}.json"
    if cache_path.exists():
        return json.loads(cache_path.read_text(encoding="utf-8"))
    result = {"status": None, "error": "not_attempted", "body": None, "fetched_at": utc_now()}
    for attempt in range(MAX_ATTEMPTS):
        try:
            response = requests.request(
                method, url, json=payload, timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT, **(headers or {})},
            )
        except requests.RequestException as error:
            result = {"status": None, "error": type(error).__name__, "body": None, "fetched_at": utc_now()}
            time.sleep(2 ** attempt)
            continue
        wait = retry_wait(response, attempt)
        if wait is not None:
            result = {"status": response.status_code, "error": "rate_limited_or_unavailable", "body": None, "fetched_at": utc_now()}
            if wait > MAX_RETRY_WAIT:
                return result
            time.sleep(wait)
            continue
        result = {"status": response.status_code, "error": None, "body": None, "link": response.headers.get("Link"), "fetched_at": utc_now()}
        if not response.ok:
            result["error"] = f"http_{response.status_code}"
        else:
            try:
                result["body"] = response.json()
            except ValueError:
                result["error"] = "malformed_json"
                return result
        if response.status_code in (200, 404):
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(json.dumps(result), encoding="utf-8")
        return result
    return result


def lookup_status(result):
    return {200: "found", 404: "not_found"}.get(result["status"], "lookup_failed")


def page_count(result):
    if result["status"] != 200 or not isinstance(result["body"], list):
        return None
    match = re.search(r'[?&]page=(\d+)>; rel="last"', result.get("link") or "")
    return int(match.group(1)) if match else len(result["body"])


def download_deepnlp(raw_dir=RAW_DIR):
    metadata_path = raw_dir / "deepnlp_source_metadata.json"
    if metadata_path.exists():
        return json.loads(metadata_path.read_text(encoding="utf-8"))
    headers = {"User-Agent": USER_AGENT, **auth_header("HF_TOKEN")}
    response = requests.get(f"{HF_BASE}/api/datasets/{HF_DATASET}", headers=headers, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    info = response.json()
    data_files = sorted(item["rfilename"] for item in info["siblings"] if item["rfilename"].endswith((".json", ".jsonl")))
    files = []
    for file_name in data_files:
        download = requests.get(f"{HF_BASE}/datasets/{HF_DATASET}/resolve/{info['sha']}/{file_name}", headers=headers, timeout=120)
        download.raise_for_status()
        target = raw_dir / file_name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(download.content)
        files.append({"file_name": file_name, "bytes": len(download.content), "sha256": hashlib.sha256(download.content).hexdigest()})
    metadata = {
        "dataset": HF_DATASET, "source_url": f"{HF_BASE}/datasets/{HF_DATASET}", "revision": info["sha"],
        "last_modified": info.get("lastModified"), "downloaded_at": utc_now(), "files": files,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return metadata


def parse_json_records(text):
    if text.lstrip().startswith("["):
        items = json.loads(text)
        records = [item for item in items if isinstance(item, dict)]
        return records, len(items) - len(records)
    decoder = json.JSONDecoder()
    whitespace = re.compile(r"\s*")
    records, malformed = [], 0
    position = whitespace.match(text, 0).end()
    while position < len(text):
        try:
            item, position = decoder.raw_decode(text, position)
            if isinstance(item, dict):
                records.append(item)
            else:
                malformed += 1
        except json.JSONDecodeError:
            malformed += 1
            newline = text.find("\n", position)
            position = len(text) if newline == -1 else newline + 1
        position = whitespace.match(text, position).end()
    return records, malformed


def load_deepnlp_records(metadata, raw_dir=RAW_DIR):
    records, malformed = [], 0
    for file_info in metadata["files"]:
        parsed, bad = parse_json_records((raw_dir / file_info["file_name"]).read_text(encoding="utf-8"))
        malformed += bad
        records += [
            {**record, "source_file": file_info["file_name"], "source_record_number": number}
            for number, record in enumerate(parsed, start=1)
        ]
    return records, malformed


def standardize_column_name(name):
    return re.sub(r"[^0-9a-z]+", "_", name.strip().lower()).strip("_")


def flatten_records(records):
    frame = pd.json_normalize(records, sep="_")
    frame.columns = [standardize_column_name(column) for column in frame.columns]
    return frame


def normalize_whitespace(value):
    return re.sub(r"\s+", " ", value).strip() if isinstance(value, str) else value


def normalize_null(value):
    if isinstance(value, str):
        return None if value.strip().lower() in NULL_PLACEHOLDERS else value
    return None if pd.isna(value) else value


def clean_description(value):
    if not isinstance(value, str):
        return None
    text = LEADING_MARKERS.sub("", value).strip()
    return text if re.search(r"[^\W_]", text) else None


def description_quality(original, cleaned):
    if not isinstance(cleaned, str):
        return "missing"
    if BOILERPLATE_PATTERN.search(cleaned):
        return "web_boilerplate"
    if re.match(r"[:;,.)\]]", str(original).strip()) or cleaned[0].islower():
        return "fragment"
    if len(cleaned.split()) < 3:
        return "too_short"
    return "ok"


def normalize_url(value):
    if not isinstance(value, str) or not value.strip():
        return None
    parts = urlsplit(value.strip())
    host = parts.netloc.lower().removeprefix("www.")
    return urlunsplit((parts.scheme.lower(), host, parts.path.rstrip("/"), parts.query, ""))


def is_valid_url(value):
    if not isinstance(value, str) or " " in value:
        return False
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and "." in parts.netloc


def parse_github_url(url):
    result = {
        "github_url_type": "not_github", "github_owner": None, "github_repo": None, "github_ref": None,
        "github_subpath": None, "repository_id": None, "repository_url": None,
    }
    if not isinstance(url, str):
        return result
    parts = urlsplit(url.strip())
    if parts.netloc.lower().removeprefix("www.") != "github.com":
        return result
    segments = [segment for segment in parts.path.split("/") if segment]
    if len(segments) < 2:
        return {**result, "github_url_type": "owner_only" if segments else "invalid", "github_owner": segments[0] if segments else None}
    owner, repo = segments[0], segments[1].removesuffix(".git")
    ref = subpath = None
    if len(segments) >= 4 and segments[2] in ("tree", "blob"):
        ref = segments[3]
        subpath = "/".join(segments[4:-1] if segments[2] == "blob" else segments[4:]) or None
    return {
        "github_url_type": "repository_subpath" if subpath else "repository",
        "github_owner": owner, "github_repo": repo, "github_ref": ref, "github_subpath": subpath,
        "repository_id": f"github:{owner.lower()}/{repo.lower()}",
        "repository_url": f"https://github.com/{owner.lower()}/{repo.lower()}",
    }


def registry_repository_id(value):
    if isinstance(value, dict):
        value = value.get("url")
    if not isinstance(value, str) or not value.strip():
        return None
    text = re.sub(r"^git\+", "", value.strip())
    text = re.sub(r"^(?:ssh://)?git@github\.com[:/]", "https://github.com/", text)
    text = re.sub(r"^(?:github:|git://github\.com/)", "https://github.com/", text)
    if re.fullmatch(r"[\w.-]+/[\w.-]+", text):
        text = f"https://github.com/{text}"
    return parse_github_url(text)["repository_id"]


def normalize_ecosystem(value):
    return ECOSYSTEM_ALIASES.get(value.strip().lower()) if isinstance(value, str) else None


def normalize_package_name(name, ecosystem):
    if not isinstance(name, str) or not name.strip():
        return None
    return canonicalize_name(name.strip()) if ecosystem == "PyPI" else name.strip().lower()


def name_key(name):
    tokens = re.sub(r"[^0-9a-z]+", " ", str(name).lower()).split()
    return "".join(token for token in tokens if token not in NAME_STOPWORDS) or None


def count_changed(before, after):
    return int(sum(not ((pd.isna(a) and pd.isna(b)) or a == b) for a, b in zip(before, after)))


def log_step(log, step, column, affected, action):
    log.append({"step": step, "column": column, "records_affected": int(affected), "action": action})


def exact_duplicates(raw_frame):
    content_columns = [column for column in raw_frame.columns if column not in ("source_file", "source_record_number")]
    return raw_frame[content_columns].astype(str).duplicated(keep="first")


def possible_duplicate_groups(frame):
    name_keys = frame["server_name"].map(name_key)
    shared_name = name_keys.notna() & name_keys.duplicated(keep=False)
    shared_site = frame["website_normalized"].notna() & frame["website_normalized"].duplicated(keep=False)
    group = ("name:" + name_keys).where(shared_name)
    return group.mask(shared_site, "website:" + frame["website_normalized"])


def normalize_text_columns(frame, columns, log):
    for column in columns:
        trimmed = frame[column].map(normalize_whitespace)
        log_step(log, "normalize_whitespace", column, count_changed(frame[column], trimmed), "modified")
        nulled = trimmed.map(normalize_null)
        log_step(log, "placeholder_to_null", column, nulled.isna().sum() - trimmed.isna().sum(), "modified")
        frame[column] = nulled
    return frame


def clean_servers(raw_frame, collected_at):
    exact = exact_duplicates(raw_frame)
    frame = raw_frame.copy()
    if "statistic_bing_rank" not in frame:
        frame["statistic_bing_rank"] = None
    frame = frame.rename(columns=SERVER_COLUMNS)
    log = []
    frame["website_original"] = frame["website_url"]
    frame["description_original"] = frame["description"]
    frame = normalize_text_columns(frame, [column for column in TEXT_COLUMNS if column in frame], log)
    described = frame["description"].map(clean_description)
    log_step(log, "strip_leading_list_markers", "description", count_changed(frame["description"], described), "modified")
    frame["description"] = described
    frame["description_quality"] = [description_quality(o, c) for o, c in zip(frame["description_original"], frame["description"])]
    log_step(log, "flag_low_quality_description", "description", (frame["description_quality"] != "ok").sum(), "flagged")
    empty_columns = [column for column in TEXT_COLUMNS if column in frame and frame[column].isna().all()]
    for column in empty_columns:
        log_step(log, "drop_empty_column", column, len(frame), "removed_column")
    frame = frame.drop(columns=empty_columns)

    frame["website_normalized"] = frame["website_url"].map(normalize_url)
    frame["website_host"] = frame["website_normalized"].map(lambda url: urlsplit(url).netloc if isinstance(url, str) else None)
    frame["website_is_valid"] = frame["website_url"].map(is_valid_url)
    log_step(log, "normalize_url", "website_url", count_changed(frame["website_url"], frame["website_normalized"]), "modified")
    log_step(log, "flag_invalid_url", "website_url", (~frame["website_is_valid"]).sum(), "flagged")
    github = pd.DataFrame([parse_github_url(url) for url in frame["website_url"]], index=frame.index)
    frame = pd.concat([frame, github], axis=1)
    frame["website_is_github"] = frame["github_url_type"] != "not_github"
    log_step(log, "extract_github_reference", "website_url", frame["repository_id"].notna().sum(), "modified")
    log_step(log, "flag_ambiguous_github_reference", "website_url", (frame["github_url_type"] == "owner_only").sum(), "flagged")

    months = pd.to_datetime(frame["snapshot_month"], format="%Y%m", errors="coerce")
    log_step(log, "convert_to_date", "snapshot_month", months.notna().sum(), "modified")
    log_step(log, "flag_invalid_date", "snapshot_month", (months.isna() & frame["snapshot_month"].notna()).sum(), "flagged")
    frame["snapshot_month"] = months.dt.strftime("%Y-%m-%d")
    frame["bing_rank"] = pd.to_numeric(frame["bing_rank"], errors="coerce")
    frame["server_name_is_generic"] = frame["server_name"].str.lower().isin(GENERIC_LINK_NAMES)
    log_step(log, "flag_generic_link_text_name", "server_name", frame["server_name_is_generic"].sum(), "flagged")

    frame["server_id"] = "deepnlp:" + frame["publisher_id"].fillna("record-" + frame["source_record_number"].astype(str))
    group = possible_duplicate_groups(frame)
    duplicate_id = frame["server_id"].duplicated(keep="first")
    frame["possible_duplicate_group"] = group
    log_step(log, "flag_possible_semantic_duplicate", "server_name", group.notna().sum(), "flagged")
    log_step(log, "remove_exact_duplicate", "all", exact.sum(), "removed")
    log_step(log, "remove_duplicate_server_id", "server_id", (duplicate_id & ~exact).sum(), "removed")
    frame = frame[~(exact | duplicate_id)].copy()
    frame["source"] = "deepnlp_huggingface"
    frame["collected_at"] = collected_at
    columns = [
        "server_id", "source_file", "source_record_number", "publisher_id", "server_name", "server_name_is_generic",
        "website_url", "website_original", "website_normalized", "website_host", "website_is_valid", "website_is_github",
        "github_url_type", "github_owner", "github_repo", "github_ref", "github_subpath", "repository_id",
        "repository_url", "description", "description_original", "description_quality", "field", "sub_field",
        "snapshot_month", "bing_rank", "possible_duplicate_group", "source", "collected_at",
    ]
    return frame[columns].reset_index(drop=True), pd.DataFrame(log)


def github_request(path):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", **auth_header("GITHUB_TOKEN")}
    return request_json("GET", f"{GITHUB_API}{path}", headers=headers)


def fetch_repositories(servers):
    targets = servers.dropna(subset=["repository_id"]).drop_duplicates("repository_id")
    rows, bodies = [], []
    for number, target in enumerate(targets.itertuples(index=False), start=1):
        result = github_request(f"/repos/{quote(target.github_owner, safe='')}/{quote(target.github_repo, safe='')}")
        rows.append({
            "repository_id": target.repository_id, "repository_url": target.repository_url,
            "lookup_status": lookup_status(result), "http_status": result["status"],
            "lookup_error": result["error"], "collected_at": result["fetched_at"],
        })
        bodies.append(result["body"] if isinstance(result["body"], dict) else {})
        if number % 25 == 0 or number == len(targets):
            print(f"  GitHub repositories: {number}/{len(targets)}")
    details = pd.json_normalize(bodies, sep="_").reindex(columns=list(REPOSITORY_FIELDS)).rename(columns=REPOSITORY_FIELDS)
    repositories = pd.concat([pd.DataFrame(rows), details], axis=1)
    found = repositories["lookup_status"] == "found"
    canonical = "github:" + repositories["full_name"].str.lower()
    repositories["repository_moved"] = (found & (canonical != repositories["repository_id"])).astype("boolean").where(found)
    for column in ("archived", "is_fork"):
        repositories[column] = repositories[column].astype("boolean")
    pushed = pd.to_datetime(repositories["pushed_at"], utc=True, errors="coerce")
    collected = pd.to_datetime(repositories["collected_at"], utc=True, errors="coerce")
    repositories["days_since_last_push"] = (collected - pushed).dt.days.astype("Int64")
    for column in ("stars", "forks", "open_issues", "http_status"):
        repositories[column] = repositories[column].astype("Int64")
    repositories["source"] = "github_rest_api"
    return repositories


def fetch_manifests(servers, repositories):
    full_names = repositories[repositories["lookup_status"] == "found"].set_index("repository_id")["full_name"]
    statuses = repositories.set_index("repository_id")["lookup_status"]
    rows, manifests = [], {}
    for server in servers.dropna(subset=["repository_id"]).itertuples(index=False):
        row = {
            "server_id": server.server_id, "repository_id": server.repository_id, "github_ref": server.github_ref,
            "github_subpath": server.github_subpath, "manifest_files": None, "unsupported_manifest_files": None,
            "manifest_fetch_errors": None, "collected_at": None, "source": "github_rest_api",
        }
        if server.repository_id not in full_names:
            rows.append({**row, "location_status": "repository_" + statuses[server.repository_id]})
            continue
        base = f"/repos/{full_names[server.repository_id]}/contents"
        if pd.notna(server.github_subpath):
            base += "/" + quote(server.github_subpath)
        query = f"?ref={quote(server.github_ref, safe='')}" if pd.notna(server.github_ref) else ""
        listing = github_request(base + query)
        row["collected_at"] = listing["fetched_at"]
        if listing["status"] != 200 or not isinstance(listing["body"], list):
            rows.append({**row, "location_status": "location_not_found" if listing["status"] in (200, 404) else "lookup_failed"})
            continue
        names = {item.get("name") for item in listing["body"] if item.get("type") == "file"}
        found = [name for name in SUPPORTED_MANIFESTS if name in names]
        files, errors = {}, []
        for name in found:
            result = github_request(f"{base}/{quote(name)}{query}")
            try:
                files[name] = base64.b64decode(result["body"]["content"]).decode("utf-8")
            except (TypeError, KeyError, ValueError):
                errors.append(name)
        manifests[server.server_id] = {"files": files, "collected_at": listing["fetched_at"]}
        rows.append({
            **row, "location_status": "manifests_checked", "manifest_files": "; ".join(found) or None,
            "unsupported_manifest_files": "; ".join(name for name in UNSUPPORTED_MANIFESTS if name in names) or None,
            "manifest_fetch_errors": "; ".join(errors) or None,
        })
    columns = [
        "server_id", "repository_id", "github_ref", "github_subpath", "location_status", "manifest_files",
        "unsupported_manifest_files", "manifest_fetch_errors", "source", "collected_at",
    ]
    return pd.DataFrame(rows, columns=columns), manifests


def fetch_repository_activity(repositories):
    full_names = repositories.loc[repositories["lookup_status"] == "found", "full_name"].drop_duplicates()
    rows = []
    for number, full_name in enumerate(full_names, start=1):
        commits = github_request(f"/repos/{full_name}/commits?per_page=1")
        contributors = github_request(f"/repos/{full_name}/contributors?per_page=1&anon=true")
        releases = github_request(f"/repos/{full_name}/releases?per_page=1")
        latest_commit = commits["body"][0] if page_count(commits) else {}
        latest_release = releases["body"][0] if page_count(releases) else {}
        rows.append({
            "full_name": full_name, "commit_count": page_count(commits),
            "last_commit_at": ((latest_commit.get("commit") or {}).get("committer") or {}).get("date"),
            "contributor_count": page_count(contributors), "release_count": page_count(releases),
            "latest_release_tag": latest_release.get("tag_name"), "latest_release_at": latest_release.get("published_at"),
        })
        if number % 25 == 0 or number == len(full_names):
            print(f"  GitHub activity: {number}/{len(full_names)}")
    activity = pd.DataFrame(rows, columns=[
        "full_name", "commit_count", "last_commit_at", "contributor_count", "release_count", "latest_release_tag", "latest_release_at",
    ])
    result = repositories.drop(columns="source").merge(activity, on="full_name", how="left")
    last_commit = pd.to_datetime(result["last_commit_at"], utc=True, errors="coerce")
    result["days_since_last_commit"] = (pd.to_datetime(result["collected_at"], utc=True) - last_commit).dt.days.astype("Int64")
    for column in ("commit_count", "contributor_count", "release_count"):
        result[column] = result[column].astype("Int64")
    result["source"] = "github_rest_api"
    return result


def clean_markdown(text):
    if not isinstance(text, str):
        return None
    for pattern, replacement in MARKDOWN_PATTERNS:
        text = pattern.sub(replacement, text)
    return normalize_null(normalize_whitespace(html.unescape(text)))


def document_row(document_id, document_type, raw_text, filter_reason, result, **metadata):
    cleaned = clean_markdown(raw_text)
    if filter_reason is None and (cleaned is None or len(cleaned) < MIN_DOCUMENT_CHARS):
        filter_reason = "empty_or_too_short"
    return {
        "document_id": document_id, "document_type": document_type, "server_id": None, "repository_id": None,
        "title": None, "source_url": None, "published_at": None, **metadata,
        "raw_char_count": len(raw_text or ""), "cleaned_char_count": len(cleaned or ""), "word_count": len((cleaned or "").split()),
        "filter_reason": filter_reason, "cleaned_text": cleaned, "source": "github_rest_api", "collected_at": result["fetched_at"],
    }


def fetch_documents(server_repository_map, repositories):
    full_names = repositories[repositories["lookup_status"] == "found"].set_index("repository_id")["full_name"]
    rows = []
    checked = server_repository_map[server_repository_map["location_status"] == "manifests_checked"]
    for location in checked.itertuples(index=False):
        path = f"/repos/{full_names[location.repository_id]}/readme"
        path += f"/{quote(location.github_subpath)}" if pd.notna(location.github_subpath) else ""
        path += f"?ref={quote(location.github_ref, safe='')}" if pd.notna(location.github_ref) else ""
        result = github_request(path)
        body = result["body"] if result["status"] == 200 and isinstance(result["body"], dict) else {}
        try:
            raw_text = base64.b64decode(body["content"]).decode("utf-8")
        except (KeyError, TypeError, ValueError):
            raw_text = None
        rows.append(document_row(
            f"readme:{location.server_id}", "readme", raw_text, None if body else "not_available", result,
            server_id=location.server_id, repository_id=location.repository_id, title=body.get("path"), source_url=body.get("html_url"),
        ))
    for repository_id, full_name in full_names.items():
        releases = github_request(f"/repos/{full_name}/releases?per_page=1")
        for release in (releases["body"] if page_count(releases) else [])[:1]:
            rows.append(document_row(
                f"release:{repository_id}:{release.get('tag_name')}", "release_notes", release.get("body"), None, releases,
                repository_id=repository_id, title=release.get("name") or release.get("tag_name"),
                source_url=release.get("html_url"), published_at=release.get("published_at"),
            ))
        issues = github_request(f"/repos/{full_name}/issues?state=all&sort=updated&per_page={ISSUES_PER_REPOSITORY}")
        for issue in issues["body"] if isinstance(issues["body"], list) else []:
            reason = "pull_request" if "pull_request" in issue else "bot_author" if (issue.get("user") or {}).get("type") == "Bot" else None
            rows.append(document_row(
                f"issue:{repository_id}#{issue.get('number')}", "issue", f"{issue.get('title') or ''}\n\n{issue.get('body') or ''}",
                reason, issues, repository_id=repository_id, title=issue.get("title"), source_url=issue.get("html_url"),
                published_at=issue.get("created_at"),
            ))
    return pd.DataFrame(rows, columns=[
        "document_id", "document_type", "server_id", "repository_id", "title", "source_url", "published_at", "raw_char_count",
        "cleaned_char_count", "word_count", "filter_reason", "cleaned_text", "source", "collected_at",
    ])


def exact_version(spec):
    match = EXACT_VERSION.fullmatch(spec.strip()) if isinstance(spec, str) else None
    return match.group(1) if match else None


def python_dependency(line):
    try:
        requirement = Requirement(line)
    except InvalidRequirement:
        return {"ecosystem": "PyPI", "dependency_name": None, "version_spec": line.strip(), "pinned_version": None}
    specifiers = list(requirement.specifier)
    single = specifiers[0] if len(specifiers) == 1 else None
    pinned = single.version if single and single.operator in ("==", "===") and "*" not in single.version else None
    return {
        "ecosystem": "PyPI", "dependency_name": canonicalize_name(requirement.name),
        "version_spec": str(requirement.specifier) or None, "pinned_version": pinned,
    }


def named_dependency(name, spec, ecosystem):
    spec = spec.get("version") if isinstance(spec, dict) else spec
    spec = spec if isinstance(spec, str) else None
    return {
        "ecosystem": ecosystem, "dependency_name": normalize_package_name(name, ecosystem),
        "version_spec": spec, "pinned_version": exact_version(spec),
    }


def requirement_lines(text):
    lines = [line.split(" #")[0].rstrip("\\").strip() for line in text.splitlines()]
    return [line for line in lines if line and not line.startswith(("#", "-"))]


def parse_manifest(file_name, text):
    package, dependencies = None, []
    if file_name == "package.json":
        data = json.loads(text)
        if data.get("name") and not data.get("private"):
            package = {"ecosystem": "npm", "declared_name": data["name"], "declared_version": data.get("version")}
        dependencies = [named_dependency(name, spec, "npm") for name, spec in (data.get("dependencies") or {}).items()]
    elif file_name == "pyproject.toml":
        data = tomllib.loads(text)
        project = data.get("project", {})
        poetry = data.get("tool", {}).get("poetry", {})
        name = project.get("name") or poetry.get("name")
        if name:
            package = {"ecosystem": "PyPI", "declared_name": name, "declared_version": project.get("version") or poetry.get("version")}
        dependencies = [python_dependency(line) for line in project.get("dependencies", [])]
        dependencies += [
            named_dependency(dep, spec, "PyPI") for dep, spec in poetry.get("dependencies", {}).items() if dep.lower() != "python"
        ]
    elif file_name == "setup.cfg":
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(text)
        name = parser.get("metadata", "name", fallback=None)
        version = parser.get("metadata", "version", fallback="")
        if name:
            literal = version.strip() if version.strip() and not version.strip().startswith(("attr:", "file:")) else None
            package = {"ecosystem": "PyPI", "declared_name": name, "declared_version": literal}
        dependencies = [python_dependency(line) for line in requirement_lines(parser.get("options", "install_requires", fallback=""))]
    elif file_name == "requirements.txt":
        dependencies = [python_dependency(line) for line in requirement_lines(text)]
    return package, dependencies


def extract_packages(manifests):
    candidates, dependencies, errors = [], [], []
    for server_id, manifest in manifests.items():
        for file_name, text in manifest["files"].items():
            try:
                package, declared = parse_manifest(file_name, text)
            except (ValueError, TypeError, AttributeError, configparser.Error):
                errors.append({"server_id": server_id, "manifest_file": file_name})
                continue
            if package:
                name = normalize_package_name(package["declared_name"], package["ecosystem"])
                candidates.append({
                    "server_id": server_id, "manifest_file": file_name, "package_id": f"{package['ecosystem']}:{name}",
                    "package_name": name, **package, "candidate_source": "repository_manifest",
                })
            dependencies += [
                {"server_id": server_id, "manifest_file": file_name, **item, "collected_at": manifest["collected_at"]} for item in declared
            ]
    candidate_columns = [
        "server_id", "manifest_file", "package_id", "ecosystem", "package_name", "declared_name", "declared_version", "candidate_source",
    ]
    dependency_columns = ["server_id", "manifest_file", "ecosystem", "dependency_name", "version_spec", "pinned_version", "collected_at"]
    candidates = pd.DataFrame(candidates, columns=candidate_columns).drop_duplicates(["server_id", "package_id"])
    dependencies = pd.DataFrame(dependencies, columns=dependency_columns)
    return candidates.reset_index(drop=True), dependencies, pd.DataFrame(errors, columns=["server_id", "manifest_file"])


def attach_parse_errors(server_repository_map, parse_errors):
    errors = parse_errors.groupby("server_id")["manifest_file"].agg("; ".join)
    result = server_repository_map.copy()
    result.insert(result.columns.get_loc("source"), "manifest_parse_errors", result["server_id"].map(errors))
    return result


def lookup_registry(ecosystem, name):
    if ecosystem == "PyPI":
        result = request_json("GET", f"{PYPI_API}/{quote(name, safe='')}/json")
    else:
        result = request_json("GET", f"{NPM_REGISTRY}/{quote(name, safe='@')}")
    record = {column: None for column in PACKAGE_COLUMNS}
    record.update({
        "package_id": f"{ecosystem}:{name}", "ecosystem": ecosystem, "package_name": name,
        "registry_status": lookup_status(result), "http_status": result["status"],
        "source": "pypi_json_api" if ecosystem == "PyPI" else "npm_registry", "collected_at": result["fetched_at"],
    })
    body = result["body"] if isinstance(result["body"], dict) else None
    if record["registry_status"] != "found" or body is None:
        return record, set()
    if ecosystem == "PyPI":
        info = body.get("info") or {}
        urls = info.get("project_urls") or {}
        links = [info.get("home_page"), info.get("download_url"), *urls.values()]
        versions = {version for version, files in (body.get("releases") or {}).items() if files}
        latest, summary, dependencies = info.get("version"), info.get("summary"), info.get("requires_dist") or []
    else:
        latest = (body.get("dist-tags") or {}).get("latest")
        latest_document = (body.get("versions") or {}).get(latest) or {}
        urls = {"homepage": body.get("homepage"), "repository": body.get("repository")}
        links = [body.get("repository"), latest_document.get("repository"), body.get("homepage")]
        versions = set(body.get("versions") or {})
        summary = body.get("description")
        dependencies = [f"{dep}@{spec}" for dep, spec in (latest_document.get("dependencies") or {}).items()]
    repository_ids = {registry_repository_id(link) for link in links} - {None}
    record.update({
        "latest_version": latest, "release_count": len(versions), "summary": normalize_whitespace(summary),
        "project_urls": json.dumps(urls, sort_keys=True), "registry_repository_ids": "; ".join(sorted(repository_ids)) or None,
        "latest_dependencies": "; ".join(dependencies) or None,
    })
    return record, versions


def identify_version(declared, available, latest, declared_source="repository_manifest"):
    if isinstance(declared, str) and declared in available:
        return declared, declared_source
    if isinstance(latest, str) and latest:
        return latest, "registry_latest"
    return None, None


def package_mapping_status(registry_status, registry_ids, accepted_ids, listed_in_mcp_registry=False):
    if registry_status == "not_found":
        return "not_published"
    if registry_status != "found":
        return "lookup_failed"
    return "verified" if listed_in_mcp_registry or registry_ids & accepted_ids else "ambiguous"


def is_valid_package_name(name, ecosystem):
    pattern = PYPI_NAME if ecosystem == "PyPI" else NPM_NAME
    return isinstance(name, str) and bool(pattern.fullmatch(name))


def is_valid_version(version, ecosystem):
    if not isinstance(version, str):
        return False
    if ecosystem != "PyPI":
        return bool(SEMVER.fullmatch(version))
    try:
        Version(version)
        return True
    except InvalidVersion:
        return False


def resolve_repository_id(repository_id):
    owner, repo = repository_id.removeprefix("github:").split("/", 1)
    result = github_request(f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}")
    body = result["body"] if result["status"] == 200 and isinstance(result["body"], dict) else {}
    return f"github:{body['full_name'].lower()}" if body.get("full_name") else None


def enrich_packages(candidates, repositories, server_repository_map):
    canonical = ("github:" + repositories["full_name"].str.lower()).where(repositories["full_name"].notna())
    canonical = dict(zip(repositories["repository_id"], canonical))
    accepted = {
        row.server_id: {row.repository_id, canonical.get(row.repository_id)} - {None}
        for row in server_repository_map.itertuples(index=False)
    }
    records, versions = {}, {}
    for package_id, ecosystem, name in candidates[["package_id", "ecosystem", "package_name"]].drop_duplicates().itertuples(index=False):
        records[package_id], versions[package_id] = lookup_registry(ecosystem, name)
    rows = []
    for candidate in candidates.itertuples(index=False):
        record = records[candidate.package_id]
        listed = candidate.candidate_source == "official_mcp_registry"
        linked_ids = set((record["registry_repository_ids"] or "").split("; ")) - {""}
        accepted_ids = accepted.get(candidate.server_id, set())
        direct_match = bool(linked_ids & accepted_ids)
        resolved_ids = set() if direct_match or listed else {resolve_repository_id(item) for item in linked_ids} - {None}
        mapping = package_mapping_status(record["registry_status"], linked_ids | resolved_ids, accepted_ids, listed)
        evidence, version, version_source = None, None, None
        if mapping == "verified":
            evidence = (
                "official_mcp_registry_lists_package" if listed
                else "registry_links_to_server_repository" if direct_match else "registry_link_redirects_to_server_repository"
            )
            version, version_source = identify_version(
                candidate.declared_version, versions[candidate.package_id], record["latest_version"], candidate.candidate_source,
            )
        rows.append({
            **candidate._asdict(), "mapping_status": mapping, "mapping_evidence": evidence,
            "declared_name_is_valid": is_valid_package_name(candidate.declared_name, candidate.ecosystem),
            "declared_version_is_valid": is_valid_version(candidate.declared_version, candidate.ecosystem),
            "declared_version_is_published": candidate.declared_version in versions[candidate.package_id],
            "identified_version": version, "version_source": version_source, "latest_version": record["latest_version"],
            "collected_at": record["collected_at"],
        })
    packages = pd.DataFrame(list(records.values()), columns=PACKAGE_COLUMNS)
    packages[["http_status", "release_count"]] = packages[["http_status", "release_count"]].astype("Int64")
    server_packages = pd.DataFrame(rows, columns=[
        "server_id", "package_id", "ecosystem", "package_name", "declared_name", "candidate_source", "manifest_file",
        "declared_version", "declared_name_is_valid", "declared_version_is_valid", "declared_version_is_published",
        "mapping_status", "mapping_evidence", "identified_version", "version_source", "latest_version", "collected_at",
    ])
    return packages, server_packages


def vulnerability_status(mapping_status, version, osv_status=None):
    if mapping_status == "ambiguous":
        return "ambiguous_mapping"
    if mapping_status in ("not_published", "unidentified"):
        return "unknown_package_identity"
    if mapping_status == "lookup_failed":
        return "api_failed"
    if not isinstance(version, str) or not version:
        return "unknown_version"
    return osv_status or "not_assessed"


def strongest_status(statuses):
    present = set(statuses)
    return next((status for status in STATUS_PRECEDENCE if status in present), None)


def query_osv(targets):
    statuses, matches = {}, []
    ordered = sorted(targets)
    for start in range(0, len(ordered), OSV_BATCH_SIZE):
        chunk = ordered[start:start + OSV_BATCH_SIZE]
        payload = {"queries": [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in chunk]}
        result = request_json("POST", f"{OSV_API}/querybatch", payload=payload)
        answers = (result["body"] or {}).get("results") if result["status"] == 200 else None
        for index, target in enumerate(chunk):
            if not isinstance(answers, list) or index >= len(answers):
                statuses[target] = {"osv_status": "api_failed", "osv_queried_at": result["fetched_at"]}
                continue
            ids = sorted({item["id"] for item in answers[index].get("vulns", [])})
            found = "known_vulnerabilities_found" if ids else "no_known_vulnerabilities_found"
            statuses[target] = {"osv_status": found, "osv_queried_at": result["fetched_at"]}
            matches += [(*target, vulnerability_id) for vulnerability_id in ids]
        print(f"  OSV batch queries: {min(start + OSV_BATCH_SIZE, len(ordered))}/{len(ordered)} targets")
    return statuses, matches


def group_vulnerability_aliases(alias_map):
    parent = {}

    def root(item):
        parent.setdefault(item, item)
        while parent[item] != item:
            item = parent[item]
        return item

    for vulnerability_id, aliases in alias_map.items():
        for alias in aliases:
            parent[root(alias)] = root(vulnerability_id)
    members = {}
    for vulnerability_id in alias_map:
        members.setdefault(root(vulnerability_id), []).append(vulnerability_id)
    return {member: min(group) for group in members.values() for member in group}


def fetch_vulnerability_details(vulnerability_ids):
    rows, bodies = [], {}
    for vulnerability_id in sorted(vulnerability_ids):
        result = request_json("GET", f"{OSV_API}/vulns/{quote(vulnerability_id, safe='')}")
        body = result["body"] if isinstance(result["body"], dict) else {}
        bodies[vulnerability_id] = body
        aliases = body.get("aliases") or []
        rows.append({
            "vulnerability_id": vulnerability_id, "lookup_status": lookup_status(result),
            "aliases": "; ".join(aliases) or None,
            "cve_ids": "; ".join(sorted({a for a in [vulnerability_id, *aliases] if a.startswith("CVE-")})) or None,
            "summary": normalize_whitespace(body.get("summary")),
            "severity_cvss": "; ".join(f"{s.get('type')}:{s.get('score')}" for s in body.get("severity") or []) or None,
            "severity_label": (body.get("database_specific") or {}).get("severity"),
            "affected_packages": "; ".join(sorted({
                f"{a['package'].get('ecosystem')}:{a['package'].get('name')}" for a in body.get("affected") or [] if a.get("package")
            })) or None,
            "published": body.get("published"), "modified": body.get("modified"), "withdrawn": body.get("withdrawn"),
            "source": "osv_api", "collected_at": result["fetched_at"],
        })
    groups = group_vulnerability_aliases({row["vulnerability_id"]: set((row["aliases"] or "").split("; ")) - {""} for row in rows})
    vulnerabilities = pd.DataFrame(rows, columns=[
        "vulnerability_id", "lookup_status", "aliases", "cve_ids", "summary", "severity_cvss", "severity_label",
        "affected_packages", "published", "modified", "withdrawn", "source", "collected_at",
    ])
    vulnerabilities.insert(1, "vulnerability_group_id", vulnerabilities["vulnerability_id"].map(groups))
    return vulnerabilities, bodies


def fixed_versions(body, ecosystem, name):
    fixed = set()
    for affected in body.get("affected") or []:
        package = affected.get("package") or {}
        if normalize_ecosystem(package.get("ecosystem")) == ecosystem and normalize_package_name(package.get("name"), ecosystem) == name:
            fixed |= {event["fixed"] for r in affected.get("ranges") or [] for event in r.get("events") or [] if "fixed" in event}
    return "; ".join(sorted(fixed)) or None


def vulnerability_groups_by_target(package_vulnerabilities):
    columns = ["ecosystem", "package_name", "package_version"]
    return package_vulnerabilities.groupby(columns)["vulnerability_group_id"].agg(set).to_dict()


def fetch_dependency_graphs(server_packages):
    verified = server_packages[server_packages["mapping_status"].eq("verified") & server_packages["identified_version"].notna()]
    targets = verified[["ecosystem", "package_name", "identified_version"]].drop_duplicates()
    rows, statuses = [], {}
    for ecosystem, name, version in targets.itertuples(index=False, name=None):
        url = f"{DEPS_DEV_API}/systems/{ecosystem.lower()}/packages/{quote(name, safe='')}/versions/{quote(version, safe='')}:dependencies"
        result = request_json("GET", url)
        statuses[(ecosystem, name, version)] = lookup_status(result)
        nodes = result["body"].get("nodes") or [] if isinstance(result["body"], dict) else []
        for node in nodes:
            key = node.get("versionKey") or {}
            if node.get("relation") == "SELF" or not key.get("name"):
                continue
            dependency_ecosystem = normalize_ecosystem(key.get("system")) or ecosystem
            rows.append({
                "ecosystem": ecosystem, "package_name": name, "package_version": version,
                "dependency_ecosystem": dependency_ecosystem,
                "dependency_name": normalize_package_name(key.get("name"), dependency_ecosystem),
                "dependency_version": key.get("version"), "relation": (node.get("relation") or "").lower() or None,
                "source": "deps_dev_api", "collected_at": result["fetched_at"],
            })
    resolved = pd.DataFrame(rows, columns=[
        "ecosystem", "package_name", "package_version", "dependency_ecosystem", "dependency_name", "dependency_version",
        "relation", "source", "collected_at",
    ]).drop_duplicates(["ecosystem", "package_name", "package_version", "dependency_ecosystem", "dependency_name", "dependency_version"])
    server_packages = server_packages.copy()
    server_packages["dependency_graph_status"] = [
        statuses.get(key) for key in zip(server_packages["ecosystem"], server_packages["package_name"], server_packages["identified_version"])
    ]
    return server_packages, resolved.reset_index(drop=True)


def annotate_osv(frame, name_column, version_column, osv_results, target_groups, ecosystem_column="ecosystem"):
    keys = list(zip(frame[ecosystem_column], frame[name_column], frame[version_column]))
    frame["osv_status"] = [
        vulnerability_status(mapping, version, osv_results.get(key, {}).get("osv_status"))
        for mapping, version, key in zip(frame["mapping_status"], frame[version_column], keys)
    ]
    frame["known_vulnerability_count"] = pd.array(
        [len(target_groups.get(key, set())) if status in ASSESSED_STATUSES else None for key, status in zip(keys, frame["osv_status"])],
        dtype="Int64",
    )
    frame["osv_queried_at"] = [osv_results.get(key, {}).get("osv_queried_at") for key in keys]
    return frame


def enrich_vulnerabilities(server_packages, dependencies, resolved):
    dependencies = dependencies.copy()
    dependencies["mapping_status"] = dependencies["dependency_name"].notna().map({True: "declared", False: "unidentified"})
    resolved = resolved.copy()
    resolved["mapping_status"] = "resolved"
    package_targets = server_packages[server_packages["mapping_status"].eq("verified") & server_packages["identified_version"].notna()]
    dependency_targets = dependencies[dependencies["dependency_name"].notna() & dependencies["pinned_version"].notna()]
    targets = set(zip(package_targets["ecosystem"], package_targets["package_name"], package_targets["identified_version"]))
    targets |= set(zip(dependency_targets["ecosystem"], dependency_targets["dependency_name"], dependency_targets["pinned_version"]))
    targets |= set(zip(resolved["dependency_ecosystem"], resolved["dependency_name"], resolved["dependency_version"]))
    osv_results, matches = query_osv(targets)
    vulnerabilities, bodies = fetch_vulnerability_details({match[3] for match in matches})
    groups = dict(zip(vulnerabilities["vulnerability_id"], vulnerabilities["vulnerability_group_id"]))
    package_vulnerabilities = pd.DataFrame(matches, columns=["ecosystem", "package_name", "package_version", "vulnerability_id"])
    package_vulnerabilities["vulnerability_group_id"] = package_vulnerabilities["vulnerability_id"].map(groups)
    package_vulnerabilities["fixed_versions"] = [
        fixed_versions(bodies.get(row.vulnerability_id, {}), row.ecosystem, row.package_name)
        for row in package_vulnerabilities.itertuples(index=False)
    ]
    package_vulnerabilities["source"] = "osv_api"
    target_keys = package_vulnerabilities[["ecosystem", "package_name", "package_version"]].itertuples(index=False, name=None)
    package_vulnerabilities["collected_at"] = [osv_results[key]["osv_queried_at"] for key in target_keys]
    target_groups = vulnerability_groups_by_target(package_vulnerabilities)
    server_packages = annotate_osv(server_packages.copy(), "package_name", "identified_version", osv_results, target_groups)
    dependencies = annotate_osv(dependencies, "dependency_name", "pinned_version", osv_results, target_groups)
    dependencies = dependencies.sort_values(["server_id", "manifest_file", "ecosystem", "dependency_name"], na_position="last")
    dependencies.insert(0, "dependency_id", [f"dep-{number:05d}" for number in range(1, len(dependencies) + 1)])
    dependencies["source"] = "github_rest_api"
    resolved = annotate_osv(resolved, "dependency_name", "dependency_version", osv_results, target_groups, "dependency_ecosystem")
    resolved = resolved.drop(columns="mapping_status")
    tables = (server_packages, dependencies.reset_index(drop=True), resolved, package_vulnerabilities, vulnerabilities)
    return (*tables, osv_results)


def github_status(row):
    if row["github_url_type"] in ("not_github", "invalid"):
        return "not_github"
    if row["github_url_type"] == "owner_only":
        return "ambiguous_owner_only_url"
    return {
        "manifests_checked": "mapped", "location_not_found": "subpath_not_found",
        "repository_not_found": "repository_not_found",
    }.get(row["location_status"], "lookup_failed")


def summarize_security(server, packages, dependencies, resolved, osv_results, target_groups):
    pinned = dependencies.dropna(subset=["dependency_name", "pinned_version"])
    pinned_keys = set(zip(pinned["ecosystem"], pinned["dependency_name"], pinned["pinned_version"]))
    resolved_keys = set(zip(resolved["dependency_ecosystem"], resolved["dependency_name"], resolved["dependency_version"]))
    dependency_keys = pinned_keys | resolved_keys
    dependency_statuses = {key: (osv_results.get(key) or {}).get("osv_status") for key in dependency_keys}
    assessed = [key for key, status in dependency_statuses.items() if status in ASSESSED_STATUSES]
    package_keys = zip(packages["ecosystem"], packages["package_name"], packages["identified_version"])
    package_groups = set().union(*[target_groups.get(key, set()) for key in package_keys])
    dependency_groups = set().union(*[target_groups.get(key, set()) for key in dependency_keys])
    package_assessed = bool(packages["osv_status"].isin(ASSESSED_STATUSES).any())
    statuses = list(packages["osv_status"]) + list(dependencies["osv_status"]) + list(resolved["osv_status"])
    fallback = "unknown_package_identity" if server["github_status"] == "mapped" else "not_assessed"
    scope = {(True, True): "package_and_dependencies", (True, False): "package_only", (False, True): "dependencies_only"}
    return {
        "package_vulnerability_status": strongest_status(packages["osv_status"]) or fallback,
        "package_known_vulnerability_count": len(package_groups) if package_assessed else None,
        "declared_dependency_count": dependencies.dropna(subset=["dependency_name"]).drop_duplicates(["ecosystem", "dependency_name"]).shape[0],
        "pinned_dependency_count": len(pinned_keys),
        "resolved_dependency_count": len(resolved_keys),
        "dependencies_assessed": len(assessed),
        "vulnerable_dependency_count": sum(status == "known_vulnerabilities_found" for status in dependency_statuses.values()),
        "dependency_known_vulnerability_count": len(dependency_groups) if assessed else None,
        "known_vulnerability_count": len(package_groups | dependency_groups) if package_assessed or assessed else None,
        "assessment_scope": scope.get((package_assessed, bool(assessed)), "none"),
        "vulnerability_assessment_status": strongest_status(statuses) or fallback,
    }


def summarize_sources(server_source_map, corpus):
    registry = server_source_map[server_source_map["linked_source"] == "official_mcp_registry"].groupby("server_id").agg(
        registry_names=("linked_record_id", join_values), registry_match_status=("match_status", "first"),
    )
    corpus_matches = server_source_map[server_source_map["linked_source"] == "mcpcorpus"].merge(
        corpus[["corpus_id", "category", "tool_count"]], left_on="linked_record_id", right_on="corpus_id",
    )
    corpus_summary = corpus_matches.groupby("server_id").agg(
        corpus_ids=("linked_record_id", join_values), corpus_match_status=("match_status", "first"),
        corpus_category=("category", lambda values: values.dropna().iloc[0] if values.dropna().nunique() == 1 else None),
        corpus_tool_count=("tool_count", "max"),
    )
    return registry.join(corpus_summary, how="outer")


def join_values(values):
    values = [str(value) for value in values if pd.notna(value)]
    return "; ".join(values) or None


def build_enriched(tables, osv_results):
    servers, repositories, server_repository_map = tables["mcp_servers"], tables["repositories"], tables["server_repository_map"]
    server_packages, dependencies, resolved = tables["server_package_map"], tables["dependencies"], tables["resolved_dependencies"]
    repository_columns = [
        "repository_id", "lookup_status", "full_name", "stars", "forks", "open_issues", "archived", "is_fork",
        "primary_language", "license", "created_at", "pushed_at", "days_since_last_push", "repository_moved",
        "commit_count", "last_commit_at", "days_since_last_commit", "contributor_count", "release_count", "latest_release_at",
    ]
    enriched = servers.drop(columns=["website_original", "description_original", "source", "collected_at"])
    enriched = enriched.merge(server_repository_map[["server_id", "location_status", "manifest_files", "unsupported_manifest_files"]], on="server_id", how="left")
    enriched = enriched.merge(
        repositories[repository_columns].rename(columns={
            "lookup_status": "repository_lookup_status", "full_name": "repository_full_name",
            "created_at": "repository_created_at", "pushed_at": "repository_pushed_at",
        }),
        on="repository_id", how="left",
    )
    enriched["github_status"] = enriched.apply(github_status, axis=1)
    enriched = enriched.merge(summarize_sources(tables["server_source_map"], tables["mcpcorpus_servers"]), left_on="server_id", right_index=True, how="left")
    target_groups = vulnerability_groups_by_target(tables["package_vulnerability_map"])
    package_groups = dict(tuple(server_packages.groupby("server_id")))
    dependency_groups = dict(tuple(dependencies.groupby("server_id")))
    resolved_groups = dict(tuple(resolved.groupby(["ecosystem", "package_name", "package_version"])))
    empty_packages, empty_dependencies, empty_resolved = server_packages.iloc[0:0], dependencies.iloc[0:0], resolved.iloc[0:0]
    summaries = []
    for server in enriched.to_dict("records"):
        packages = package_groups.get(server["server_id"], empty_packages)
        verified = packages[packages["mapping_status"] == "verified"]
        package_keys = zip(verified["ecosystem"], verified["package_name"], verified["identified_version"])
        frames = [resolved_groups[key] for key in package_keys if key in resolved_groups]
        server_resolved = pd.concat(frames) if frames else empty_resolved
        summaries.append({
            "package_ids": join_values(packages["package_id"]),
            "package_mapping_status": join_values(packages["mapping_status"]),
            "identified_versions": join_values(packages["identified_version"]),
            "latest_versions": join_values(packages["latest_version"]),
            **summarize_security(
                server, packages, dependency_groups.get(server["server_id"], empty_dependencies), server_resolved, osv_results, target_groups,
            ),
        })
    enriched = pd.concat([enriched, pd.DataFrame(summaries, index=enriched.index)], axis=1)
    for column in ("corpus_tool_count", "package_known_vulnerability_count", "dependency_known_vulnerability_count", "known_vulnerability_count"):
        enriched[column] = enriched[column].astype("Int64")
    enriched["enriched_at"] = utc_now()
    return enriched


def export_tables(tables, directory):
    directory.mkdir(parents=True, exist_ok=True)
    outputs = []
    for name, frame in tables.items():
        path = directory / f"{name}.csv"
        frame.to_csv(path, index=False)
        outputs.append({"file": str(path.relative_to(PROJECT_ROOT)), "rows": len(frame), "columns": frame.shape[1]})
    return outputs

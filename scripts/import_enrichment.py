import argparse
import gzip
import json
import sys
from collections import defaultdict
from pathlib import Path

from psycopg.types.json import Jsonb

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sentinel_common import (
    DEPS_TO_ECOSYSTEM, EVIDENCE_TYPES, OSV_TO_ECOSYSTEM, apply_migrations, canonical_repository, connect, ensure_sources, finish_run,
    normalize_endpoint, normalize_package_name, parse_time, range_status, schema_state, sha256_file, start_run,
)

ID_PREFERENCE = ("GHSA-", "PYSEC-")


def identifier_type(value):
    for prefix, kind in (("CVE-", "CVE"), ("GHSA-", "GHSA"), ("PYSEC-", "PYSEC")):
        if value.startswith(prefix):
            return kind
    return "OSV" if "-" in value else "OTHER"


class Loader:
    def __init__(self, conn, sources, evidence_path):
        self.conn = conn
        self.sources = sources
        self.evidence_path = str(evidence_path)
        self.evidence_sha = sha256_file(evidence_path)
        self.runs = {}
        self.counts = defaultdict(lambda: defaultdict(int))
        self.errors = defaultdict(list)
        self.package_ids = {(e, n): i for i, e, n in conn.execute("SELECT package_id, ecosystem, normalized_name FROM packages")}
        self.version_ids = {(p, v): i for i, p, v in conn.execute("SELECT package_version_id, package_id, version FROM package_versions")}
        self.server_versions = {(n, v): i for i, n, v in conn.execute(
            "SELECT sv.server_version_id, s.registry_name, sv.version FROM server_versions sv JOIN servers s ON s.server_id = sv.server_id")}
        self.latest = dict(conn.execute("SELECT registry_name, latest_version_id FROM servers").fetchall())
        self.declarations = {}
        for row in conn.execute("""SELECT declaration_id, server_version_id, position, package_id, package_version_id, registry_type,
                                          declared_identifier, declared_version FROM server_package_declarations"""):
            self.declarations[(row[1], row[2])] = row
        self.repos = dict(conn.execute("SELECT canonical_url, repository_id FROM repositories").fetchall())
        self.advisory_by_identifier = {}
        self.osv_records = {}
        self.osv_observations = {}
        self.resolutions = {}
        self.query_observations = {}

    def run(self, source_key, collected_at=None):
        if source_key not in self.runs:
            self.runs[source_key] = start_run(self.conn, self.sources[source_key], "enrichment_import", self.evidence_path, self.evidence_sha, collected_at)
        return self.runs[source_key]

    def error(self, source_key, ref, message):
        self.run(source_key)
        self.errors[source_key].append((ref, message))

    def package(self, ecosystem, name, display=None):
        key = (ecosystem, normalize_package_name(ecosystem, name))
        if key not in self.package_ids:
            self.package_ids[key] = self.conn.execute(
                """INSERT INTO packages (ecosystem, normalized_name, display_name) VALUES (%s, %s, %s)
                   ON CONFLICT (ecosystem, normalized_name) DO UPDATE SET ecosystem = EXCLUDED.ecosystem RETURNING package_id""",
                (key[0], key[1], display or name)).fetchone()[0]
        return self.package_ids[key]

    def package_version(self, package_id, version):
        if not version:
            return None
        key = (package_id, version)
        if key not in self.version_ids:
            self.version_ids[key] = self.conn.execute(
                """INSERT INTO package_versions (package_id, version) VALUES (%s, %s)
                   ON CONFLICT (package_id, version) DO UPDATE SET version = EXCLUDED.version RETURNING package_version_id""",
                key).fetchone()[0]
        return self.version_ids[key]

    def observation(self, source_key, key, kind, observed_at, payload=None, **links):
        run_id = self.run(source_key)
        self.counts[source_key]["evidence_observations"] += 1
        return self.conn.execute(
            """
            INSERT INTO evidence_observations (source_id, run_id, observation_key, observation_kind, evidence_type, source_record_id, source_url,
                observed_at, match_method, match_confidence, server_version_id, package_version_id, repository_id, endpoint_id, advisory_id, payload)
            VALUES (%(source_id)s, %(run_id)s, %(key)s, %(kind)s, %(evidence_type)s, %(source_record_id)s, %(source_url)s, %(observed_at)s,
                %(match_method)s, %(match_confidence)s, %(server_version_id)s, %(package_version_id)s, %(repository_id)s, %(endpoint_id)s,
                %(advisory_id)s, %(payload)s)
            ON CONFLICT (source_id, observation_key) DO UPDATE SET run_id = EXCLUDED.run_id, observation_kind = EXCLUDED.observation_kind,
                evidence_type = EXCLUDED.evidence_type, source_record_id = EXCLUDED.source_record_id, source_url = EXCLUDED.source_url,
                observed_at = EXCLUDED.observed_at, match_method = EXCLUDED.match_method, match_confidence = EXCLUDED.match_confidence,
                server_version_id = EXCLUDED.server_version_id, package_version_id = EXCLUDED.package_version_id,
                repository_id = EXCLUDED.repository_id, endpoint_id = EXCLUDED.endpoint_id, advisory_id = EXCLUDED.advisory_id, payload = EXCLUDED.payload
            RETURNING observation_id
            """,
            {"source_id": self.sources[source_key], "run_id": run_id, "key": key, "kind": kind, "evidence_type": links.pop("evidence_type", EVIDENCE_TYPES[source_key]),
             "source_record_id": links.pop("source_record_id", None), "source_url": links.pop("source_url", None), "observed_at": parse_time(observed_at),
             "match_method": links.pop("match_method", None), "match_confidence": links.pop("match_confidence", None),
             "server_version_id": links.pop("server_version_id", None), "package_version_id": links.pop("package_version_id", None),
             "repository_id": links.pop("repository_id", None), "endpoint_id": links.pop("endpoint_id", None), "advisory_id": links.pop("advisory_id", None),
             "payload": Jsonb(payload) if payload is not None else None},
        ).fetchone()[0]

    def declaration(self, record):
        version_id = self.server_versions.get((record["server_name"], record["server_version"]))
        if version_id is None or record.get("position") is None:
            return version_id, None
        return version_id, self.declarations.get((version_id, record["position"]))

    def load_advisories(self, records):
        parent = {}

        def find(item):
            parent.setdefault(item, item)
            while parent[item] != item:
                parent[item] = parent[parent[item]]
                item = parent[item]
            return item

        def union(a, b):
            parent[find(a)] = find(b)

        for record in records:
            self.osv_records[record["id"]] = record
            find(record["id"])
            for alias in record["body"].get("aliases") or []:
                union(record["id"], alias)
        groups = defaultdict(set)
        for item in list(parent):
            groups[find(item)].add(item)
        for members in groups.values():
            stored = sorted(member for member in members if member in self.osv_records)
            if not stored:
                continue
            cves = sorted(member for member in members if member.startswith("CVE-"))
            ghsas = sorted(member for member in members if member.startswith("GHSA-"))
            pysecs = sorted(member for member in members if member.startswith("PYSEC-"))
            canonical = cves[0] if len(cves) == 1 else (ghsas[0] if ghsas else sorted(members)[0])
            primary = next((self.osv_records[m] for prefix in ID_PREFERENCE for m in stored if m.startswith(prefix)), self.osv_records[stored[0]])
            body = primary["body"]
            reasons = []
            if len(ghsas) > 1:
                reasons.append(f"alias group joins {len(ghsas)} GHSA advisories: {', '.join(ghsas)}")
            if len(pysecs) > 1:
                reasons.append(f"alias group joins {len(pysecs)} PYSEC advisories: {', '.join(pysecs)}")
            ghsa_record = next((self.osv_records[m] for m in stored if m.startswith("GHSA-")), None)
            severity = ((ghsa_record or {}).get("body", {}).get("database_specific") or {}).get("severity")
            vectors = [{"record": m, **item} for m in stored for item in self.osv_records[m]["body"].get("severity") or []]
            cwes = sorted({cwe for m in stored for cwe in ((self.osv_records[m]["body"].get("database_specific") or {}).get("cwe_ids") or [])})
            published = [parse_time(self.osv_records[m]["body"].get("published")) for m in stored]
            modified = [parse_time(self.osv_records[m]["body"].get("modified")) for m in stored]
            advisory_id = self.conn.execute(
                """
                INSERT INTO advisories (canonical_id, summary, details, published_at, modified_at, withdrawn_at, severity_label, severity_source,
                    cvss_vectors, cwe_ids, alias_review_needed, alias_review_reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (canonical_id) DO UPDATE SET summary = EXCLUDED.summary, details = EXCLUDED.details, published_at = EXCLUDED.published_at,
                    modified_at = EXCLUDED.modified_at, withdrawn_at = EXCLUDED.withdrawn_at, severity_label = EXCLUDED.severity_label,
                    severity_source = EXCLUDED.severity_source, cvss_vectors = EXCLUDED.cvss_vectors, cwe_ids = EXCLUDED.cwe_ids,
                    alias_review_needed = EXCLUDED.alias_review_needed, alias_review_reason = EXCLUDED.alias_review_reason
                RETURNING advisory_id
                """,
                (canonical, body.get("summary"), body.get("details"), min((p for p in published if p), default=None),
                 max((m for m in modified if m), default=None), parse_time(body.get("withdrawn")), severity,
                 f"GitHub-reviewed severity in {ghsa_record['id']} (OSV database_specific)" if severity else None,
                 Jsonb(vectors) if vectors else None, cwes or None, bool(reasons), "; ".join(reasons) or None),
            ).fetchone()[0]
            self.counts["osv"]["advisories"] += 1
            for member in stored:
                record = self.osv_records[member]
                observation_id = self.observation("osv", f"osv_record|{member}|{record['observed_at']}", "osv_record", record["observed_at"], record["body"],
                                                  source_record_id=member, source_url=f"https://osv.dev/vulnerability/{member}", advisory_id=advisory_id)
                self.osv_observations[member] = observation_id
                for index, affected in enumerate(record["body"].get("affected") or []):
                    package = affected.get("package") or {}
                    ecosystem = OSV_TO_ECOSYSTEM.get(package.get("ecosystem"))
                    if not ecosystem or not package.get("name"):
                        continue
                    package_id = self.package(ecosystem, package["name"])
                    fixed = sorted({str(event["fixed"]) for rng in affected.get("ranges") or [] for event in rng.get("events") or [] if "fixed" in event})
                    self.conn.execute(
                        """
                        INSERT INTO advisory_affected_packages (advisory_id, package_id, source_record_id, entry_index, ranges, affected_versions,
                            fixed_versions, observation_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (source_record_id, entry_index) DO UPDATE SET advisory_id = EXCLUDED.advisory_id, package_id = EXCLUDED.package_id,
                            ranges = EXCLUDED.ranges, affected_versions = EXCLUDED.affected_versions, fixed_versions = EXCLUDED.fixed_versions,
                            observation_id = EXCLUDED.observation_id
                        """,
                        (advisory_id, package_id, member, index, Jsonb(affected.get("ranges") or []),
                         Jsonb(affected["versions"]) if affected.get("versions") else None, fixed or None, observation_id),
                    )
                    self.counts["osv"]["affected_package_entries"] += 1
            for member in sorted(members):
                self.conn.execute(
                    """INSERT INTO advisory_identifiers (identifier, advisory_id, identifier_type, osv_observation_id) VALUES (%s, %s, %s, %s)
                       ON CONFLICT (identifier) DO UPDATE SET advisory_id = EXCLUDED.advisory_id, identifier_type = EXCLUDED.identifier_type,
                       osv_observation_id = EXCLUDED.osv_observation_id""",
                    (member, advisory_id, identifier_type(member), self.osv_observations.get(member)))
                self.advisory_by_identifier[member] = advisory_id
                self.counts["osv"]["advisory_identifiers"] += 1

    def cve_row(self, source_key, cve, observation_id, observed_at, status, **values):
        self.conn.execute(
            """
            INSERT INTO cve_observations (cve_id, source_id, observation_id, observed_at, lookup_status, record_state, nvd_status, cvss_v31_score,
                cvss_v31_severity, cvss_v31_vector, cvss_v31_source, cvss_v40_score, epss_score, epss_percentile, epss_model_date, kev_listed,
                kev_catalog_version, kev_date_added, kev_ransomware_use)
            VALUES (%(cve)s, %(source_id)s, %(observation_id)s, %(observed_at)s, %(status)s, %(record_state)s, %(nvd_status)s, %(v31)s, %(v31_severity)s,
                %(v31_vector)s, %(v31_source)s, %(v40)s, %(epss)s, %(percentile)s, %(epss_date)s, %(kev_listed)s, %(kev_version)s, %(kev_added)s, %(kev_ransomware)s)
            ON CONFLICT (cve_id, source_id, observed_at) DO UPDATE SET observation_id = EXCLUDED.observation_id, lookup_status = EXCLUDED.lookup_status,
                record_state = EXCLUDED.record_state, nvd_status = EXCLUDED.nvd_status, cvss_v31_score = EXCLUDED.cvss_v31_score,
                cvss_v31_severity = EXCLUDED.cvss_v31_severity, cvss_v31_vector = EXCLUDED.cvss_v31_vector, cvss_v31_source = EXCLUDED.cvss_v31_source,
                cvss_v40_score = EXCLUDED.cvss_v40_score, epss_score = EXCLUDED.epss_score, epss_percentile = EXCLUDED.epss_percentile,
                epss_model_date = EXCLUDED.epss_model_date, kev_listed = EXCLUDED.kev_listed, kev_catalog_version = EXCLUDED.kev_catalog_version,
                kev_date_added = EXCLUDED.kev_date_added, kev_ransomware_use = EXCLUDED.kev_ransomware_use
            """,
            {"cve": cve, "source_id": self.sources[source_key], "observation_id": observation_id, "observed_at": parse_time(observed_at), "status": status,
             **{key: values.get(key) for key in ("record_state", "nvd_status", "v31", "v31_severity", "v31_vector", "v31_source", "v40", "epss",
                                                 "percentile", "epss_date", "kev_listed", "kev_version", "kev_added", "kev_ransomware")}},
        )
        self.counts[source_key]["cve_observations"] += 1

    def load_cves(self, by_kind):
        for record in by_kind["nvd_record"]:
            cve = record["cve_id"]
            items = ((record.get("body") or {}).get("vulnerabilities") or []) if record["status"] == 200 else []
            data = items[0]["cve"] if items else None
            payload = {key: data.get(key) for key in ("id", "sourceIdentifier", "published", "lastModified", "vulnStatus", "metrics", "weaknesses", "configurations")} if data else {"http_status": record["status"]}
            observation_id = self.observation("nvd", f"nvd|{cve}|{record['observed_at']}", "nvd_cve_record", record["observed_at"], payload,
                                              source_record_id=cve, source_url=f"https://nvd.nist.gov/vuln/detail/{cve}",
                                              advisory_id=self.advisory_by_identifier.get(cve))
            if not data:
                self.cve_row("nvd", cve, observation_id, record["observed_at"], "not_found" if record["status"] in (200, 404) else "error")
                continue
            metrics = data.get("metrics") or {}
            v31_list = metrics.get("cvssMetricV31") or []
            v31 = next((m for m in v31_list if m.get("type") == "Primary"), v31_list[0] if v31_list else None)
            v40 = (metrics.get("cvssMetricV40") or [{}])[0].get("cvssData") or {}
            cvss = (v31 or {}).get("cvssData") or {}
            self.cve_row("nvd", cve, observation_id, record["observed_at"], "found", nvd_status=data.get("vulnStatus"), v31=cvss.get("baseScore"),
                         v31_severity=cvss.get("baseSeverity"), v31_vector=cvss.get("vectorString"),
                         v31_source=f"{v31.get('source')} ({v31.get('type')})" if v31 else None, v40=v40.get("baseScore"))
        for record in by_kind["cveorg_record"]:
            cve = record["cve_id"]
            body = record.get("body") or {}
            cna = (body.get("containers") or {}).get("cna") or {}
            payload = {"cveMetadata": body.get("cveMetadata"), "title": cna.get("title"), "problemTypes": cna.get("problemTypes"),
                       "metrics": cna.get("metrics"), "affected": cna.get("affected")} if body else {"http_status": record["status"]}
            observation_id = self.observation("cve_org", f"cve_org|{cve}|{record['observed_at']}", "cve_record", record["observed_at"], payload,
                                              source_record_id=cve, source_url=f"https://www.cve.org/CVERecord?id={cve}",
                                              advisory_id=self.advisory_by_identifier.get(cve))
            self.cve_row("cve_org", cve, observation_id, record["observed_at"], "found" if body else ("not_found" if record["status"] == 404 else "error"),
                         record_state=(body.get("cveMetadata") or {}).get("state"))
        for record in by_kind["epss_response"]:
            observation_id = self.observation("epss", f"epss|{record['url']}|{record['observed_at']}", "epss_response", record["observed_at"],
                                              {"cves_queried": record["cves_queried"], "data": record["data"]}, source_url=record["url"])
            scores = {item["cve"]: item for item in record["data"]}
            for cve in record["cves_queried"]:
                item = scores.get(cve)
                self.cve_row("epss", cve, observation_id, record["observed_at"], "found" if item else "not_found",
                             epss=item.get("epss") if item else None, percentile=item.get("percentile") if item else None,
                             epss_date=item.get("date") if item else None)
        for record in by_kind["kev_catalog"]:
            listed = {item["cveID"]: item for item in record["entries"]}
            observation_id = self.observation("cisa_kev", f"kev|{record['catalog_version']}|{record['sha256']}", "kev_catalog", record["observed_at"],
                                              {key: record[key] for key in ("catalog_version", "date_released", "count", "sha256", "url")},
                                              source_record_id=record["catalog_version"], source_url=record["url"])
            for cve in sorted(identifier for identifier in self.advisory_by_identifier if identifier.startswith("CVE-")):
                item = listed.get(cve)
                self.cve_row("cisa_kev", cve, observation_id, record["observed_at"], "found" if item else "not_found", kev_listed=bool(item),
                             kev_version=record["catalog_version"], kev_added=item.get("dateAdded") if item else None,
                             kev_ransomware=item.get("knownRansomwareCampaignUse") if item else None)

    def load_github(self, records):
        for record in records:
            version_id = self.server_versions.get((record["server_name"], record["server_version"]))
            repo = canonical_repository(record["repository_url"])
            if not version_id or not repo or repo["canonical_url"] not in self.repos:
                self.error("github", record["server_name"], "repository observation could not be linked to an imported repository")
                continue
            repository_id = self.repos[repo["canonical_url"]]
            fields = record.get("fields") or {}
            found = record["status"] == "Matched"
            self.observation("github", f"github|{repo['canonical_url']}|{record['observed_at']}", "github_repository", record["observed_at"],
                             {**fields, "http_status": record.get("http_status"), "lookup": "found" if found else "not_found"},
                             source_record_id=record.get("github_id"), source_url=record.get("source_url"),
                             match_method="owner/name parsed from registry repository.url", match_confidence="high" if found else None,
                             server_version_id=version_id, repository_id=repository_id)
            if not found:
                self.conn.execute("UPDATE repositories SET lookup_status = 'not_found', metadata_observed_at = %s WHERE repository_id = %s",
                                  (parse_time(record["observed_at"]), repository_id))
                self.counts["github"]["repositories_not_found"] += 1
                continue
            github_id = int(record["github_id"]) if record.get("github_id") else None
            owner = self.conn.execute("SELECT repository_id FROM repositories WHERE github_id = %s", (github_id,)).fetchone() if github_id else None
            if owner and owner[0] != repository_id:
                self.error("github", repo["canonical_url"], f"GitHub id {github_id} already belongs to repository {owner[0]}; id not reassigned")
                github_id = None
            self.conn.execute(
                """
                UPDATE repositories SET github_id = COALESCE(%s, github_id), lookup_status = 'found', full_name_observed = %s, is_archived = %s,
                    is_fork = %s, is_disabled = %s, stars = %s, license = %s, default_branch = %s, language = %s, created_at_source = %s, pushed_at = %s,
                    metadata_observed_at = %s
                WHERE repository_id = %s
                """,
                (github_id, fields.get("full_name"), fields.get("archived"), fields.get("fork"), fields.get("disabled"), fields.get("stars"),
                 fields.get("license"), fields.get("default_branch"), fields.get("language"), parse_time(fields.get("created_at")),
                 parse_time(fields.get("pushed_at")), parse_time(record["observed_at"]), repository_id),
            )
            self.counts["github"]["repositories_found"] += 1

    def load_package_metadata(self, records, provenance):
        for record in sorted(records, key=lambda r: r["source"] != "deps_dev"):
            version_id, declaration = self.declaration(record)
            if not declaration or declaration[4] is None:
                self.error(record["source"], f"{record['server_name']} {record['identifier']}@{record['version']}",
                           "package observation could not be linked to an exact declared package version")
                continue
            fields = record.get("fields") or {}
            package_version_id = declaration[4]
            found = record["status"] == "Matched"
            self.observation(record["source"], f"{record['source']}|{record['registry_type']}:{record['identifier']}@{record['version']}|{record['observed_at']}",
                             f"{record['source']}_package_version", record["observed_at"], {**fields, "lookup": "found" if found else "not_found",
                                                                                            "http_status": record.get("http_status")},
                             source_record_id=f"{record['identifier']}@{record['version']}", source_url=record.get("source_url"),
                             match_method="exact ecosystem/name/version", match_confidence="high" if found else None,
                             server_version_id=version_id, package_version_id=package_version_id)
            if not found:
                self.counts[record["source"]]["versions_not_found"] += 1
                continue
            published = fields.get("version_published_at") or fields.get("upload_time") or fields.get("published_at")
            deprecated = fields.get("deprecated") if "deprecated" in fields else fields.get("is_deprecated")
            yanked = fields.get("all_files_yanked")
            self.conn.execute(
                """
                UPDATE package_versions SET published_at = COALESCE(%s, published_at), is_deprecated = COALESCE(%s, is_deprecated),
                    is_yanked = COALESCE(%s, is_yanked), metadata_observed_at = GREATEST(metadata_observed_at, %s)
                WHERE package_version_id = %s
                """,
                (parse_time(published), deprecated if isinstance(deprecated, bool) else None, yanked if isinstance(yanked, bool) else None,
                 parse_time(record["observed_at"]), package_version_id),
            )
            self.counts[record["source"]]["versions_found"] += 1
        for record in provenance:
            version_id = self.latest.get(record["server_name"])
            package_id = self.package("pypi", record["package"])
            package_version_id = self.package_version(package_id, record["version"])
            payload = {key: record.get(key) for key in ("release_status", "release_files", "provenance_http_status", "has_provenance", "publisher_kind",
                                                        "publisher_repository", "publisher_matches_registry_repo")}
            self.observation("pypi_integrity", f"pypi_provenance|{record['package']}=={record['version']}|{record['observed_at']}", "pypi_provenance",
                             record["observed_at"], payload, source_record_id=f"{record['package']}=={record['version']}",
                             source_url=f"https://pypi.org/project/{record['package']}/{record['version']}/", match_method="exact name and version",
                             server_version_id=version_id, package_version_id=package_version_id)

    def load_graphs(self, records):
        for record in records:
            if record["status"] != 200 or not record.get("body"):
                continue
            ecosystem = DEPS_TO_ECOSYSTEM.get(record["system"])
            if not ecosystem:
                continue
            root = self.package_version(self.package(ecosystem, record["name"]), record["version"])
            body = record["body"]
            nodes = body.get("nodes") or []
            edges = body.get("edges") or []
            node_errors = sum(1 for node in nodes if node.get("errors"))
            status = "failed" if (not nodes or (body.get("error") and len(nodes) <= 1)) else ("partial" if (node_errors or body.get("error")) else "complete")
            observation_id = self.observation("deps_dev", f"depsdev|{record['system']}:{record['name']}@{record['version']}|{record['observed_at']}",
                                              "dependency_graph", record["observed_at"],
                                              {"nodes": len(nodes), "edges": len(edges), "nodes_with_errors": node_errors, "error": body.get("error")},
                                              source_record_id=f"{record['system']}:{record['name']}@{record['version']}", source_url=record["url"],
                                              match_method="system/name/version", match_confidence="high", package_version_id=root)
            resolution_id = self.conn.execute(
                """
                INSERT INTO dependency_resolutions (root_package_version_id, source_id, observation_id, resolved_at, status, node_count, edge_count, error)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (root_package_version_id, source_id, resolved_at) DO UPDATE SET observation_id = EXCLUDED.observation_id,
                    status = EXCLUDED.status, node_count = EXCLUDED.node_count, edge_count = EXCLUDED.edge_count, error = EXCLUDED.error
                RETURNING resolution_id
                """,
                (root, self.sources["deps_dev"], observation_id, parse_time(record["observed_at"]), status, len(nodes), len(edges), body.get("error")),
            ).fetchone()[0]
            self.resolutions[root] = resolution_id
            self.counts["deps_dev"]["resolutions"] += 1
            node_versions = []
            for node in nodes:
                key = node.get("versionKey") or {}
                node_ecosystem = DEPS_TO_ECOSYSTEM.get(key.get("system"), (key.get("system") or "unknown").lower())
                package_id = self.package(node_ecosystem, key["name"]) if key.get("name") else None
                version_id = self.package_version(package_id, key.get("version")) if package_id else None
                node_versions.append((node_ecosystem, key.get("name") or "", key.get("version") or None, version_id, node))
            rows = []
            for edge in edges:
                source, target = edge.get("fromNode"), edge.get("toNode")
                if source is None or target is None or target >= len(node_versions) or source >= len(node_versions):
                    self.error("deps_dev", record["url"], "edge references a missing node")
                    continue
                eco, name, version, pv, node = node_versions[target]
                rows.append((resolution_id, source, target, node_versions[source][3], pv, eco, name, version, node.get("relation"), edge.get("requirement"),
                             Jsonb(node["errors"]) if node.get("errors") else None))
            with self.conn.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO dependency_edges (resolution_id, from_node, to_node, from_package_version_id, to_package_version_id, to_ecosystem, to_name,
                        to_version, to_relation, requirement, to_errors)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (resolution_id, from_node, to_node) DO UPDATE SET requirement = EXCLUDED.requirement, to_errors = EXCLUDED.to_errors
                    """,
                    rows,
                )
            self.counts["deps_dev"]["edges"] += len(rows)

    def finding(self, version_id, advisory_id, package_version_id, category, declaration_id, resolution_id, observation_id, method, check, observed_at):
        withdrawn = self.conn.execute("SELECT withdrawn_at IS NOT NULL FROM advisories WHERE advisory_id = %s", (advisory_id,)).fetchone()[0]
        status = "withdrawn" if withdrawn else ("conflicting_evidence" if check == "not_affected" else "active")
        moment = parse_time(observed_at)
        self.conn.execute(
            """
            INSERT INTO security_findings (server_version_id, advisory_id, affected_package_version_id, finding_category, declaration_id, resolution_id,
                observation_id, match_method, range_check, finding_status, first_observed_at, last_observed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (server_version_id, advisory_id, affected_package_version_id, finding_category) DO UPDATE SET
                first_observed_at = LEAST(security_findings.first_observed_at, EXCLUDED.first_observed_at),
                last_observed_at = GREATEST(security_findings.last_observed_at, EXCLUDED.last_observed_at),
                range_check = CASE WHEN security_findings.match_method = EXCLUDED.match_method THEN EXCLUDED.range_check ELSE security_findings.range_check END,
                finding_status = CASE WHEN security_findings.match_method = EXCLUDED.match_method THEN EXCLUDED.finding_status ELSE security_findings.finding_status END
            """,
            (version_id, advisory_id, package_version_id, category, declaration_id, resolution_id, observation_id, method, check, status, moment, moment),
        )
        self.counts["osv"][f"findings_{category}"] += 1

    def range_check(self, osv_id, ecosystem, name, version):
        record = self.osv_records.get(osv_id)
        if not record:
            return "undetermined"
        wanted = normalize_package_name(ecosystem, name)
        results = [range_status(ecosystem, version, affected) for affected in record["body"].get("affected") or []
                   if OSV_TO_ECOSYSTEM.get((affected.get("package") or {}).get("ecosystem")) == ecosystem
                   and normalize_package_name(ecosystem, (affected.get("package") or {}).get("name")) == wanted]
        if "affected" in results:
            return "affected"
        if results and all(result == "not_affected" for result in results):
            return "not_affected"
        return "undetermined"

    def load_findings(self, queries, nodes):
        for record in queries:
            version_id, declaration = self.declaration(record)
            if not declaration or declaration[4] is None:
                self.error("osv", f"{record['server_name']} {record['identifier']}@{record['version']}", "OSV query could not be linked to an exact declaration")
                continue
            ecosystem = record["registry_type"]
            observation_id = self.observation("osv", f"osv_query|{ecosystem}:{normalize_package_name(ecosystem, record['identifier'])}@{record['version']}|{record['observed_at']}|{record['context']}",
                                              "osv_exact_version_query", record["observed_at"], {"returned_ids": record["ids"], "context": record["context"]},
                                              source_record_id=f"{record['identifier']}@{record['version']}", source_url=record.get("source_url"),
                                              match_method=record["method"], match_confidence="high", server_version_id=version_id,
                                              package_version_id=declaration[4])
            self.query_observations[(version_id, record["position"])] = observation_id
            for osv_id in record["ids"]:
                advisory_id = self.advisory_by_identifier.get(osv_id)
                if advisory_id is None:
                    self.error("osv", osv_id, "OSV query returned an advisory whose record is not stored; finding not created")
                    continue
                self.finding(version_id, advisory_id, declaration[4], "direct_package", declaration[0], None, observation_id, "osv_exact_version_query",
                             self.range_check(osv_id, ecosystem, record["identifier"], record["version"]), record["observed_at"])
        for record in nodes:
            version_id, declaration = self.declaration(record)
            if not declaration or declaration[4] is None:
                self.error("osv", f"{record['server_name']} {record['name']}@{record['version']}", "dependency finding could not be linked to a declaration")
                continue
            resolution_id = self.resolutions.get(declaration[4])
            if resolution_id is None:
                self.error("osv", f"{record['server_name']} {record['name']}@{record['version']}", "dependency finding has no stored resolution; not created")
                continue
            ecosystem = DEPS_TO_ECOSYSTEM.get(record["system"])
            package_version_id = self.package_version(self.package(ecosystem, record["name"]), record["version"])
            observation_id = self.observation("osv", f"osv_dependency_query|{ecosystem}:{normalize_package_name(ecosystem, record['name'])}@{record['version']}|{record['observed_at']}",
                                              "osv_exact_version_query", record["observed_at"], {"returned_ids": record["ids"], "context": "resolved_dependency"},
                                              source_record_id=f"{record['name']}@{record['version']}",
                                              match_method="OSV querybatch over resolved dependency versions", match_confidence="high",
                                              package_version_id=package_version_id)
            for osv_id in record["ids"]:
                advisory_id = self.advisory_by_identifier.get(osv_id)
                if advisory_id is None:
                    self.error("osv", osv_id, "OSV query returned an advisory whose record is not stored; finding not created")
                    continue
                self.finding(version_id, advisory_id, package_version_id, "resolved_dependency", declaration[0], resolution_id, observation_id,
                             "osv_exact_version_query", self.range_check(osv_id, ecosystem, record["name"], record["version"]), record["observed_at"])

    def load_range_findings(self, checked_declarations):
        rows = self.conn.execute(
            """
            SELECT aap.source_record_id, aap.entry_index, p.ecosystem, d.declaration_id, d.server_version_id, d.position, d.package_version_id,
                   pv.version, aap.advisory_id, s.registry_name, sv.version
            FROM advisory_affected_packages aap
            JOIN packages p ON p.package_id = aap.package_id
            JOIN server_package_declarations d ON d.package_id = aap.package_id AND d.package_version_id IS NOT NULL
            JOIN package_versions pv ON pv.package_version_id = d.package_version_id
            JOIN server_versions sv ON sv.server_version_id = d.server_version_id
            JOIN servers s ON s.server_id = sv.server_id
            WHERE p.ecosystem IN ('npm', 'pypi')
            ORDER BY aap.source_record_id, aap.entry_index, d.declaration_id
            """
        ).fetchall()
        checks = []
        for osv_id, index, ecosystem, declaration_id, version_id, position, package_version_id, version, advisory_id, server_name, server_version in rows:
            record = self.osv_records[osv_id]
            if range_status(ecosystem, version, record["body"]["affected"][index]) != "affected":
                continue
            self.finding(version_id, advisory_id, package_version_id, "direct_package", declaration_id, None, self.osv_observations[osv_id],
                         "osv_record_range_evaluation", "affected", record["observed_at"])
            self.counts["osv"]["range_evaluation_matches"] += 1
            if (version_id, position) not in checked_declarations:
                checks.append({"check_key": f"direct_package_advisories|{server_name}|{server_version}|osv|range-evaluation|{position}|{osv_id}",
                               "server_version_id": version_id, "check_type": "direct_package_advisories", "check_scope": "package_declaration",
                               "declaration_id": declaration_id, "resolution_id": None, "repository_id": None, "endpoint_id": None,
                               "source_id": self.sources["osv"], "run_id": self.run("osv"), "observation_id": self.osv_observations[osv_id],
                               "checked_at": parse_time(record["observed_at"]), "outcome": "finding_found",
                               "method": "version-range evaluation of the declared exact version against a stored OSV record",
                               "reason": "partial check: only stored OSV records were evaluated; this is not a complete OSV query",
                               "details": Jsonb({"osv_record": osv_id})})
        self.insert_checks(checks)

    def insert_checks(self, rows):
        with self.conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO assessment_checks (check_key, server_version_id, check_type, check_scope, declaration_id, resolution_id, repository_id,
                    endpoint_id, source_id, run_id, observation_id, checked_at, outcome, method, reason, details)
                VALUES (%(check_key)s, %(server_version_id)s, %(check_type)s, %(check_scope)s, %(declaration_id)s, %(resolution_id)s, %(repository_id)s,
                    %(endpoint_id)s, %(source_id)s, %(run_id)s, %(observation_id)s, %(checked_at)s, %(outcome)s, %(method)s, %(reason)s, %(details)s)
                ON CONFLICT (check_key) DO UPDATE SET server_version_id = EXCLUDED.server_version_id, declaration_id = EXCLUDED.declaration_id,
                    resolution_id = EXCLUDED.resolution_id, repository_id = EXCLUDED.repository_id, endpoint_id = EXCLUDED.endpoint_id,
                    run_id = EXCLUDED.run_id, observation_id = EXCLUDED.observation_id, checked_at = EXCLUDED.checked_at, outcome = EXCLUDED.outcome,
                    method = EXCLUDED.method, reason = EXCLUDED.reason, details = EXCLUDED.details
                """,
                rows,
            )

    def load_checks(self, records):
        rows = []
        checked = set()
        for record in records:
            version_id, declaration = self.declaration(record)
            if version_id is None:
                self.error(record["source"], record["check_key"], "check refers to a server version that is not imported")
                continue
            if record["check_scope"] == "package_declaration" and declaration is None and record["outcome"] not in ("not_applicable", "missing_identifier"):
                self.error(record["source"], record["check_key"], "package-level check could not be linked to a declaration")
                continue
            repo = canonical_repository(record.get("repository_url"))
            resolution_id = self.resolutions.get(declaration[4]) if declaration and record["check_type"] in ("dependency_advisories", "dependency_resolution") else None
            observation_id = self.query_observations.get((version_id, record.get("position"))) if record["check_type"] == "direct_package_advisories" and record["source"] == "osv" else None
            if record["check_type"] == "direct_package_advisories" and record["source"] == "osv" and record["outcome"] in ("finding_found", "no_known_finding"):
                checked.add((version_id, record.get("position")))
            rows.append({"check_key": record["check_key"], "server_version_id": version_id, "check_type": record["check_type"],
                         "check_scope": record["check_scope"], "declaration_id": declaration[0] if declaration else None, "resolution_id": resolution_id,
                         "repository_id": self.repos.get(repo["canonical_url"]) if repo else None, "endpoint_id": None,
                         "source_id": self.sources[record["source"]], "run_id": self.run(record["source"]), "observation_id": observation_id,
                         "checked_at": parse_time(record.get("checked_at")), "outcome": record["outcome"], "method": record.get("method"),
                         "reason": record.get("reason"), "details": Jsonb(record["details"]) if record.get("details") else None})
            self.counts[record["source"]]["assessment_checks"] += 1
        self.insert_checks(rows)
        return checked

    def load_agora(self, records):
        endpoints = defaultdict(dict)
        for endpoint_id, version_id, normalized in self.conn.execute("SELECT endpoint_id, server_version_id, normalized_url FROM remote_endpoints"):
            endpoints[version_id].setdefault(normalized, endpoint_id)
        evidence, observations = [], []
        run_id = self.run("agora", parse_time(records[0]["observed_at"]) if records else None)
        for record in records:
            if not (record.get("endpoint") or record.get("check_class") or record.get("check_result")):
                self.counts["agora"]["rows_without_endpoint_check"] += 1
                continue
            version_id = self.latest.get(record["name"])
            endpoint_id = endpoints[version_id].get(normalize_endpoint(record.get("endpoint"))) if version_id else None
            key = f"agora|{record['name']}|{record.get('endpoint')}|{record.get('checked_at')}"
            evidence.append({"source_id": self.sources["agora"], "run_id": run_id, "key": key, "observed_at": parse_time(record.get("checked_at")),
                             "server_version_id": version_id, "endpoint_id": endpoint_id, "source_record_id": record["name"],
                             "payload": Jsonb({k: record.get(k) for k in ("endpoint", "check_result", "check_class", "checked_at", "protocol", "tool_count",
                                                                         "registry_status", "observed_at", "csv_sha256")})})
            observations.append((key, version_id, endpoint_id, record))
        with self.conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO evidence_observations (source_id, run_id, observation_key, observation_kind, evidence_type, source_record_id, source_url,
                    observed_at, match_method, match_confidence, server_version_id, endpoint_id, payload)
                VALUES (%(source_id)s, %(run_id)s, %(key)s, 'agora_endpoint_check', 'third_party_observed', %(source_record_id)s,
                    'https://openforallofus.com/data', %(observed_at)s, 'exact registry name', 'high', %(server_version_id)s, %(endpoint_id)s, %(payload)s)
                ON CONFLICT (source_id, observation_key) DO UPDATE SET run_id = EXCLUDED.run_id, observed_at = EXCLUDED.observed_at,
                    server_version_id = EXCLUDED.server_version_id, endpoint_id = EXCLUDED.endpoint_id, payload = EXCLUDED.payload
                """,
                evidence,
            )
        ids = dict(self.conn.execute("SELECT observation_key, observation_id FROM evidence_observations WHERE source_id = %s", (self.sources["agora"],)).fetchall())
        rows = []
        for key, version_id, endpoint_id, record in observations:
            count = record.get("tool_count")
            rows.append((version_id, endpoint_id, ids[key], record.get("endpoint"), record.get("check_result"), record.get("check_class"),
                         (record.get("check_class") == "gated") if record.get("check_class") else None, record.get("protocol"),
                         int(count) if count and str(count).isdigit() else None, parse_time(record.get("checked_at"))))
        with self.conn.cursor() as cursor:
            cursor.executemany(
                """
                INSERT INTO endpoint_observations (server_version_id, endpoint_id, observation_id, observed_url, check_result, availability_class,
                    auth_gated, protocol_version, observed_tool_count, observed_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (observation_id) DO UPDATE SET endpoint_id = EXCLUDED.endpoint_id, check_result = EXCLUDED.check_result,
                    availability_class = EXCLUDED.availability_class, auth_gated = EXCLUDED.auth_gated, protocol_version = EXCLUDED.protocol_version,
                    observed_tool_count = EXCLUDED.observed_tool_count, observed_at = EXCLUDED.observed_at
                """,
                rows,
            )
        self.counts["agora"]["evidence_observations"] += len(evidence)
        self.counts["agora"]["endpoint_observations"] += len(rows)
        self.counts["agora"]["linked_to_declared_endpoint"] += sum(1 for row in rows if row[1])

    def load_tools(self, records):
        for record in records:
            version_id = self.server_versions.get((record["server_name"], record["server_version"]))
            if version_id is None:
                self.error(record["source"], record["server_name"], "tool listing refers to a server version that is not imported")
                continue
            observation_id = self.observation(
                record["source"], f"tools|{record['server_name']}|{record['server_version']}|{record['source_record_id']}|{record['observed_at']}",
                "tool_listing", record["observed_at"], {"entry": record.get("entry"), "tools_listed": len(record["tools"])},
                source_record_id=record["source_record_id"], source_url=record.get("source_url"), match_method=record["match_method"],
                match_confidence=record["match_confidence"], server_version_id=version_id)
            rows = []
            for position, tool in enumerate(record["tools"]):
                state, schema = schema_state(tool.get("input_schema"))
                output = tool.get("output_schema") if isinstance(tool.get("output_schema"), dict) and tool.get("output_schema") else None
                classification = tool.get("classification")
                rows.append((version_id, observation_id, position, str(tool.get("name")), tool.get("description"), record["declaration_kind"],
                             Jsonb(schema) if schema is not None else None, state, Jsonb(output) if output else None,
                             Jsonb(tool["annotations"]) if tool.get("annotations") else None, Jsonb(classification) if classification else None,
                             "PolicyLayer classifier output (inferred, third-party)" if classification else None, parse_time(record["observed_at"])))
            with self.conn.cursor() as cursor:
                cursor.executemany(
                    """
                    INSERT INTO tool_observations (server_version_id, observation_id, tool_position, tool_name, description, declaration_kind, input_schema,
                        input_schema_state, output_schema, annotations, classification, classification_source, observed_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (observation_id, tool_position) DO UPDATE SET tool_name = EXCLUDED.tool_name, description = EXCLUDED.description,
                        declaration_kind = EXCLUDED.declaration_kind, input_schema = EXCLUDED.input_schema, input_schema_state = EXCLUDED.input_schema_state,
                        output_schema = EXCLUDED.output_schema, annotations = EXCLUDED.annotations, classification = EXCLUDED.classification,
                        classification_source = EXCLUDED.classification_source, observed_at = EXCLUDED.observed_at
                    """,
                    rows,
                )
            self.counts[record["source"]]["tool_observations"] += len(rows)
            self.counts[record["source"]]["valid_input_schemas"] += sum(1 for row in rows if row[7] == "valid")

    def finish(self):
        for source_key, run_id in self.runs.items():
            finish_run(self.conn, run_id, {k: v for k, v in self.counts[source_key].items()}, self.errors[source_key])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", required=True)
    args = parser.parse_args()
    path = Path(args.bundle) / "evidence.jsonl.gz"
    by_kind = defaultdict(list)
    with gzip.open(path, "rt", encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            by_kind[record["kind"]].append(record)
    with connect() as conn:
        apply_migrations(conn)
        loader = Loader(conn, ensure_sources(conn), path)
        if not loader.server_versions:
            raise SystemExit("No registry records are loaded; run import_registry.py first.")
        loader.load_advisories(by_kind["osv_record"])
        loader.load_cves(by_kind)
        loader.load_github(by_kind["github_repository"])
        loader.load_package_metadata(by_kind["package_metadata"], by_kind["pypi_provenance"])
        loader.load_graphs(by_kind["depsdev_graph"])
        loader.load_findings(by_kind["osv_query"], by_kind["dependency_node"])
        checked = loader.load_checks(by_kind["check"])
        loader.load_range_findings(checked)
        loader.load_agora(by_kind["agora_row"])
        loader.load_tools(by_kind["tool_listing"])
        loader.finish()
        conn.commit()
    summary = {source: dict(counts) for source, counts in sorted(loader.counts.items())}
    print(json.dumps({"counts": summary, "errors": {k: len(v) for k, v in loader.errors.items() if v}}, indent=2))


if __name__ == "__main__":
    main()

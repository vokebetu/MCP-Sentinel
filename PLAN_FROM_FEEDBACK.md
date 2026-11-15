# Plan from feedback from Vanessa Vreeland

# Status: all three steps are implemented (2026-11-14). See "Status" at the end.

## The feedback

Question: when an MCP server has no known vulnerabilities but was never fully assessed, what evidence and safeguards should a bank require?

- "No known vulnerabilities" means nobody has looked yet. Treat the server as unapproved until proven otherwise.
- Evidence to require: a software bill of materials (SBOM), signed builds with provenance, an identifiable maintainer, pinned dependency versions, static code analysis, a permission review of every tool, and testing for prompt injection hidden in tool descriptions.
- Safeguards after approval: sandbox with least-privilege credentials and limited network, pin the reviewed version, fingerprint tool definitions so any change triggers a new review, route calls through a logging gateway with a kill switch.
- Positioning: MCP Sentinel cuts a bank's third-party review from weeks to days with audit-ready evidence.

The app already follows the first point: a server that was never checked shows "not assessed", never "0 vulnerabilities".

## Each point against our data

Numbers are for the 48,673 non-deleted servers in the current database.

| Feedback | What we have now | What we can add |
|---|---|---|
| SBOM | Full dependency lists for 215 package versions (research sample) | "Download SBOM" per server. Step 3 extends lists to about 16,400 package versions. |
| Signed builds, provenance | Research sample only: deps.dev reported SLSA provenance for 25 and attestations for 54 of 195 package versions | Provenance check for every npm and PyPI package (Step 3) |
| Identifiable maintainer | Registry-verified namespace for every server: 29,247 by GitHub account, 19,426 by domain. Repository activity (last push, archived, missing) from Agora and GitHub. | "Publisher identity" line on the profile (Step 1) |
| Pinned versions | Exact declared version for every package. Whether it is the latest was checked for the research sample only. | Show the declared version on the checklist. Pinning inside dependencies needs OpenSSF Scorecard, which covered 1 repository in the sample, so it shows "not assessed". |
| Static code analysis | None | Shown as "not assessed". Running analysis means downloading each server's code (out of scope). |
| Tool permission review | 16,055 tools on 1,037 servers. 13,785 labelled by PolicyLayer: Read 8,591, Write 3,481, Execute 811, Destructive 809, Financial 71; severity Critical 109, High 943. | Per-server summary, for example "3 destructive tools, 1 critical" (Step 2) |
| Prompt injection in tool descriptions | 14,427 stored tool descriptions. A rough test pattern matches 6 servers (not yet reviewed). | Text checks on stored descriptions, optional AI classifier (Step 2). No server is contacted. |
| Sandbox, least privilege | Bank's runtime control. We know the inputs: 6,904 servers ask for secret settings, 5,439 hosted servers need login headers. | "What this server needs" section (Step 1) |
| Pin version, fingerprint tools | Tool lists stored per server version | SHA-256 fingerprint of each tool list (Step 2). Change detection needs a second collection to compare. |
| Logging gateway, kill switch | Bank's runtime control | Not built. Named in the pitch as the bank's side. |
| Weeks to days, audit-ready | Profiles show checked and not checked | Bank review checklist and evidence export (Step 1) |

## Out of scope

- Running MCP servers, sending them test prompts, or scanning their endpoints. This is exploit-style testing and breaks the project rules.
- Static analysis of server source code.
- Building a sandbox or gateway.

## Steps

### Step 1. Bank review checklist and evidence export (about 1 day)

- API: `GET /api/servers/{name}/evidence` returns one item per feedback point with status `present`, `missing` or `not_assessed`, plus source and date.
- Server profile: a "Review checklist" section and a "Download evidence" button (JSON and Markdown).
- Items: publisher identity, repository activity, declared versions, vulnerabilities, SBOM, provenance, tool permissions, prompt-injection flags, tool fingerprint, required secrets and logins, static analysis.
- Uses only data already in the database.
- Done when: every server profile shows the checklist, the export downloads, API and browser tests pass.

### Step 2. Tool risk (about 1 day)

- Permission summary per server from PolicyLayer labels and tool annotations.
- Prompt-injection checks on stored descriptions: hidden instructions ("ignore previous instructions", `<IMPORTANT>`), invisible Unicode characters, mentions of secrets or files (`~/.ssh`, `.env`), instructions to call other tools. Each flag shows the matched text.
- Optional: AI classifier over the 14,427 descriptions using the existing OpenAI setup.
- Tool fingerprint: SHA-256 of the sorted tool names, descriptions and input schemas.
- Search filter: "has flagged tools".
- Done when: profiles show the summary, flags and fingerprint; flagged servers are reviewed by hand and false alarms noted.

### Step 3. Full vulnerability and provenance run (about 1 to 2 days)

- New script `scripts/enrich_packages.py` for every npm and PyPI package version: deps.dev dependency list and version details (provenance, attestations), OSV for every dependency, then advisory details, CVE.org, NVD, EPSS and KEV. NuGet and Cargo: OSV for the package only.
- Every response saved in `data/research/cache/http`, so no request repeats. If the builder starts reading the 518 cached lookups now listed in `.gitignore`, remove those lines.
- Update `scripts/build_bundle.py`, rebuild `data/bundle`, import, validate, update the AI index.
- Cost: free APIs. About 33,000 deps.dev requests, 100 to 200 OSV batch requests, a few thousand detail lookups. 1 to 3 hours of running. A free NVD key makes it faster.
- Coverage after the run: about 16,700 servers. 30,150 URL-only servers and about 1,900 Docker or MCPB servers have no package to check.
- Done when: validation passes, the dashboard shows the new coverage.

### After all steps

1. Export a new dump and check it is under 100 MB.
2. Update numbers in `README.md`, `DEPLOYMENT.md` and `docs/PROJECT_REPORT.md`.
3. Re-run the tests and the AI evaluation; refresh screenshots.

## Pitch

MCP Sentinel gives a bank's third-party risk team an evidence pack for each MCP server: what was checked, what was found, and what was not checked, with sources and dates. The bank keeps the runtime controls: sandbox, pinned versions and a logging gateway.

## Status

| Step | Status | Result |
|---|---|---|
| 1. Review checklist and evidence export | done | `GET /api/servers/{id}/review` and `/sbom`; "Review checklist" tab with JSON, Markdown and CycloneDX SBOM downloads |
| 2. Tool risk | done, without the optional AI classifier | permission summary, four text-pattern hints (24 servers), SHA-256 tool fingerprint, "Tool review hints" search filter |
| 3. Full vulnerability and provenance run | done | 16,669 package versions looked up with 35,404 free API requests; 16,514 servers checked; 19,406 findings on 6,048 servers; SLSA provenance for 2,773 and attestations for 4,880 package versions |
| After all steps | done | two dump files (37 MB data, 77 MB AI index), updated docs, 64 tests passing, AI evaluation 26/26 |

- NVD was not queried for the 1,265 new CVEs: its public limit (5 requests per 30 seconds) would add about 2.3 hours. CVE.org records were collected instead.
- The optional AI classifier for tool descriptions was not built; the text patterns cover the same review hints without extra cost.

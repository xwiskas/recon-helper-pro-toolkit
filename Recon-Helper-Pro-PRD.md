# Recon Helper Pro — Product Requirements Document (PRD) v2

> **Purpose of this document:** A complete, self-contained build specification to hand to an AI coding tool or developer. Where a decision was left open, this document states a concrete default and tells the builder to proceed with it. This is v2, revised after a detailed design review; changes from v1 are summarized in Section 20.

---

## 1. Overview

**Recon Helper Pro (RHP)** is a **learner-first** reconnaissance companion for people new to ethical hacking. Its flagship experience is a single, well-guided journey:

> Create an engagement, define an explicit scope, complete one guided domain-recon workflow, understand the results, and export a defensible report.

Everything in the product supports that journey. RHP performs **third-party OSINT** and **read-only web recon** against authorized targets, explains what it is doing and why at every step, records structured evidence, and generates Markdown reports that clearly separate raw facts from interpretation.

It ships as two coordinated pieces sharing one core engine:

1. **A command-line interface (CLI)** — the primary way to run recon; scriptable and fast.
2. **A local web dashboard** — a loopback-only browser view to browse engagements, assets, findings, and reports.

Both are in scope for v1 (the user's explicit decision). The build is **phased** so the CLI golden path is proven before the dashboard is layered on (see Section 15).

### Design principles
- **Teach while doing.** Every action explains what it does, why it matters, and how to read the result.
- **Safe and honest by default.** Conservative request behavior; clear labeling of what contacts the target; evidence-based reporting that never inflates a missing header into a confirmed vulnerability.
- **Works out of the box.** Runs fully on pip-installed Python dependencies; external tools are optional enhancers, never required.
- **Simple core, extensible edges.** A small core with self-contained, **bundled** recon modules. Third-party plugin installation is deferred to a later phase for security reasons.
- **Free and no-signup.** Only data sources that need no API key or account.

---

## 2. Goals and non-goals

### Goals
- Give a beginner a guided, safe, genuinely useful recon workflow with strong interpretation of results.
- Produce structured, provenance-rich findings and defensible Markdown reports per engagement.
- Keep the user in control of scope and of what gets contacted.
- Provide an extensible module architecture that can grow without rewriting the core.

### Non-goals (v1)
- Active exploitation, brute-forcing, password attacks, fuzzing, or denial-of-service.
- Aggressive/intrusive scanning that could disrupt a target.
- Paid or key-gated data sources.
- **Third-party / user-installed plugins** (deferred; v1 ships only trusted bundled modules).
- Multi-user, cloud-hosted, or team-collaboration features.
- Mobile app.
- PDF/HTML reports (Markdown only in v1; JSON export deferred).

---

## 3. Target user

A single individual **new to ethical hacking**, running RHP **locally** against targets they are **authorized** to test (their own lab, in-scope bug-bounty targets, CTFs, or client engagements with written permission). One user, local use only.

---

## 4. Key decisions (locked in)

| Area | Decision |
|---|---|
| App name | **Recon Helper Pro** |
| Language | **Python 3.10+** |
| Interfaces | **CLI (primary) + local web dashboard**, both in v1, built in phases |
| Product posture | **Learner-first**; one guided golden path is the flagship |
| Recon scope (v1) | **Third-party OSINT** + **read-only web recon** |
| Teaching level | **Heavy guidance** (beginner companion), with verbosity levels |
| Build approach | **Pure-Python baseline (pip deps)**; optionally wrap external tools when installed |
| Out-of-box requirement | Installs via pip and works with **no external binaries** |
| Scope semantics | **Exact host only**; subdomains, wildcards, IPs, CIDRs must be added explicitly |
| Scope enforcement | **Warn-but-allow** for out-of-scope direct contact (user's explicit choice), **but** revalidate scope after DNS resolution and on every redirect, and **always hard-block cloud-metadata endpoints** |
| Discovered assets | **Recorded only, never auto-contacted** until the user adds them to scope |
| Lab/private targets | **Allowed** (so users can practice on their own lab); cloud-metadata addresses hard-blocked |
| Raw data | **Stored as evidence with automatic redaction** of secrets/cookies/tokens/PII; configurable retention |
| Guided recipe | **Interactive by default**, plus a **non-interactive/scriptable flag** |
| Storage | **Local SQLite** + Markdown file exports |
| Report format | **Markdown** |
| Extensibility | **Module architecture**, bundled trusted modules only in v1 |
| External APIs | **None** — free, no-key sources only |

---

## 5. Contact modes (replaces the ambiguous "passive/active" split)

Every module declares exactly one **contact mode**. This is shown in the UI and recorded per run.

| Mode | Definition | Examples | Target contact |
|---|---|---|---|
| `third-party` | Data obtained from third parties or resolvers; the target host is never contacted directly. | WHOIS, DNS lookups via a resolver, Certificate Transparency logs (crt.sh) | None |
| `direct-read` | A small number of read-only requests to the target to observe public responses. | TLS certificate fetch, HTTP header retrieval, homepage technology fingerprint | Low volume |
| `enumerative` | Multiple requests to the target to enumerate resources. | Discovery of standard published files/paths | Multiple, budgeted |

- The UI must label each module with its mode and show the **expected/actual request count** per run.
- `direct-read` and `enumerative` are gated behind the authorization acknowledgment, rate-limited, and subject to scope revalidation (Section 7).
- Note: DNS is `third-party` only because it goes through a resolver, not the target. Fetching a TLS certificate or any HTTP response is `direct-read`, not passive.

---

## 6. Recon capabilities (v1 feature set)

Each capability is a **bundled module** (Section 9). Heavier capabilities ship "lite" in v1 and can expand later.

### 6.1 Third-party OSINT
- **Registration data (WHOIS / RDAP)** — registrar, creation/expiry dates, name servers, and registrant org where public. Uses RDAP/`python-whois`; system `whois` used if present.
- **DNS records** — A, AAAA, MX, NS, TXT, CNAME, SOA via a resolver (`dnspython`).
- **Reverse DNS / network context** — PTR records and which network/ASN an IP belongs to, from free sources.
- **Subdomain / hostname discovery (passive)** — from **Certificate Transparency logs** (crt.sh JSON, free/keyless) and cert SANs. Optionally deeper via `subfinder`/`amass` if installed. **Discovered hostnames are recorded as assets, never auto-contacted.**
- **Certificate inspection** — fetch and summarize the TLS certificate (issuer, validity, SANs). *Mode: `direct-read` (this contacts the target).*

### 6.2 Read-only web recon
- **HTTP header analysis** — retrieve headers; record observations for security-relevant ones (HSTS, CSP, X-Frame-Options, CORS config, cookie Secure/HttpOnly/SameSite, server/version disclosure). *Mode: `direct-read`.*
- **Technology fingerprinting (lite in v1)** — identify server/framework/CMS from headers and homepage content using a **small bundled signature set**. A large signature database is a later expansion. *Mode: `direct-read`.*
- **Standard published-file discovery** — check only well-known published files (`robots.txt`, `sitemap.xml`, `security.txt`, `.well-known/`). Broader directory brute-forcing is deferred. Does **not** follow links by default. *Mode: `enumerative`.*
- **Interpreted hints (informational only)** — surface observations that *may* indicate weaknesses (disclosed outdated version, directory listing enabled, missing security headers) as **hints with confidence and context, never confirmed vulnerabilities**. Severity is context-dependent and never assigned solely because a header is absent.

### 6.3 Deferred capabilities (documented, not built in v1)
Email/contact harvesting (weak as a headline: WHOIS is often redacted and SPF/DMARC describe mail infrastructure, not contacts), large-signature fingerprinting, deep directory discovery, JSON export, and third-party plugin installation. Kept out of v1 to protect the golden path.

---

## 7. Safety, ethics, and scope enforcement

### 7.1 Authorization
- **One-time acknowledgment** on first run: the user reads and accepts an authorization/ethics agreement. Acceptance (version + timestamp) is stored in `policy_acceptances`. Re-prompted if config is reset or the agreement version changes.

### 7.2 Scope model
- **Explicit scope entries** per engagement. Supported entry types: exact host, `*.domain` wildcard, IP address, CIDR range, plus scheme/port qualifiers. IDN and IPv6 must be handled.
- **Exact-host semantics:** a bare `example.com` authorizes only that host. Subdomains, wildcards, and IPs must be added deliberately.
- **Scope revalidation** happens: (a) before each `direct-read`/`enumerative` run, (b) **after DNS resolution** (the resolved IP is checked), and (c) **on every redirect hop** — a redirect to an out-of-scope or internal host stops the request and records an out-of-scope event.

### 7.3 Enforcement level (user's explicit choice: warn-but-allow)
- For a `direct-read`/`enumerative` target **outside** the saved scope, RHP **warns clearly and requires a one-time in-session confirmation**, then proceeds. It records the override in the activity log. (The reviewer recommended a hard block; the user chose warn-but-allow. This is intentional and documented.)
- **Regardless of the above**, the following are **always hard-blocked** and cannot be overridden in normal mode:
  - Cloud-metadata endpoints (e.g. `169.254.169.254`, `fd00:ec2::254`, and equivalent metadata addresses).
  - The **entire link-local range** (`169.254.0.0/16` and IPv6 `fe80::/10`), not just the single metadata address.
- **Lab/private targets are allowed**: private (RFC1918), loopback, and unique-local ranges are permitted so the user can practice on their own lab, *except* the always-blocked ranges above.

#### 7.3.1 Address-block hardening (mandatory)
The block above is enforced on the **numeric IP actually connected to**, not on the hostname string, and must not be bypassable by encoding tricks or DNS timing:
- **Normalize every IP representation before checking:** decimal, octal, hex, and mixed forms (e.g. `2852039166`, `0xA9FEA9FE`, `0251.0376.0251.0376`), IPv4-mapped/compatible IPv6, `0.0.0.0`, and `[::]`. Reject or normalize ambiguous forms; never scope-check a raw string.
- **Resolve once, then pin.** Resolve the hostname a single time, validate the resulting IP against scope and the block list, and then **connect to that exact validated IP** (with the original Host header). Do **not** re-resolve between the check and the connection — that reopens DNS-rebinding, where a name passes the check and then points at an internal address a moment later.
- **Re-validate on every redirect hop** using the same resolve-once-then-pin procedure for the new destination.

### 7.4 Request policy (conservative defaults; all configurable)
| Setting | Default |
|---|---|
| Delay between requests (per host) | 1000 ms |
| Max concurrency (per host) | 2 |
| Per-run request budget (enumerative) | 100 requests |
| Request timeout | 10 s |
| Max redirects followed | 5 (each hop scope-checked) |
| Max response body stored | 2 MB (larger truncated with a note) |
| User-Agent | Honest, identifiable RHP UA string |
| **Global request ceiling (per host, per engagement)** | **500 requests** — a hard cap across all modules and runs; the workflow stops and reports when reached |
| **Global request ceiling (per engagement, all hosts)** | **2000 requests** |

**Cancellation / kill switch (mandatory):** any running module, guided recipe, or the whole workflow can be cancelled cleanly from the CLI (Ctrl-C or `rhp cancel`) and from the dashboard. Cancellation stops in-flight work, records the run as `cancelled`, and preserves whatever was already collected as a partial run. The global ceilings above act as an automatic kill switch so an accidental fan-out cannot generate unbounded load.

### 7.5 robots.txt handling (explicit)
- RHP **reads and displays** `robots.txt`. For the standard published-file discovery module, disallowed paths are **skipped by default** and only checked if the user explicitly opts in per run. robots.txt is treated as a courtesy signal, **not** as authorization or a security boundary, and this is stated in the UI.

### 7.6 Data redaction and data-at-rest
- Secrets, session cookies, tokens, authorization headers, and obvious personal data are **redacted** from logs, stored artifacts, and reports by default. Redaction is best-effort pattern matching and may miss things, so the data store is treated as sensitive regardless.
- **Retention:** raw artifacts are stored (Section 8) but redacted; retention is configurable with a **conservative default of 30 days**, after which artifacts are pruned automatically (structured observations/findings are kept unless purged).
- **Purge:** a `rhp purge` command (and a dashboard control) deletes stored raw artifacts and, optionally, an entire engagement's data on demand.
- **Location warning:** on first run and in the README, RHP **warns if its data directory sits inside a known cloud-synced or backup location** (e.g. OneDrive, Dropbox, Google Drive, iCloud) and recommends relocating the data store outside synced folders, since it may contain hostnames, headers, and secrets redaction missed. The data directory location is configurable.
- **Optional encryption at rest:** the SQLite database and artifacts can be stored encrypted (e.g. SQLCipher or an app-level encryption layer) behind a user passphrase. Off by default for simplicity; a single setting enables it.

### 7.7 Activity log
- Every run and override is recorded in `activity_events` (engagement, module, mode, target, request count, timestamp, outcome).

---

## 8. Data model & storage

**Storage:** one local **SQLite** database (WAL mode for safe concurrent reads/writes between the CLI and the dashboard server) plus Markdown exports. The "finding" concept from v1 is split into **assets → observations → findings**, and a **runs** table is added.

### Tables
- **engagements** — `id`, `name`, `description`, `created_at`, `notes`.
- **scope_entries** — `id`, `engagement_id`, `type` (host/wildcard/ip/cidr), `value`, `scheme`, `port`, `created_at`.
- **assets** — `id`, `engagement_id`, `kind` (domain/host/ip/url), `value`, `discovered_by` (module), `first_seen`, `in_scope` (bool, derived).
- **runs** — `id`, `engagement_id`, `module`, `module_version`, `parameters` (JSON), `mode`, `status` (queued/running/completed/partial/failed/cancelled), `started_at`, `ended_at`, `request_count`, `error_summary`.
- **observations** — raw facts: `id`, `run_id`, `asset_id`, `type`, `normalized_value`, `raw_value_or_artifact_ref`, `source_provider`, `collected_at`, `evidence`, `confidence`, `dedup_key`.
- **findings** — interpretations derived from observations: `id`, `engagement_id`, `asset_id`, `title`, `category`, `interpretation_text`, `supporting_observation_ids`, `confidence`, `limitations`, `severity_hint` (info/low/med/high, context-aware, never auto-assigned from a single missing header), `created_at`.
- **artifacts** — retained raw material (redacted): `id`, `run_id`, `type`, `path_or_blob`, `sha256`, `created_at`, `retention_policy`.
- **activity_events** — `id`, `engagement_id`, `module`, `mode`, `target`, `request_count`, `timestamp`, `outcome`, `override_reason`.
- **policy_acceptances** — `id`, `agreement_version`, `accepted_at`.
- **settings** — key/value (verbosity, throttle, retention, lab mode, etc.).

### Provenance requirement
Every observation and finding carries: source/provider, collection timestamp, module + module version, evidence, confidence, normalized value, raw value or artifact reference, interpretation text (findings), limitations, and a deduplication key.

---

## 9. Architecture

### 9.1 Shared core engine
Both the CLI and dashboard call one core engine. Neither interface contains recon logic.

```
recon_helper_pro/
├── core/
│   ├── engine.py          # orchestrates runs, writes runs/observations/findings
│   ├── module_base.py     # abstract base class for all recon modules
│   ├── registry.py        # discovers & loads BUNDLED modules
│   ├── db.py              # SQLite access layer (WAL mode)
│   ├── models.py         # engagement, scope, asset, run, observation, finding, artifact
│   ├── scope.py          # scope parsing + revalidation (DNS, redirects, metadata block)
│   ├── teaching.py       # loads teaching content by teaching_key
│   ├── safety.py         # authorization, request policy, redaction
│   ├── httpclient.py     # shared HTTP client: budgets, redirects, size limits, UA
│   └── reporting.py      # Markdown report generation
├── modules/
│   ├── osint/            # whois, dns, revdns, subdomains, cert
│   └── web/              # headers, fingerprint, published_files, hints
├── cli/
│   └── main.py
├── web/
│   ├── server.py          # loopback-only; session token; CSRF; strict origin
│   ├── api.py
│   ├── templates/         # output-escaped
│   └── static/
├── teaching_content/       # editable explanation templates & glossary (prose lives here)
├── data/                   # SQLite db & logs (gitignored)
├── exports/                # Markdown reports
├── tests/                  # pytest, mocked network
├── pyproject.toml
└── README.md
```

### 9.2 Module contract
Every module subclasses `ModuleBase` and declares:
- **Identity:** stable `id`, human `name`, `version`, `category`, `mode` (`third-party`/`direct-read`/`enumerative`).
- **Targets:** `supported_target_types`.
- **Teaching:** a `teaching_key` referencing prose in `teaching_content/` (prose is **not** inlined in the module — resolves the v1 tension where Section 6 said files but Section 9 said inline).
- **Config:** a configuration schema (with defaults).
- **Limits:** `request_budget`, `timeout`, `redirect_policy`, `retry_policy`, `scope_requirement`.
- **Tooling:** optional external tools it can use and detection of their versions; a pure-Python fallback flag.
- **Output:** `output_schema_version`.
- **Execution:** `run(context) -> PluginResult`, emitting progress events and honoring cancellation.

Return type:
```python
PluginResult(
    status="completed | partial | failed | cancelled",
    observations=[...],
    findings=[...],
    discovered_assets=[...],   # recorded only, never auto-contacted
    warnings=[...],
    errors=[...],
    metrics={"requests": 3, "duration_ms": 840},
)
```

### 9.3 Module discovery & trust (v1)
The registry loads **only bundled, trusted modules** shipped with the app. Automatic import of user-dropped Python files is **not** enabled in v1 (it would execute arbitrary code). Third-party modules will arrive later via an explicit install + trust model. The architecture stays plugin-shaped so this is additive.

### 9.4 External command execution
When wrapping an external tool, execute it **without a shell**, with an explicit argument list, a timeout, output-size limits, and record the tool's detected version in the run. **Argument-injection hardening (mandatory):**
- Validate and normalize every target **before** it reaches a subprocess. Reject targets that begin with `-`/`--` or contain shell metacharacters or whitespace that a strict host/IP/URL validator would not accept.
- Place a `--` end-of-options separator before user-derived arguments so a crafted target cannot be interpreted as a flag.
- Pass arguments as a list (never a formatted string), and never interpolate target values into a command line.

### 9.5 Pure-Python-first
Every capability has a pip-dependency baseline (e.g. `dnspython`, `python-whois`/RDAP, `httpx`, `cryptography`) and works with **no external binaries**. External tools only add depth when present, and the UI tells the user when installing one would help.

---

## 10. Teaching / companion system (heavy guidance)

- **Explain-before-run**, **explain-the-results**, and **suggested next steps** panels for every module, sourced from `teaching_content/` via each module's `teaching_key`.
- **Glossary:** `rhp define <term>` in the CLI and tooltips in the dashboard.
- **Guided recipe mode:** a step-by-step full-domain recon walkthrough (registration → DNS → CT-log hostnames → cert → live-host check → headers → fingerprint → published files → report), explaining every transition. Interactive by default; a `--non-interactive` flag runs the same sequence unattended for scripting.
- **Verbosity levels:** `beginner` (default, full explanations), `normal` (short hints), `quiet` (results only).
- All teaching prose lives in editable files, never hard-coded in module logic.

---

## 11. CLI requirements

- Built with **Typer** (or Click); rich output via **Rich**.
- Banner with disclaimer on startup.
- Commands (illustrative):
  - `rhp init` — first-run setup + authorization acknowledgment.
  - `rhp engagement new "<name>"` / `list` / `use <id>`.
  - `rhp scope add <entry>` / `scope list` / `scope remove <id>`.
  - `rhp run <module> <target>` — run one module.
  - `rhp recon <domain>` — guided recipe (interactive; `--non-interactive` for scripts).
  - `rhp modules` — list modules, mode, request budget, and detected optional tools.
  - `rhp assets` / `rhp findings` / `rhp runs` — browse stored data.
  - `rhp report [--engagement <id>]` — generate Markdown report.
  - `rhp cancel` — cancel the running module/workflow (also Ctrl-C).
  - `rhp purge [--engagement <id>] [--artifacts-only]` — delete stored raw artifacts, or an engagement's data.
  - `rhp define <term>` — glossary.
  - `rhp web` — launch the local dashboard.
- Respects verbosity setting; exits non-zero on failure for scripting.

---

## 12. Web dashboard requirements

- **Loopback-only:** binds to `127.0.0.1` on a configurable port; never `0.0.0.0`.
- **Hardening (mandatory):** a random per-session token required for all requests; CSRF protection on state-changing endpoints; strict `Origin`/`Host` checking; **no permissive CORS**; all output (including target-controlled strings like hostnames, headers, and page titles) HTML-escaped to prevent XSS; a restrictive Content-Security-Policy on the dashboard itself.
- Backend: **FastAPI + Uvicorn** serving a small JSON API and Jinja2 templates, over the shared core engine and SQLite (WAL).
- Views: dashboard/home, engagement view (assets, findings by category, activity log, runs), run-recon view (pick target + modules, watch progress, teaching panels), finding detail (with "how to read this" + evidence + confidence + limitations), reports (generate/preview/download Markdown), glossary/learn.
- Disclaimer in the footer.

---

## 13. Reporting requirements (Markdown)

A report must include:
- **Header:** engagement name, methodology summary, collection period.
- **Scope & exclusions:** exactly what was authorized and what was not.
- **Versions:** app version, module versions, provider sources used.
- **Coverage:** which checks succeeded, were partial, skipped, or failed.
- **Assets** discovered.
- **Observations** (raw facts) with source and collection timestamp.
- **Findings** (interpretations) with evidence, confidence, limitations, and context-aware severity hints.
- **Direct-contact accounting:** request counts for `direct-read`/`enumerative` operations.
- **Clear separation** between observations, hypotheses/hints, and any validated findings, so a beginner never mistakes an automated hint for a confirmed vulnerability.
- A short glossary of terms used.

Reports are written to `exports/` with a timestamped filename.

---

## 14. Non-functional requirements

- **Cross-platform:** Windows, macOS, Linux (primary dev on Windows 11), verified in CI.
- **Python 3.10+**, installable via `pip install .` / `requirements.txt`; **no external binaries required**.
- **Reliability:** a failing module yields a **partial run**, never a crashed workflow; errors are logged and shown in plain language.
- **Concurrency:** SQLite in WAL mode; a single-writer discipline coordinates CLI and dashboard writes; concurrent writes are serialized safely rather than corrupting data.
- **Testing:** deterministic tests using **recorded/mocked network responses**; no dependency on live services in CI. Core engine, scope logic, redaction, and OSINT modules covered.
- **Logging:** structured logs to file plus the `activity_events` table.
- **Maintainability:** clear module separation, type hints, docstrings.

---

## 15. Build milestones (phased)

**Phase 1 — CLI golden path (MVP core):**
1. Scaffold, config, SQLite (WAL), models (engagement/scope/asset/run/observation/finding/artifact), authorization acknowledgment, activity log.
2. Scope engine: parsing, exact-host semantics, DNS + redirect revalidation, metadata hard-block, lab allowance.
3. Shared HTTP client with budgets, redirect scope-checks, size limits, redaction.
4. OSINT modules: WHOIS/RDAP, DNS, reverse DNS, CT-log hostnames, cert inspection.
5. Web modules: header analysis, lite fingerprint, published-file discovery, interpreted hints.
6. Teaching system + glossary + verbosity.
7. CLI incl. guided `recon` recipe (interactive + `--non-interactive`).
8. Markdown reporting.
9. Deterministic mocked-network tests; cross-platform CI.

**Phase 2 — Dashboard (still v1):**
10. Loopback FastAPI server with full hardening (session token, CSRF, origin checks, escaped output, CSP).
11. Dashboard views over the same engine; teaching panels; report preview/download.
12. Hostile-string rendering tests.

**Later (post-v1):** third-party plugin install/trust model, external-binary integrations, large-signature fingerprinting, deep directory discovery, JSON export, email/contact features.

---

## 16. Acceptance criteria (measurable)

Feature completeness:
- With **no external tools installed**, a new user runs `rhp init`, accepts the notice, creates an engagement, adds scope, and completes `rhp recon <authorized-domain>` end to end.
- OSINT (WHOIS/RDAP, DNS, CT-log hostnames, cert) and web recon (headers, lite fingerprint, published files, hints) all produce structured observations and findings.
- Every module shows beginner "what/why" before and "how to read this" after.
- A Markdown report generates and separates observations, hints, and any validated findings.
- The dashboard shows the same engagements/assets/findings and teaching content.

Usability / safety / reliability (measurable):
- A new user completes the guided workflow and produces a report **within 15 minutes** without external documentation.
- **No direct request is sent to an out-of-scope destination without an explicit logged override**, including after DNS resolution and on redirects; cloud-metadata addresses are never contacted.
- **Every result records** source, collection time, module version, and confidence.
- **A single module failure produces a partial run**, not an aborted workflow.
- **Network tests use recorded/mocked responses** and pass without live services.
- The project passes **Windows, macOS, and Linux CI**.
- The dashboard **safely renders hostile, target-controlled strings** without executing them.
- The report **distinguishes observations, hypotheses/hints, and confirmed findings**.

---

## 17. Notes for the builder

- Prefer clarity and beginner-friendliness over cleverness — this is a learning companion.
- Keep all user-facing explanations in `teaching_content/`; modules reference them by `teaching_key`.
- Default to the safest behavior; make anything that contacts the target explicit, labeled by mode, rate-limited, and scope-checked.
- You may substitute equivalent libraries, but preserve: **pure-Python-first / external-tools-optional**, **no API keys**, **bundled-modules-only in v1**, and all **safety guarantees** in Sections 7 and 12.
- Build CLI and dashboard on the **same core engine** — never duplicate recon logic.

---

## 18. Recommended technology stack

| Concern | Recommendation |
|---|---|
| Language | Python 3.10+ |
| CLI | Typer (or Click) + Rich |
| Web | FastAPI + Uvicorn + Jinja2 |
| DB | SQLite (WAL) via sqlite3 or SQLModel/SQLAlchemy |
| DNS | dnspython |
| WHOIS/RDAP | RDAP over httpx; python-whois or system `whois` as fallback |
| HTTP | httpx |
| TLS/cert | cryptography / stdlib ssl |
| HTML parse | selectolax or BeautifulSoup |
| CT logs | crt.sh JSON endpoint (free, keyless) |
| Testing | pytest + respx/vcr-style recorded responses |
| Packaging | pyproject.toml |

Optional external tools wrapped **only if present** (never required): `whois`, `dig`, `subfinder`, `amass`, `httpx` (ProjectDiscovery). **`nmap` is intentionally excluded** from v1 — it implies a more active direction than the defined feature set.

---

## 19. Open defaults the builder should adopt (unless told otherwise)

- **Raw artifacts:** stored, redacted, retained **30 days by default** then pruned; retention configurable; `rhp purge` for on-demand deletion.
- **Request policy defaults:** as in Section 7.4, including the global per-host (500) and per-engagement (2000) ceilings that act as a kill switch.
- **Encryption at rest:** off by default, one setting to enable.
- **Data location:** configurable; RHP warns if the data directory is inside a cloud-synced/backup folder.
- **Verbosity default:** `beginner`.
- **Lab mode:** private/loopback allowed by default; link-local range and metadata endpoints always blocked, enforced on the normalized, pinned resolved IP.

---

## 20. Changes from v1 (for reviewers)

- Reframed as **learner-first** with one flagship golden path; dashboard kept in v1 (user decision) but build is **phased** behind the CLI.
- Replaced ambiguous "passive/active" with three **contact modes** (`third-party`/`direct-read`/`enumerative`) and per-run request counts.
- Defined **exact-host scope semantics** and explicit entry types (host/wildcard/IP/CIDR/scheme/port, IDN/IPv6).
- Added **scope revalidation** after DNS resolution and on every redirect; **always hard-block cloud-metadata**; kept **warn-but-allow** for other out-of-scope contact per user's explicit choice, with logged overrides.
- **Discovered assets are recorded, never auto-contacted.**
- Added a **runs/job model** and a structured **PluginResult**; split **assets / observations / findings** with full provenance, evidence, and confidence.
- **Bundled-modules-only in v1**; third-party plugins deferred to an explicit trust model.
- **Dashboard hardening** made mandatory (loopback bind, session token, CSRF, strict origin, escaped output, CSP).
- **Report** now includes methodology, versions, coverage, request counts, and strict separation of observations vs findings.
- Added **measurable** usability/safety/reliability/CI acceptance criteria.
- Removed **nmap**; demoted **email/contact harvesting**, large-signature fingerprinting, deep directory discovery, and JSON export to later phases.
- Clarified **"pure Python"** = pip dependencies allowed, no external binaries required; **robots.txt** handling made explicit; **redaction** rules defined.

### Safety hardening added in this revision
- **Address-block hardening (7.3.1):** normalize all IP encodings, block the whole link-local range, and resolve-once-then-pin the connection to the validated IP to defeat DNS rebinding; re-validated on every redirect.
- **Subprocess argument-injection hardening (9.4):** strict target validation, reject leading dashes, `--` separator, list-based args only.
- **Data-at-rest (7.6):** 30-day default retention with auto-prune, `rhp purge`, cloud-synced-folder warning, and optional encryption at rest.
- **Global request ceilings + cancellation (7.4, CLI):** per-host and per-engagement request caps as an automatic kill switch, plus clean cancellation of any run or workflow.
- Note: **warn-but-allow** scope enforcement and **private-allowed-by-default** remain per the user's explicit choices; hardening above reduces their blast radius but does not reverse them.

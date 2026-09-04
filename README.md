# Recon Helper Pro

A learner-first reconnaissance companion for people new to ethical hacking.

It does one thing well: walks you through a guided domain-recon workflow against
a target **you are authorized to test**, explains every step before and after it
runs, records structured evidence with full provenance, and exports a Markdown
report that never lets an automated hint be mistaken for a confirmed
vulnerability.

> **Only point this at systems you own or have written permission to test.**
> Unauthorized access to computer systems is a crime in most jurisdictions.

It ships as two coordinated pieces over one core engine: a **command line**
(`rhp`) and a **local web dashboard** (`rhp web`) that runs on the loopback
interface only. Neither contains recon logic; both drive `core.engine`.

---

## Install

Requires Python 3.10 or newer. No external binaries are needed for anything.

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate

pip install -e .
```

That gives you the `rhp` command. (Everything below also works as
`python -m recon_helper_pro.cli.main ...` if you would rather not install.)

For the test suite:

```bash
pip install -e ".[dev]"
pytest
```

The tests use recorded/mocked responses only - they pass with no network access
and no optional tools installed.

## The golden path

```bash
rhp init                                  # read and accept the agreement
rhp engagement new "My first engagement"
rhp scope add example.com                 # declare what you are authorized to test
rhp recon example.com                     # the guided walkthrough
```

`rhp recon` walks the sequence registration → DNS → reverse DNS → certificate
transparency → TLS certificate → HTTP headers → technology fingerprint →
published files → interpreted hints → report, explaining each transition. Add
`--non-interactive` to run it unattended in a script.

A report lands in `<data dir>/exports/` at the end.

## The dashboard

```bash
rhp web                 # then open the link it prints
rhp web --port 9000 --no-open
```

It binds to `127.0.0.1` only and prints a URL containing a session token, which
is regenerated on every launch. From the browser you can create engagements,
edit scope, run a single module or the whole guided recipe with live progress and
a cancel button, read the teaching panels and glossary, drill into a finding with
its supporting observations, and generate, preview and download reports.

Everything it does goes through the same engine as the CLI, so scope checks,
request budgets, redaction and the activity log apply identically. If a target is
out of scope the page tells you why before anything is sent and makes you tick a
confirmation; if it is hard-blocked, no amount of clicking will send a request.

The hardening is not optional (PRD §12): loopback bind, session cookie
(`HttpOnly`, `SameSite=Strict`), `Host`-header validation, CSRF token plus
`Origin` checking on every state-changing request, no CORS headers at all,
server-side rendering with Jinja autoescaping, and a CSP with no `unsafe-inline`
and no remote origins. Hostile, target-controlled strings are covered by tests
that assert they render as text and never as markup.

One workflow runs at a time, on purpose: it keeps the single-writer discipline on
SQLite simple and stops two concurrent runs from doubling the load on a host.

## Commands

| Command | What it does |
|---|---|
| `rhp init` | First-run setup and the authorization acknowledgment |
| `rhp engagement new/list/use` | Create and switch engagements |
| `rhp scope add/list/remove` | Declare what you are authorized to contact |
| `rhp run <module> <target>` | Run one module |
| `rhp recon <domain>` | The guided recipe (`--non-interactive` for scripts) |
| `rhp modules` | Modules, contact mode, request budget, detected optional tools |
| `rhp assets` / `findings` / `runs` / `activity` | Browse what has been recorded |
| `rhp report [--engagement N] [--show]` | Generate the Markdown report |
| `rhp cancel` | Stop a running module or workflow (Ctrl-C also works) |
| `rhp purge [--artifacts-only] [--expired-only]` | Delete stored raw data |
| `rhp define <term>` | Glossary |
| `rhp config list/set/reset` | Settings |
| `rhp web [--port N] [--no-open]` | Launch the local dashboard |

Global options: `--data-dir <path>`, `--verbosity beginner|normal|quiet`.

## Contact modes

Every module declares exactly one, and it is shown in the UI and recorded per run:

| Mode | What it means | Modules |
|---|---|---|
| `third-party` | Data from resolvers and public providers. **The target is never contacted.** | `whois`, `dns`, `revdns`, `subdomains`, `hints` |
| `direct-read` | A small number of read-only requests to the target. | `cert`, `headers`, `fingerprint` |
| `enumerative` | Several requests to check a fixed list of well-known files. | `published-files` |

## Safety model

- **Scope is explicit and exact.** `example.com` authorizes that host only.
  Subdomains need `*.example.com`; addresses and ranges must be added
  deliberately.
- **Out-of-scope contact warns and asks.** You can override, and the override is
  recorded in the activity log and printed in the report. This is a deliberate
  design decision, not an oversight.
- **Some destinations can never be contacted, whatever the scope says:** the
  entire link-local range (`169.254.0.0/16`, `fe80::/10`) and the known cloud
  metadata endpoints. Private and loopback addresses *are* allowed so you can
  practise against your own lab.
- **Resolve once, then pin.** Hostnames are resolved a single time, the resulting
  address is validated, and the connection goes to that exact address with the
  original `Host` header and TLS SNI. Nothing re-resolves between the check and
  the connection, which closes the DNS-rebinding window. Every address encoding
  (`0xA9FEA9FE`, `2852039166`, `0251.0376.0251.0376`, IPv4-mapped IPv6 …) is
  normalized before it is checked.
- **Every redirect hop is re-validated** by the same procedure, and an override
  never carries across a redirect.
- **Budgets are enforced and act as a kill switch:** a per-run budget, 500
  requests per host per engagement, 2000 per engagement, 1 second between
  requests, a 10 second timeout, and a 2 MB body cap by default.
- **Discovered assets are recorded, never auto-contacted.** Adding one to scope
  is always your decision.
- **robots.txt is honoured as a courtesy**, not as an authorization boundary.
  Disallowed paths are skipped unless you explicitly opt in per run.
- **Optional external tools are executed without a shell**, with list arguments,
  a `--` separator, strict target validation, a timeout and an output cap.

## What is stored, and where

One SQLite database (WAL mode) plus Markdown exports:

| Platform | Default location |
|---|---|
| Windows | `%LOCALAPPDATA%\ReconHelperPro` |
| macOS | `~/Library/Application Support/ReconHelperPro` |
| Linux | `$XDG_DATA_HOME/recon-helper-pro` or `~/.local/share/recon-helper-pro` |

Override with `--data-dir` or the `RHP_DATA_DIR` environment variable.

**Keep this directory out of cloud-synced folders.** It contains hostnames,
headers and anything redaction missed. `rhp init` warns you if it detects
OneDrive, Dropbox, Google Drive, iCloud and similar in the path.

- **Redaction** removes authorization headers, cookie values, tokens, private
  keys and email addresses from everything stored. It is best-effort pattern
  matching, so treat the data store as sensitive regardless.
- **Retention:** raw artifacts are pruned after 30 days by default
  (`rhp config set retention.artifact_days N`, or `rhp purge --expired-only`).
- **Encryption at rest** is off by default. Turning it on
  (`rhp config set encryption.artifacts true` plus an `RHP_PASSPHRASE`
  environment variable) encrypts the stored **artifact files**. The SQLite
  database itself is *not* encrypted - that needs SQLCipher, which is not a
  pure-pip dependency on every platform. Use full-disk encryption for the rest.

## Optional external tools

Never required; used only if they happen to be on your PATH, and reported by
`rhp modules`:

`whois`, `subfinder`, `amass`. `nmap` is deliberately excluded - it implies a
more active posture than this tool has.

## How to read a report

The report keeps three things separate on purpose:

- **Observations** - raw facts, with source, timestamp, module and version.
- **Findings** - *interpretations* of observations, with confidence, limitations
  and a context-aware severity hint.
- **Confirmed findings** - none appear automatically. Verification is yours.

A missing security header is not a vulnerability. A version banner is not a CVE.
The report says so, in those words, every time.

## What is not here yet

The post-v1 items: third-party plugin install/trust, external-binary
integrations beyond the optional wrappers above, large-signature fingerprinting,
deep directory discovery, JSON export, and email/contact harvesting.

## Layout

```
recon_helper_pro/
├── core/              engine, db, scope, safety, httpclient, reporting, teaching
├── modules/osint/     whois, dns, revdns, subdomains, cert
├── modules/web/       headers, fingerprint, published_files, hints
├── cli/               the command line       (no recon logic)
├── web/               the loopback dashboard (no recon logic)
└── teaching_content/  every user-facing explanation, as editable Markdown
tests/                 pytest, mocked network only
```

The CLI and the dashboard both drive `core.engine`. Recon logic lives in exactly
one place.

## Licence

MIT.

## Settings reference

`rhp config list` shows all of these with their current values.

| Key | Default | Notes |
|---|---|---|
| `request.delay_ms` | 1000 | Pause between requests to the same host |
| `request.max_concurrency` | 2 | Upper bound; phase 1 issues requests sequentially |
| `request.enumerative_budget` | 100 | Per-run budget for enumerative modules |
| `request.timeout_s` | 10 | Per-request timeout |
| `request.max_redirects` | 5 | Each hop is re-validated |
| `request.max_body_bytes` | 2097152 | Larger bodies are truncated with a note |
| `request.user_agent` | honest RHP string | Identifies the scan in the target's logs |
| `limits.per_host_requests` | 500 | Kill switch, per host per engagement |
| `limits.per_engagement_requests` | 2000 | Kill switch, per engagement |
| `retention.artifact_days` | 30 | Then pruned by `rhp purge --expired-only` |
| `encryption.artifacts` | false | Encrypts artifact files (needs `RHP_PASSPHRASE`) |
| `verbosity` | beginner | `beginner`, `normal` or `quiet` |
| `lab.allow_private` | true | Set false to block private/loopback targets too |
| `robots.respect` | true | Skip robots-disallowed paths in published-file discovery |
| `scope.enforcement` | warn | `warn` allows a logged override; `block` never does |

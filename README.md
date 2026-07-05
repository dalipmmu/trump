# secret-scout

A local desktop tool that scans a **website** and a **local project** for
leaked API keys and secrets, then gives a consolidated severity summary.

| Technique | What it checks | Where |
|---|---|---|
| 1. Hardcoded client-side secrets | API keys in HTML/JS/CSS sent to the browser | website |
| 2. Exposed source maps | `.js.map` files that rebuild source + hide secrets | website |
| 3. Exposed env/config files | `/.env`, `.git/config`, `.npmrc`, `.aws/credentials`… | website |
| 4. Malicious dependencies | known-bad/typosquat packages + `auth.json` exfiltration code | local project |
| 5. Exposed `.git` repository | live `/.git/` dir → full source + history recoverable (git-dumper); pulls remote-URL creds, `index` file inventory, `logs/HEAD` commit history | website |
| 6. Debug/admin endpoints | Spring Boot `/actuator/env` & `/heapdump`, Go `expvar`/`pprof`, `phpinfo`, Apache `server-status`/`server-info`, Symfony profiler, Prometheus `/metrics` | website |
| 7. Historical exposure (Wayback) | archive.org CDX → fetches archived JS/`.env`/config snapshots and scans them for secrets that were "fixed" but never rotated | website |
| 8. Security headers & TLS posture | missing/weak CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; insecure cookie flags; dangerous CORS (`*` + credentials); outdated TLS / expiring cert | website |
| 9. Admin / database / API surfaces | reachable admin panels (wp-admin, phpMyAdmin, Adminer, Tomcat…), SQL dumps, open Firebase RTDB / Elasticsearch, Swagger/OpenAPI/GraphQL introspection, robots.txt/sitemap mining — **detection only, never logs in or exploits** | website |
| 10. Subdomain / attack-surface enumeration | pulls subdomains from Certificate Transparency logs (crt.sh), flags non-production hosts (dev/staging/admin), optional re-scan of live subdomains | website |

**Evidence for verification:** every finding carries the exact reproduction
(`GET <url> -> 200` + response snippet) in plain view, and the precise value
(remote-URL token, full file list, archived snapshot URL, matched secret) under
`--reveal` / the "show full secret values" toggle — ready to show management.

Technique IDs for `--only`: `t1`=js `t2`=maps `t3`=env `t4`=deps `t5`=git
`t6`=debug `t7`=wayback `t8`=headers/TLS `t9`=admin/db/API `t10`=subdomains.
Example: `--only t5,t6,t8`.

**Detection patterns now also cover:** Anthropic (Claude), Hugging Face, Groq,
Replicate, Perplexity, Cohere, Razorpay (Key ID + key/webhook secret), Stripe
publishable keys, Google service-account JSON, and Sentry DSNs — plus a
**Shannon-entropy pass** that catches custom/in-house keys with no known prefix,
**JWT decoding** that flags `alg:none` / no-expiry / PII-bearing tokens, and an
**allowlist** that downgrades values that are public by design (Razorpay Key ID,
Stripe publishable key, Sentry DSN) to Info so they never inflate the Critical
count.

## Run

```bash
pip install -r requirements.txt
python -m secretscout.cli ui          # dashboard + optional API at :5000
# or
python -m secretscout.cli scan https://example.com --project ./my-app --out report.json
```

Double-click launchers are included: `run.bat` (Windows), `secret-scout.app` /
`run.command` (macOS), `run.sh` (Linux). See **QUICKSTART.md**.

## Highlights
- **Live secret validation** (opt-in, read-only): confirms whether a discovered
  credential is actually **active** by making a single read-only call to its
  provider (OpenAI, Anthropic, Stripe, GitHub, Slack, SendGrid, Mailgun, Google,
  Hugging Face, Groq, Replicate, plus **AWS** STS GetCallerIdentity, **Razorpay**
  and **Twilio** when both halves of the key pair are found). Findings are marked
  **CONFIRMED LIVE** / revoked, and any live key is **auto-escalated to
  Critical** and highlighted across the dashboard, reports and attack chains.
  Nothing is ever sent, created or changed. Enable with the dashboard checkbox or
  `--validate`. (AWS validation uses `boto3` if installed.)
- **Dependency CVE mapping** (opt-in, `--cve` or dashboard checkbox): maps pinned
  dependency versions to known advisories via the OSV.dev API, and flags
  typosquats / dependency-confusion against popular packages.
- **Beyond API keys**: detects credentials, database connection strings,
  payment cards (Luhn-validated), PII (emails, SSNs), and infrastructure intel
  (internal IPs/hosts, S3 buckets, cloud-metadata refs) across every technique.
- **Data-class tagging**: every finding is tagged Credential / Financial / PII /
  Source / Infra, with a per-finding **"potential breach impact"** line written
  for leadership.
- **Attack chains**: the report shows how findings combine into a kill chain
  (e.g. *Exposed .git → read source → admin route via /actuator/mappings → DB
  creds via /actuator/env → old un-rotated commit → dump PII → full breach*),
  with the exact evidence URL behind every hop.
- **Executive framing**: a "why this matters" summary that reframes findings as
  business risk to drive rotation + remediation.
- **Whole-site crawl** (optional): scan every same-host page, not just the entry page.
- **Report export**: download HTML or PDF reports (full technical or plain-English).
- **Plain-English summary**: a non-technical report giving the exact step-by-step
  process + data for each issue, that anyone can follow.
- **Optional agent REST API** (token-protected).

## Layout
```
secret-scout/
├─ secretscout/
│  ├─ engine.py            orchestrates the 4 techniques (+ crawl)
│  ├─ crawler.py           same-host whole-site crawler
│  ├─ patterns.py          secret regexes + redaction
│  ├─ fetcher.py           HTTP + same-origin asset discovery
│  ├─ storage.py           findings store + summary
│  ├─ walkthrough.py       plain-English exploit/verify steps
│  ├─ report_export.py     HTML + PDF report builders (full/simple)
│  ├─ report.py            console summary
│  ├─ webapp.py            Flask dashboard + report downloads + REST API
│  ├─ cli.py               command-line entry
│  ├─ scanners/            js_secrets · source_maps · env_files · dependencies
│  │                       · git_repo · debug_endpoints · wayback
│  ├─ data/known_bad_packages.json   editable supply-chain list
│  └─ templates/dashboard.html
├─ launcher.py · run.bat · run.sh · run.command · secret-scout.app
├─ assets/ (icon) · requirements.txt · QUICKSTART.md
└─ _selftest_site.py · _selftest_proj/   safe local targets to try
```

## Self-test (safe)
```bash
python _selftest_site.py            # serves http://127.0.0.1:8077
python -m secretscout.cli scan http://127.0.0.1:8077 --project ./_selftest_proj --no-home-check
```
You should see Critical findings for all four techniques.

## Agent / REST API
`POST /api/scan` with JSON `{"url","project","only","no_home_check"}`. Protect it
with a bearer token (`python -m secretscout.cli ui --api-token TOKEN`) or disable
it (`--no-api`). Details in QUICKSTART.md.

⚠️ Authorised use only — techniques 1–3 send live requests to the target.

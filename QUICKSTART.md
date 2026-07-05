# secret-scout — Quick start (Windows)

**secret-scout** finds leaked API keys & secrets using four techniques:

1. **Hardcoded secrets in client-side JavaScript/HTML/CSS** — fetches pages and
   their same-origin scripts/styles and matches 18+ key formats (OpenAI `sk-`,
   AWS, GitHub, Stripe, Google, JWTs, private keys, generic `api_key=`…).
2. **Exposed source maps** — finds `.js.map` files, flags the exposure, and
   reconstructs the original source to hunt for hidden secrets.
3. **Exposed environment/config files** — probes `/.env` and friends
   (`.env.local`, `.git/config`, `.npmrc`, `.aws/credentials`, …).
4. **Malicious dependencies (supply chain)** — scans a local project's
   `package.json`/`requirements.txt` against a known-bad list + typosquat
   heuristics, and flags code that reads a credential file (e.g. `auth.json`)
   **and** makes a network/exec call (the token-stealer pattern).

## 1. Install Python (one-time)
Open Command Prompt → `py --version`. If missing, install from
<https://www.python.org/downloads/> and **tick "Add Python to PATH."**

## 2. Run it (double-click)
- Unzip `secret-scout.zip`.
- Double-click **`run.bat`** (or `Create Desktop Shortcut (Windows).bat` once for
  a desktop icon).

First launch builds a private environment, installs dependencies (including the
PDF library), and opens the dashboard at **http://127.0.0.1:5000**.

## 3. Use the dashboard
- **Target website** → techniques 1–3.
- **Local project folder** → technique 4 (e.g. `C:\code\my-app`).
- **Crawl the whole site** → tick this to scan every page (not just the entry
  page); set "Max pages" to control how far it goes.
- Pick techniques, then **Run scan**.
- **Show full secret values** → tick this to display the **exact** leaked
  secrets (instead of `sk-1…[23 chars]`) so you can verify and fix them. Off by
  default; reports made with it on are watermarked "Confidential". Keep them secure.
- Results show a severity roll-up + per-technique breakdown, with two tabs:
  - **Technical findings** — full detail + evidence (secrets redacted) + fix.
  - **Plain-English walkthrough** — numbered steps anyone can follow to *see*
    each issue on your own site, what it means, and what to do.

## 4. Download a report
After a scan, use the **Download report** buttons:
- **Full report (HTML / PDF)** — the complete technical write-up.
- **Plain-English summary (HTML / PDF)** — *only* the simple step-by-step
  process + data, written for someone with no IT background.

## 5. Optional: the agent API
Start with a token (recommended):
```
py launcher.py MY-SECRET-TOKEN
```
Then an agent can call:
```
POST http://127.0.0.1:5000/api/scan
Authorization: Bearer MY-SECRET-TOKEN
Content-Type: application/json

{"url":"https://example.com","project":"C:/code/app",
 "crawl":true,"max_pages":40,"only":["t1","t2","t3","t4"]}
```
The JSON response includes `summary`, `findings`, and `walkthrough`.
No token → API open on localhost. Disable with `py -m secretscout.cli ui --no-api`.

## Command line (no browser)
```
py -m secretscout.cli scan https://example.com --crawl --max-pages 40 ^
   --html-out report.html --pdf-out report.pdf
py -m secretscout.cli scan https://example.com --reveal --pdf-out report-FULL.pdf
py -m secretscout.cli scan https://example.com --pdf-out summary.pdf --report-mode simple
py -m secretscout.cli scan --project ./app --only t4
```

> **Exact evidence:** add `--reveal` (CLI), tick **Show full secret values**
> (dashboard), or send `"reveal": true` (API) to get the complete secret for
> management verification. Without it, evidence stays redacted.

## Keeping technique 4 current
Edit `secretscout/data/known_bad_packages.json` to add newly-disclosed malicious
packages — no code changes needed.

⚠️ **Authorised use only.** Techniques 1–3 send real requests to the target;
only scan sites and machines you own or are explicitly permitted to test.

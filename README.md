# 🔍 SecretScout PRO

**Professional API Vulnerability Detection Tool**

A comprehensive, enterprise-grade tool for finding API glitches, leaks, private keys, exposed credentials, and security flaws in websites and applications. Built for security researchers, bug bounty hunters, and DevOps teams.

![SecretScout PRO Dashboard](https://img.shields.io/badge/Status-Active-brightgreen) ![License](https://img.shields.io/badge/License-MIT-blue) ![Python](https://img.shields.io/badge/Python-3.8%2B-orange) ![Version](https://img.shields.io/badge/Version-2.0.0-purple)

## 🚀 Features

### 🎯 **15 Advanced Scanning Techniques**

| Technique | Description | Severity |
|-----------|-------------|----------|
| **T1** | Hardcoded client-side secrets | 🔴 Critical |
| **T2** | Exposed source maps | 🟠 High |
| **T3** | Exposed env/config files | 🔴 Critical |
| **T4** | Malicious dependencies | 🔴 Critical |
| **T5** | Exposed .git repository | 🔴 Critical |
| **T6** | Debug/admin endpoints | 🟠 High |
| **T7** | Historical exposure (Wayback) | 🔴 Critical |
| **T8** | Security headers & TLS posture | 🟡 Medium |
| **T9** | Admin/database/API surfaces | 🟠 High |
| **T10** | Subdomain enumeration | 🟡 Medium |
| **T11** | API endpoint discovery | 🟠 High |
| **T12** | API key validation | 🔴 Critical |
| **T13** | CORS misconfiguration | 🟠 High |
| **T14** | Rate limit testing | 🟡 Medium |
| **T15** | Error message analysis | 🟡 Medium |

### 🔑 **Comprehensive API Key Detection**

Detects **50+ types of secrets** including:

- **AI Services**: OpenAI, Anthropic (Claude), Hugging Face, Groq, Replicate, Perplexity, Cohere
- **Cloud Services**: AWS Access Keys, Google API Keys, Google Service Accounts
- **Development**: GitHub Tokens, GitHub OAuth Tokens
- **Payment Processors**: Stripe (Secret & Publishable), Razorpay (Key ID & Secret), SendGrid, Mailgun
- **Communication**: Slack Tokens, Twilio API Keys
- **Authentication**: JWT Tokens, Private Keys (PEM, SSH)
- **Generic Patterns**: api_key, apikey, secret, token, password
- **Sensitive Data**: Credit Card Numbers, SSNs, Email Addresses, Phone Numbers
- **Infrastructure**: Database Connection Strings, AWS S3 Buckets, Internal IPs

### 🎪 **Live Secret Validation**

**Read-only validation** of discovered API keys to confirm they're active:

- ✅ OpenAI API Keys
- ✅ Anthropic API Keys  
- ✅ GitHub Tokens
- ✅ Stripe API Keys
- ✅ Razorpay Keys
- ✅ Google API Keys
- ✅ Slack Tokens
- ✅ SendGrid API Keys
- ✅ Hugging Face Tokens

*Live keys are auto-escalated to **CRITICAL** severity and highlighted in reports.*

### 📊 **Advanced Analysis**

- **Shannon Entropy Analysis**: Detects high-entropy strings that look like secrets
- **JWT Token Decoding**: Checks for `alg: none` vulnerabilities and PII in payloads
- **Attack Chain Analysis**: Shows how findings combine into kill chains
- **Risk Scoring**: Overall risk score (0-100) with severity classification
- **Data Classification**: Tags findings as Credential, Financial, PII, Source, or Infra

### 🌐 **Web Dashboard**

- **Real-time Scanning**: Start scans and monitor progress
- **Interactive Results**: Filter, sort, and explore findings
- **Multiple Views**: Technical findings + Plain-English walkthroughs
- **Report Download**: JSON, HTML, PDF formats
- **Scan History**: Track all previous scans
- **REST API**: Automate scanning via API calls

### 📈 **Comprehensive Reporting**

**Technical Reports**:
- Detailed findings with evidence
- Severity breakdowns
- Attack chain visualization
- Remediation steps
- Risk assessment

**Plain-English Reports**:
- Business impact explanations
- Step-by-step verification instructions
- Non-technical language
- Executive summaries

### 🛡️ **Security Features**

- **Rate Limiting**: Configurable delays between requests
- **Concurrent Requests**: Controlled parallelism
- **Error Handling**: Graceful failure recovery
- **Secret Redaction**: Optional full secret value display
- **API Token Protection**: Secure REST API access

## 📦 Installation

### Quick Start

```bash
# Clone the repository
git clone https://github.com/dalipmmu/trump.git
cd trump

# Install dependencies
pip install -r requirements.txt

# Run a scan
python -m secretscout.cli scan https://example.com

# Start the web dashboard
python -m secretscout.cli ui --port 5000
```

### Using the Launcher

```bash
# The launcher creates a virtual environment and installs dependencies
python launcher.py

# With API token protection
python launcher.py MY-SECRET-TOKEN
```

## 🚀 Usage Examples

### Command Line Interface

```bash
# Basic scan
python -m secretscout.cli scan https://example.com

# Scan with specific techniques only
python -m secretscout.cli scan https://example.com --only t1,t2,t3,t4

# Full scan with crawling
python -m secretscout.cli scan https://example.com --crawl --max-pages 100

# Scan with live key validation
python -m secretscout.cli scan https://example.com --validate --reveal

# Scan a local project for malicious dependencies
python -m secretscout.cli scan --project ./my-app --only t4

# Generate reports
python -m secretscout.cli scan https://example.com --html-out report.html --pdf-out report.pdf

# Plain-English report
python -m secretscout.cli scan https://example.com --report-mode simple --pdf-out summary.pdf

# List all available techniques
python -m secretscout.cli list-techniques
```

### REST API

```bash
# Start with API token
python launcher.py MY-SECRET-TOKEN

# Scan via API
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Authorization: Bearer MY-SECRET-TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com", "crawl": true, "only": ["t1", "t2", "t3"]}'

# Get scan results
curl http://127.0.0.1:5000/api/scan/SCAN_ID/results \
  -H "Authorization: Bearer MY-SECRET-TOKEN"
```

### Python Library

```python
from secretscout.engine import Engine, ScanConfig
from secretscout.storage import FindingStore

# Create scan configuration
config = ScanConfig(
    url="https://example.com",
    techniques=["t1", "t2", "t3", "t4", "t5"],
    crawl=True,
    max_pages=50,
    validate_keys=True,
    reveal_secrets=False
)

# Create and run engine
engine = Engine(config)
result = engine.scan(config)

# Access findings
for finding in result.store.findings:
    print(f"[{finding.severity.value}] {finding.title}")
    print(f"  URL: {finding.url}")
    print(f"  Impact: {finding.impact}")
    print()

# Get summary
summary = result.get_summary()
print(f"Risk Score: {summary['risk_score']}/100 ({summary['risk_level']})")
```

## 🎯 Technique Details

### T1: Hardcoded Client-Side Secrets
Scans HTML, JavaScript, and CSS files for API keys and credentials exposed to the browser.

### T2: Exposed Source Maps
Finds `.js.map` and `.css.map` files that can reveal original source code and hidden secrets.

### T3: Exposed Config Files
Detects exposed configuration files like `.env`, `.git/config`, `.npmrc`, `.aws/credentials`.

### T4: Malicious Dependencies
Scans `package.json` and `requirements.txt` for known malicious packages and typosquats.

### T5: Exposed .git Repository
Finds accessible `.git/` directories that can reveal full source code and commit history.

### T6: Debug/Admin Endpoints
Detects exposed debug endpoints like `/actuator/env`, `/phpinfo`, `/pprof`, etc.

### T7: Historical Exposure (Wayback)
Queries Wayback Machine for archived versions of JS files, .env files, and configs.

### T8: Security Headers & TLS
Checks for missing or weak security headers (CSP, HSTS, X-Frame-Options) and TLS configuration.

### T9: Admin/Database/API Surfaces
Finds exposed admin panels, database interfaces, API documentation, and management interfaces.

### T10: Subdomain Enumeration
Uses Certificate Transparency logs to discover subdomains, especially non-production ones.

### T11: API Endpoint Discovery
Extracts and tests API endpoints from JavaScript code and HTML content.

### T12: API Key Validation
**Read-only** validation of discovered API keys to confirm they're active.

### T13: CORS Misconfiguration
Detects dangerous CORS configurations like wildcard origins with credentials.

### T14: Rate Limit Testing
Tests for missing rate limiting by making rapid requests.

### T15: Error Message Analysis
Checks error responses for information leaks like stack traces and database queries.

## 🏆 Bounty Hunting Focus

SecretScout PRO is **optimized for bug bounty hunting** with special attention to:

- **Razorpay Key Detection**: Finds both Key IDs and Secret Keys (like the example that earned your friend a bounty)
- **Payment Processor Keys**: Stripe, PayPal, Square, etc.
- **Cloud Credentials**: AWS, Google Cloud, Azure
- **API Gateway Keys**: All major API providers
- **Database Credentials**: Connection strings and credentials
- **Admin Interfaces**: Exposed management panels

## 📊 Example Output

```
Starting scan of https://example.com
Techniques: t1, t2, t3, t4, t5, t6, t7, t8, t9, t10
Crawl: Yes
--------------------------------------------------

==================================================
SCAN SUMMARY
==================================================
Scan ID: abc123def456
Target: https://example.com
Duration: 15.23 seconds
Total Findings: 8

Findings by Severity:
  CRITICAL: 3
  HIGH: 2
  MEDIUM: 2
  LOW: 1

Findings by Technique:
  t1 (Hardcoded client-side secrets): 2
  t3 (Exposed env/config files): 1
  t5 (Exposed .git repository): 1
  t6 (Debug/admin endpoints): 1
  t8 (Security headers & TLS posture): 2
  t12 (API key validation): 1

Risk Score: 85.5/100 (CRITICAL)

==================================================
FINDINGS
==================================================

[CRITICAL] Razorpay Key Secret found in https://example.com/config.js
  Technique: t1 - Hardcoded client-side secrets
  URL: https://example.com/config.js
  Data Class: Financial
  Secret: rzp_live_abc...xyz123
  Impact: Exposure of Razorpay secret key could allow unauthorized transactions
  Remediation: Remove key from client-side code, use server-side configuration
  STATUS: CONFIRMED LIVE
```

## 🛠️ Configuration

### Scan Options

| Option | Description | Default |
|--------|-------------|---------|
| `--url` | Target website URL | Required |
| `--project` | Local project path | None |
| `--only` | Specific techniques to run | All |
| `--exclude` | Techniques to exclude | None |
| `--crawl` | Crawl entire website | False |
| `--max-pages` | Maximum pages to crawl | 50 |
| `--max-depth` | Maximum crawl depth | 5 |
| `--reveal` | Show full secret values | False |
| `--validate` | Validate discovered API keys | False |
| `--delay` | Delay between requests (seconds) | 0.1 |
| `--max-concurrent` | Maximum concurrent requests | 10 |

### Environment Variables

```bash
# API token for web dashboard
export SECRETSCOUT_API_TOKEN=my-secret-token

# Maximum concurrent requests
export SECRETSCOUT_MAX_CONCURRENT=20

# Request delay
export SECRETSCOUT_DELAY=0.2
```

## 🔧 Customization

### Adding Custom Patterns

Edit `secretscout/patterns.py` to add your own secret patterns:

```python
from secretscout.patterns import SecretPattern
import re

# Add custom pattern
CUSTOM_PATTERNS = [
    SecretPattern(
        name="My Custom API Key",
        pattern=re.compile(r'myapi_[a-zA-Z0-9]{20,}', re.IGNORECASE),
        severity="critical",
        data_class="Credential",
        provider="myapi"
    )
]
```

### Updating Known Bad Packages

Edit `secretscout/data/known_bad_packages.json` to add newly discovered malicious packages:

```json
{
  "malicious-package": {
    "name": "malicious-package",
    "description": "Steals environment variables",
    "reference": "https://security-advisory.com",
    "severity": "critical",
    "type": "data_exfiltration"
  }
}
```

## 🚨 Security & Ethics

### ⚠️ **IMPORTANT: Authorized Use Only**

- **Only scan websites and systems you own or have explicit permission to test**
- **Do not scan production systems without authorization**
- **Respect robots.txt and rate limiting**
- **Do not attempt to exploit vulnerabilities**
- **Report findings responsibly**

### Ethical Guidelines

1. **Get Permission**: Always obtain written permission before scanning
2. **Scope Limitation**: Stay within agreed scope
3. **Data Protection**: Handle discovered secrets responsibly
4. **Reporting**: Report vulnerabilities to the appropriate parties
5. **Compliance**: Follow all applicable laws and regulations

## 📚 Documentation

- **Quick Start**: See `QUICKSTART.md`
- **API Documentation**: Available in the web dashboard
- **Technique Details**: Run `python -m secretscout.cli list-techniques`

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

MIT License - see `LICENSE` file for details.

## 🙏 Acknowledgments

- Inspired by the original secret-scout project
- Built with Python and Flask
- Uses regex patterns from various open-source security tools
- Special thanks to the security research community

## 📞 Support

- **Issues**: Report bugs and feature requests in GitHub Issues
- **Questions**: Ask in GitHub Discussions
- **Security**: Report security vulnerabilities responsibly

---

**🔍 Happy Hunting!**

*Find those API keys, earn those bounties, secure the web!*

*Built with ❤️ for the security community*
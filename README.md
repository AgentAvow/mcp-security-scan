# MCP Security Scan

[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-MCP%20Security%20Scan-blue?logo=github)](https://github.com/marketplace/actions/mcp-security-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Security scanner for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers. Finds hardcoded secrets, unsafe execution patterns, data exfiltration risks, filesystem access issues, code obfuscation, and missing authentication.

Available as a **GitHub Action** and a **CLI tool**.

---

## Why?

We statically scanned **7,029 public MCP servers** (part of a 35,689-endpoint agent-ecosystem corpus):

- **9% — nearly 1 in 11 — ship at least one high or critical issue** detectable by static analysis alone
- Most common: hardcoded secrets, unsafe shell/exec with user-controllable input, credential-exfiltration paths, filesystem access far broader than advertised

Full prevalence data + methodology: [Agent Tool Supply-Chain Security: Prevalence from 35,689 Scans](https://github.com/AgentAvow/AgentAvow/blob/main/docs/research/agent-tool-supply-chain-prevalence-2026.md).

MCP servers run on your machine with access to your files, shell, and API keys — and increasingly get called in a loop by autonomous agents with nobody watching. Recent incidents like [GitLost](https://noma.security/blog/gitlost-how-we-tricked-githubs-ai-agent-into-leaking-private-repos/) (GitHub's AI agent tricked into leaking private repos) and [MCPoison / CVE-2025-54136](https://nvd.nist.gov/vuln/detail/CVE-2025-54136) (the Cursor `mcp.json` rug-pull) live on this exact attack surface. Most MCP servers have no security review process.

## What it detects

Twelve finding categories, all open source:

| Category | Examples |
|----------|----------|
| `secret` | Hardcoded API keys, tokens, credentials |
| `unsafe_exec` | `shell=True` with user input, `eval`/`exec` on external data |
| `exfiltration` | Env vars / secrets piped into network calls |
| `fs_access` | "Read a file" servers that can walk the entire home directory |
| `obfuscation` | Base64-packed or dynamically-assembled code |
| `dynamic_remote_load` | Rug-pulls: fetch-then-exec, curl\|sh, unpinned npx/uvx, **manifest-exec (the MCPoison / CVE-2025-54136 class)** |
| `hidden_unicode` | Invisible Unicode Tags, bidi controls (Trojan Source), zero-width chars smuggling instructions past review |
| `prompt_injection` | Instruction-override / hide-from-user / exfil directives in tool descriptions, `mcp.json`, `SKILL.md` |
| `insecure_deserialization` | `pickle.loads`, unsafe `yaml.load`, `torch.load` on untrusted data |
| `install_hook` | npm `preinstall`/`postinstall` scripts that fetch, eval, or pipe to shell |
| `toxic_flow` | **The lethal trifecta (the GitLost class)**: private-data read + untrusted input + outbound send composing in one tool |
| Missing auth | Tool endpoints with no authentication boundary |

The hosted scanner at **[agentgraph.co/check](https://agentgraph.co/check)** adds what a local one-shot scan structurally can't: every verdict **signed as an offline-verifiable attestation** (Ed25519/JWS), **tool-definition pinning** with **drift detection** across re-scans (a tool that changes after you vetted it fails verification), and vulnerable-dependency intelligence from a 35,689-endpoint scan corpus.

---

## Quick Start

### GitHub Action (recommended)

Add this to `.github/workflows/mcp-security.yml`:

```yaml
name: MCP Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: AgentAvow/mcp-security-scan@v1
        with:
          fail-on: critical
```

That's it. The action will:
- Scan your repository for security issues
- Post a detailed comment on pull requests
- Fail the check if critical findings are detected

### CLI

```bash
pip install mcp-security-scan

# Scan any MCP server repo on GitHub
mcp-security-scan owner/repo

# Scan the current repo (auto-detects from git remote)
mcp-security-scan

# JSON output for programmatic use
mcp-security-scan owner/repo --format json

# Fail CI on critical findings
mcp-security-scan owner/repo --fail-on critical
```

---

## Advanced Usage

### Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `repo` | GitHub repo to scan (`owner/repo`). Defaults to the current repository. | Current repo |
| `token` | GitHub token for API access | `${{ github.token }}` |
| `fail-on` | Fail the check if findings at or above this severity: `critical`, `high`, or `medium` | `critical` |
| `format` | Output format: `text`, `json`, `github` | `github` |

### Action Outputs

| Output | Description |
|--------|-------------|
| `trust-score` | Trust score from 0-100 |
| `findings-count` | Total number of security findings |
| `critical-count` | Number of critical-severity findings |
| `report` | Full scan report as JSON |

### Using Outputs in Your Workflow

```yaml
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: AgentAvow/mcp-security-scan@v1
        id: scan
        with:
          fail-on: high

      - name: Check trust score
        if: steps.scan.outputs.trust-score < 50
        run: echo "Trust score is below 50 — review findings"
```

### Scanning a Different Repository

```yaml
- uses: AgentAvow/mcp-security-scan@v1
  with:
    repo: some-org/their-mcp-server
    token: ${{ secrets.GITHUB_TOKEN }}
```

### CLI Flags

| Flag | Description | Default |
|------|-------------|---------|
| `repo` | GitHub repo (`owner/repo`) | Auto-detect from git remote |
| `--token` | GitHub API token | `$GITHUB_TOKEN` env var |
| `--format` | Output format: `text`, `json`, `github` | `text` |
| `--output`, `-o` | Write JSON report to file | -- |
| `--fail-on` | Exit code 1 if findings at this severity or above: `critical`, `high`, `medium` | -- |

---

## What It Scans

The scanner checks for **6 categories** of security issues:

### :key: Hardcoded Secrets (critical/high)
- AWS access keys and secret keys
- OpenAI, Anthropic, Google API keys
- GitHub tokens, Slack tokens, Stripe keys
- Private key blocks (RSA, etc.)
- Generic API key and password assignments

### :warning: Unsafe Execution (critical/high)
- `subprocess.run()`, `os.system()`, `os.popen()` (Python)
- `shell=True` in subprocess calls (Python -- critical)
- `eval()`, `exec()` (Python/JS)
- `child_process`, `execSync` (Node.js)
- `Command::new` (Rust), `exec.Command` (Go)

### :file_folder: Filesystem Access (medium/high)
- Unrestricted file read/write operations
- Path traversal patterns (`../`)
- Recursive delete (`shutil.rmtree`, `rimraf`)

### :satellite: Data Exfiltration (high/critical)
- Outbound HTTP requests with sensitive data
- Encoded data transmission patterns
- Suspicious network calls in unexpected contexts

### :detective: Code Obfuscation (high)
- Base64-encoded code execution
- Dynamic code generation patterns
- Obfuscated variable names and control flow

### :white_check_mark: Positive Security Signals (reduce risk)
- Authentication and authorization checks
- Input validation (Zod, Pydantic, JSON Schema)
- Rate limiting
- CORS configuration
- Security headers (Helmet, CSP)

---

## Example PR Comment

When the action runs on a pull request, it posts a comment like this:

> ## MCP Security Scan Results
>
> :white_check_mark: **Trust Score: 85/100** (Good)
>
> - :white_check_mark: **Credential Theft** -- Clear
> - :white_check_mark: **Data Exfiltration** -- Clear
> - :warning: **Unsafe Execution** -- 2 findings
> - :white_check_mark: **Filesystem Access** -- Clear
> - :white_check_mark: **Code Obfuscation** -- Clear
>
> | Metric | Value |
> |--------|-------|
> | Files scanned | 45 |
> | Language | Python |
> | Positive signals | Input validation, Rate limiting |
>
> <details>
> <summary>Findings (2)</summary>
>
> | Severity | Category | Name | File | Line |
> |----------|----------|------|------|------|
> | high | unsafe_exec | subprocess.run | `src/tools.py` | 42 |
> | medium | unsafe_exec | os.popen | `src/utils.py` | 18 |
>
> </details>

---

## Trust Score

Each scanned repo receives a score from 0 to 100:

| Factor | Impact |
|--------|--------|
| Base score | **70** |
| Critical finding | **-15** each |
| High finding | **-8** each |
| Medium finding | **-3** each |
| Positive security signal | **+5** each |
| Has README | **+5** |
| Has LICENSE | **+5** |
| Has tests | **+5** |

---

## Contributing

Found a false positive? Missing a detection pattern? PRs welcome.

**Good first issues:**
- Add detection for more secret patterns (Twilio, SendGrid, etc.)
- Reduce false positives on path traversal in test files
- Add support for local directory scanning (not just GitHub repos)
- Add SARIF output format for GitHub Code Scanning integration

---

## License

MIT -- see [LICENSE](LICENSE).

---

Built by [AgentAvow](https://agentgraph.co) -- trust infrastructure for AI agents.

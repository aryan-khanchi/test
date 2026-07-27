"""
Agent Skill Scanner
--------------------
A small HTTP service that inspects a single "agent skill" markdown file
(YAML frontmatter + markdown body) and reports which of four vulnerability
categories it appears to contain:

  * hardcoded_secret       - a literal credential embedded in the file
  * prompt_injection       - a step that tries to override user/agent control
  * excessive_permissions  - a broader filesystem/network grant than the task needs
  * unclear_provenance     - missing author/version/changelog, or a silent
                             self-rewrite of version metadata

Design notes:
  - Everything runs locally with regexes + a YAML parse. No outbound network
    calls, no LLM calls -> fast, deterministic, and won't time out.
  - Because false positives on genuinely clean files are penalized harder
    than missed detections (see grading: F-beta, beta=0.5), every pattern
    below is fairly specific, and matches are suppressed when they sit next
    to negation/placeholder/example language ("not", "never", "e.g.",
    "placeholder", "${ENV_VAR}", etc).
"""

import json
import re

import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

VALID_CATEGORIES = [
    "hardcoded_secret",
    "prompt_injection",
    "excessive_permissions",
    "unclear_provenance",
]

# ---------------------------------------------------------------------------
# Frontmatter parsing
# ---------------------------------------------------------------------------

FRONTMATTER_RE = re.compile(r"^\s*---\s*\n(.*?\n)---\s*\n?", re.DOTALL)


def split_frontmatter(text):
    """Return (frontmatter_dict, frontmatter_raw, body_text)."""
    text = text.lstrip("\ufeff")
    m = FRONTMATTER_RE.match(text)
    if not m:
        return {}, "", text
    raw = m.group(1)
    body = text[m.end():]
    try:
        data = yaml.safe_load(raw)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    return data, raw, body


# ---------------------------------------------------------------------------
# Shared suppression logic (reduces false positives)
# ---------------------------------------------------------------------------

SUPPRESS_CONTEXT_RE = re.compile(
    r"\b(e\.g\.|eg\.|example|for instance|sample|placeholder|dummy|fake|"
    r"redacted|never|do not|don't|avoid|instead of|rather than|not a real|"
    r"must not|should not|no longer)\b",
    re.IGNORECASE,
)

NEGATION_RE = re.compile(
    r"\b(no|not|never|without needing|don't|doesn't|isn't|shouldn't|avoid|"
    r"restricted to|limited to|only|scoped to|read-only)\b",
    re.IGNORECASE,
)


def _any_unsuppressed_match(text, patterns, neg_window=45, use_negation=True):
    """Return True if any pattern matches text without nearby suppression context."""
    for pat in patterns:
        for m in pat.finditer(text):
            start = max(0, m.start() - neg_window)
            end = min(len(text), m.end() + neg_window)
            context = text[start:end]
            if SUPPRESS_CONTEXT_RE.search(context):
                continue
            if use_negation and NEGATION_RE.search(text[start:m.start()]):
                continue
            return True
    return False


# ---------------------------------------------------------------------------
# 1) hardcoded_secret
# ---------------------------------------------------------------------------

SECRET_LITERAL_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
    re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{24,}"),
]

KEYVALUE_SECRET_RE = re.compile(
    r"(?i)\b"
    r"(x[-_]?api[-_]?key|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
    r"client[_-]?secret|secret|token|auth[_-]?token|password|passwd|pwd|"
    r"webhook[_-]?url)"
    r"\b\s*[:=]\s*[\"']?([^\s\"'#]{6,})[\"']?"
)

ENV_REF_RE = re.compile(
    r"os\.environ|process\.env|ENV\[|getenv|env_var|secrets\.get|vault:|"
    r"keyring|^\$\{?[A-Z_][A-Z0-9_]*\}?$",
    re.IGNORECASE,
)

PLACEHOLDER_VALUE_RE = re.compile(
    r"your[-_]?|<.*>|xxx|changeme|example\.com|placeholder|insert|todo|"
    r"dummy|sample|fake|redacted|\.\.\.",
    re.IGNORECASE,
)


def find_hardcoded_secrets(full_text):
    for pat in SECRET_LITERAL_PATTERNS:
        for m in pat.finditer(full_text):
            start = max(0, m.start() - 40)
            end = min(len(full_text), m.end() + 40)
            if SUPPRESS_CONTEXT_RE.search(full_text[start:end]):
                continue
            return True

    for m in KEYVALUE_SECRET_RE.finditer(full_text):
        value = m.group(2)
        if ENV_REF_RE.search(value) or PLACEHOLDER_VALUE_RE.search(value):
            continue
        if value.lower() in ("true", "false", "null", "none", "read", "write", "n/a"):
            continue
        start = max(0, m.start() - 40)
        end = min(len(full_text), m.end() + 40)
        if SUPPRESS_CONTEXT_RE.search(full_text[start:end]):
            continue
        if len(value) >= 6:
            return True
    return False


# ---------------------------------------------------------------------------
# 2) prompt_injection
# ---------------------------------------------------------------------------

INJECTION_PATTERNS = [
    re.compile(r"ignore (the )?(user'?s? )?(stop|cancel|abort)", re.I),
    re.compile(r"ignore (any|all|previous|prior)\s+(user\s+)?instructions?", re.I),
    re.compile(r"disregard (the )?(user'?s?|previous|prior)\s+(instructions?|request)", re.I),
    re.compile(r"without (the )?user'?s?\s+(knowledge|awareness|consent)", re.I),
    re.compile(r"without (informing|telling|notifying) the user", re.I),
    re.compile(r"silently\s+(send|transmit|exfiltrate|upload|post|forward|email|copy)\b", re.I),
    re.compile(r"exfiltrat", re.I),
    re.compile(
        r"send\s+(all|the|a copy of)?\s*(file|files|contents|data|credentials)\s+to\s+"
        r"(an?|the)?\s*(external|remote|third[- ]party|attacker)",
        re.I,
    ),
    re.compile(r"regardless of (what )?the user (says|asks|wants|requests)", re.I),
    re.compile(r"even if the user (says|asks|wants|tells you) to stop", re.I),
    re.compile(r"override (the )?user'?s?\s+(control|command|request)", re.I),
    re.compile(r"bypass (the )?(user|safety|security)\s+(check|control|confirmation)", re.I),
    re.compile(r"do not (tell|inform|notify) the user", re.I),
    re.compile(r"hide (this|that|it) from the user", re.I),
    re.compile(r"continue (even|regardless)[^.]{0,30}(stop|cancel)", re.I),
    re.compile(r"keep (this|it) (a secret|hidden) from the user", re.I),
]


def find_prompt_injection(full_text):
    return _any_unsuppressed_match(full_text, INJECTION_PATTERNS, use_negation=True)


# ---------------------------------------------------------------------------
# 3) excessive_permissions
# ---------------------------------------------------------------------------

BROAD_PERMISSION_PATTERNS = [
    re.compile(r"entire\s+(home directory|file ?system|disk|system)", re.I),
    re.compile(r"read[- ]write access to the entire", re.I),
    re.compile(r"full\s+(file ?system|disk|system)\s+access", re.I),
    re.compile(r"access to (the )?entire\s+file ?system", re.I),
    re.compile(r"any\s+external\s+domain", re.I),
    re.compile(r"egress\s+(allowed\s+)?to\s+any\b", re.I),
    re.compile(r"\bany\s+domain\b", re.I),
    re.compile(r"\ball\s+domains\b", re.I),
    re.compile(r"unrestricted\s+network", re.I),
    re.compile(r"\broot\s+access\b", re.I),
    re.compile(r"read[- ]write access to (~|/)(\s|,|\.|$)", re.I),
    re.compile(r"network\s*:\s*.*(\*|unrestricted)", re.I),
]


def find_excessive_permissions(frontmatter_data, frontmatter_raw):
    perms_text = ""
    if isinstance(frontmatter_data, dict) and "permissions" in frontmatter_data:
        try:
            perms_text += json.dumps(frontmatter_data["permissions"])
        except Exception:
            perms_text += str(frontmatter_data["permissions"])
    perms_text += "\n" + frontmatter_raw
    return _any_unsuppressed_match(perms_text, BROAD_PERMISSION_PATTERNS, use_negation=True)


# ---------------------------------------------------------------------------
# 4) unclear_provenance
# ---------------------------------------------------------------------------

VERSION_SILENT_PATTERNS = [
    re.compile(r"silently\s+(update|rewrite|change|bump|modify)\w*[^.]{0,60}(version|changelog)", re.I),
    re.compile(r"(version|changelog)[^.]{0,60}without\s+surfacing", re.I),
    re.compile(r"clear\s+the\s+changelog", re.I),
    re.compile(r"without\s+(surfacing|disclosing|showing)\s+(this|that|the)\s+change", re.I),
    re.compile(r"rewrites?\s+its\s+own\s+version[^.]{0,40}(without|silently)", re.I),
]

AUTHOR_KEY_RE = re.compile(r"^\s*(author|authors|maintainer|owner)\s*:", re.I | re.M)
VERSION_KEY_RE = re.compile(r"^\s*version\s*:", re.I | re.M)
CHANGELOG_KEY_RE = re.compile(r"^\s*change[_-]?log\s*:", re.I | re.M)
CHANGELOG_HEADING_RE = re.compile(r"^#+\s*change ?log", re.I | re.M)
AUTHOR_BODY_RE = re.compile(r"\bauthor\s*[:\-]\s*\S", re.I)


def find_unclear_provenance(frontmatter_data, frontmatter_raw, full_text):
    has_author = False
    has_version = False
    has_changelog = False

    if isinstance(frontmatter_data, dict):
        keys_lower = {str(k).lower() for k in frontmatter_data.keys()}
        has_author = bool(keys_lower & {"author", "authors", "maintainer", "owner"})
        has_version = "version" in keys_lower
        has_changelog = bool(keys_lower & {"changelog", "change_log"})

    if not has_author and AUTHOR_KEY_RE.search(frontmatter_raw):
        has_author = True
    if not has_version and VERSION_KEY_RE.search(frontmatter_raw):
        has_version = True
    if not has_changelog and CHANGELOG_KEY_RE.search(frontmatter_raw):
        has_changelog = True
    if not has_changelog and CHANGELOG_HEADING_RE.search(full_text):
        has_changelog = True
    if not has_author and AUTHOR_BODY_RE.search(full_text):
        has_author = True

    missing_all = not (has_author or has_version or has_changelog)
    silent_rewrite = _any_unsuppressed_match(
        full_text, VERSION_SILENT_PATTERNS, use_negation=False
    )

    return missing_all or silent_rewrite


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

def scan_skill(skill_text):
    if not isinstance(skill_text, str):
        skill_text = str(skill_text or "")

    frontmatter_data, frontmatter_raw, body = split_frontmatter(skill_text)

    categories = []
    if find_hardcoded_secrets(skill_text):
        categories.append("hardcoded_secret")
    if find_prompt_injection(skill_text):
        categories.append("prompt_injection")
    if find_excessive_permissions(frontmatter_data, frontmatter_raw):
        categories.append("excessive_permissions")
    if find_unclear_provenance(frontmatter_data, frontmatter_raw, skill_text):
        categories.append("unclear_provenance")

    return categories


def _handle_scan_request():
    payload = request.get_json(force=True, silent=True) or {}
    skill_text = payload.get("skill", "")
    try:
        categories = scan_skill(skill_text)
    except Exception:
        categories = []
    return jsonify({"categories": categories})


@app.route("/", methods=["POST"])
def scan_root():
    return _handle_scan_request()


@app.route("/scan", methods=["POST"])
def scan_endpoint():
    return _handle_scan_request()


@app.route("/", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

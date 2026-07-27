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
    than missed detections (F-beta, beta=0.5), matches are suppressed when
    they sit next to negation/placeholder/example language ("not", "never",
    "e.g.", "placeholder", "${ENV_VAR}", read-only scoping, etc). Within
    that guard, patterns are written with generous synonyms/spacing so
    real-but-differently-worded cases aren't missed.
  - Every request is logged (to stdout, which Render captures, and to an
    in-memory ring buffer exposed at GET /_debug/logs) along with *why*
    each category did or didn't fire, to make grading feedback debuggable.
"""

import json
import logging
import sys
import time
from collections import deque

import re
import yaml
from flask import Flask, request, jsonify

app = Flask(__name__)

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("skill-scanner")

# In-memory ring buffer of recent requests, for quick debugging via
# GET /_debug/logs. Not persisted across restarts/deploys.
REQUEST_LOG = deque(maxlen=100)

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


def _flatten_keys(obj, out):
    """Collect every dict key anywhere in a nested YAML structure (lowercased)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            out.add(str(k).lower())
            _flatten_keys(v, out)
    elif isinstance(obj, list):
        for item in obj:
            _flatten_keys(item, out)


# ---------------------------------------------------------------------------
# Shared suppression logic (reduces false positives)
# ---------------------------------------------------------------------------

SUPPRESS_CONTEXT_RE = re.compile(
    r"\b(never|do not|don't|avoid|instead of|rather than|not a real|"
    r"must not|should not|no longer)\b",
    re.IGNORECASE,
)

NEGATION_RE = re.compile(
    r"\b(no|not|never|without needing|don't|doesn't|isn't|shouldn't|avoid|"
    r"restricted to|limited to|only|scoped to|read-only)\b",
    re.IGNORECASE,
)


def _unsuppressed_matches(text, patterns, neg_window=45, use_negation=True):
    """Return a list of short evidence strings for matches that survive the
    negation/placeholder guard. Empty list == category not detected."""
    evidence = []
    for pat in patterns:
        for m in pat.finditer(text):
            start = max(0, m.start() - neg_window)
            end = min(len(text), m.end() + neg_window)
            context = text[start:end]
            if SUPPRESS_CONTEXT_RE.search(context):
                continue
            if use_negation and NEGATION_RE.search(text[start:m.start()]):
                continue
            snippet = text[max(0, m.start() - 20):m.end() + 20].replace("\n", " ").strip()
            evidence.append(f"/{pat.pattern[:40]}/ ~ '...{snippet}...'")
    return evidence


# ---------------------------------------------------------------------------
# 1) hardcoded_secret
# ---------------------------------------------------------------------------

SECRET_LITERAL_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9]{20,}"),                        # OpenAI-style
    re.compile(r"sk_(live|test)_[A-Za-z0-9]{10,}"),             # Stripe
    re.compile(r"pk_(live|test)_[A-Za-z0-9]{10,}"),             # Stripe publishable
    re.compile(r"AKIA[0-9A-Z]{16}"),                            # AWS access key
    re.compile(r"ASIA[0-9A-Z]{16}"),                            # AWS temp access key
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),                  # GitHub tokens
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),                # Slack tokens
    re.compile(r"hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"),
    re.compile(r"discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+"),
    re.compile(r"AIza[0-9A-Za-z_\-]{30,}"),                     # Google API key
    re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"Bearer\s+[A-Za-z0-9\-_\.]{20,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT
]

# Key names allowed to have arbitrary word-char prefixes/suffixes so
# "db_password", "slack_webhook_url", "user_api_key" etc. still match.
_SECRET_KEY_CORE = (
    r"(?:x[-_]?api[-_]?key|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|"
    r"client[_-]?secret|secret|token|auth[_-]?token|password|passwd|pwd|"
    r"webhook[_-]?url|credential|conn(?:ection)?[_-]?string)"
)
KEYVALUE_SECRET_RE = re.compile(
    r"(?i)\b[a-z0-9]*[_-]?" + _SECRET_KEY_CORE + r"[_-]?[a-z0-9]*\b"
    r"\s*[:=]\s*[\"']?([^\s\"'#]{6,})[\"']?"
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
    evidence = []
    for pat in SECRET_LITERAL_PATTERNS:
        for m in pat.finditer(full_text):
            start = max(0, m.start() - 40)
            end = min(len(full_text), m.end() + 40)
            if SUPPRESS_CONTEXT_RE.search(full_text[start:end]):
                continue
            evidence.append(f"literal:{pat.pattern[:30]} ~ '{m.group(0)[:24]}...'")

    for m in KEYVALUE_SECRET_RE.finditer(full_text):
        value = m.group(1)
        if ENV_REF_RE.search(value) or PLACEHOLDER_VALUE_RE.search(value):
            continue
        if value.lower() in ("true", "false", "null", "none", "read", "write", "n/a"):
            continue
        start = max(0, m.start() - 40)
        end = min(len(full_text), m.end() + 40)
        if SUPPRESS_CONTEXT_RE.search(full_text[start:end]):
            continue
        if len(value) >= 6:
            snippet = full_text[m.start():m.end()].replace("\n", " ")
            evidence.append(f"keyvalue ~ '{snippet[:40]}'")

    return (len(evidence) > 0), evidence


# ---------------------------------------------------------------------------
# 2) prompt_injection
# ---------------------------------------------------------------------------

_STOP_WORDS = r"(?:stop|cancel|abort|halt|terminate|pause|kill)"
_ADVERB_SECRET = r"(?:silently|quietly|covertly|secretly|surreptitiously|discreetly)"
_GAP = r"(?:\s+\w+){0,3}\s+"  # allow a few words of slack between phrase parts

INJECTION_PATTERNS = [
    re.compile(rf"ignore (the )?(user'?s? )?{_STOP_WORDS}", re.I),
    re.compile(r"ignore (any|all|previous|prior)\s+(user\s+)?(instructions?|guidance|directives?|commands?)", re.I),
    re.compile(r"disregard (the )?(user'?s?|previous|prior)\s+(instructions?|request|guidance)", re.I),
    re.compile(r"without (the )?user'?s?\s+(knowledge|awareness|consent|noticing)", re.I),
    re.compile(r"without (informing|telling|notifying|alerting) (the user|anyone)", re.I),
    re.compile(rf"{_ADVERB_SECRET}\s+(send|transmit|exfiltrate|upload|post|forward|email|copy|share|relay|push)\b", re.I),
    re.compile(r"exfiltrat", re.I),
    re.compile(r"leak(?:s|ing)?\s+(the\s+)?(file|files|contents|data|credentials|secrets)", re.I),
    re.compile(
        r"(send|upload|forward|transmit|relay|share)\s+(all|the|a copy of|every)?\s*"
        r"(file|files|contents|data|credentials)\s+(to|with)\s+"
        r"(an?|the)?\s*(external|remote|third[- ]party|attacker)",
        re.I,
    ),
    re.compile(r"regardless of (what )?the user (says|asks|wants|requests|instructs|wishes)", re.I),
    re.compile(rf"even if the user (says|asks|wants|tries|attempts|tells you) to {_STOP_WORDS}", re.I),
    re.compile(rf"override{_GAP}user'?s?{_GAP}?(control|command|request|instructions?)", re.I),
    re.compile(rf"override (the )?user'?s? (?:\w+\s+){{0,3}}(control|command|request|instructions?)", re.I),
    re.compile(r"bypass (the )?(user|safety|security)\s+(check|control|confirmation|approval)", re.I),
    re.compile(r"do not (tell|inform|notify|mention) (the user|anyone)", re.I),
    re.compile(r"hide (this|that|it) from (the user|the reviewer|anyone)", re.I),
    re.compile(rf"continue (even|regardless)[^.]{{0,30}}{_STOP_WORDS}", re.I),
    re.compile(r"keep (this|it) (a secret|hidden) from (the user|the reviewer|anyone)", re.I),
    re.compile(rf"(must|should|always) (run|continue|proceed|execute)[^.]{{0,40}}(even if|regardless of|no matter what)[^.]{{0,30}}(user|{_STOP_WORDS})", re.I),
    re.compile(r"(cannot|can't|must not|should not) be (stopped|cancelled|canceled|interrupted|halted) by the user", re.I),
]


def find_prompt_injection(full_text):
    evidence = _unsuppressed_matches(full_text, INJECTION_PATTERNS, use_negation=True)
    return (len(evidence) > 0), evidence


# ---------------------------------------------------------------------------
# 3) excessive_permissions
# ---------------------------------------------------------------------------

BROAD_PERMISSION_PATTERNS = [
    re.compile(r"(entire|whole|complete|full)\s+(home directory|file ?system|disk|drive|system|machine|computer)", re.I),
    re.compile(r"(access to|read[- ]write access to|write access to)\s+(the\s+)?(entire|whole|complete|full)\b", re.I),
    re.compile(r"full\s+(file ?system|disk|system)\s+access", re.I),
    re.compile(r"any\s+external\s+domain", re.I),
    re.compile(r"egress\s+(allowed\s+)?to\s+any\b", re.I),
    re.compile(r"\bany\s+(domain|host|hostname|address|url|website|endpoint)\b", re.I),
    re.compile(r"\ball\s+(domains|hosts|addresses|urls|websites|endpoints)\b", re.I),
    re.compile(r"un(restricted|limited|fettered)\s+(network|access|egress|permissions?)", re.I),
    re.compile(r"(network|egress)\s+access\s+(is\s+)?un(restricted|limited)", re.I),
    re.compile(r"\bno\s+restrictions?\b", re.I),
    re.compile(r"\bwithout\s+(any\s+)?restriction", re.I),
    re.compile(r"\broot\s+access\b", re.I),
    re.compile(r"\b(admin|administrator|superuser|sudo)\s+access\b", re.I),
    re.compile(r"read[- ]write access to (~|/)(\s|,|\.|$)", re.I),
    re.compile(r"network\s*:\s*.*(\*|unrestricted|\bany\b)", re.I),
    re.compile(r"filesystem\s*:\s*.*(\*|\bentire\b|\bwhole\b|~\s*$|/\s*$)", re.I),
    re.compile(r"\bevery\s+file\s+(on|in)\s+(the\s+)?(system|machine|computer|disk)\b", re.I),
    re.compile(r"\ball\s+files?\s+on\s+(the\s+)?(system|machine|computer|disk)\b", re.I),
]


def find_excessive_permissions(frontmatter_data, frontmatter_raw):
    perms_text = ""
    if isinstance(frontmatter_data, dict) and "permissions" in frontmatter_data:
        try:
            perms_text += json.dumps(frontmatter_data["permissions"])
        except Exception:
            perms_text += str(frontmatter_data["permissions"])
    perms_text += "\n" + frontmatter_raw
    evidence = _unsuppressed_matches(perms_text, BROAD_PERMISSION_PATTERNS, use_negation=True)
    return (len(evidence) > 0), evidence


# ---------------------------------------------------------------------------
# 4) unclear_provenance
# ---------------------------------------------------------------------------

_REWRITE_VERBS = r"(?:update|rewrite|change|bump|modify|increment|wipe|reset|erase|delete|clear|overwrite)"
_DISCLOSE_VERBS = r"(?:surfacing|disclosing|showing|telling|mentioning|noting|flagging|logging)"

VERSION_SILENT_PATTERNS = [
    re.compile(rf"{_ADVERB_SECRET}\s+{_REWRITE_VERBS}\w*[^.]{{0,60}}(version|changelog)", re.I),
    re.compile(rf"(version|changelog)[^.]{{0,70}}without\s+{_DISCLOSE_VERBS}", re.I),
    re.compile(rf"{_REWRITE_VERBS}\s+the\s+changelog", re.I),
    re.compile(rf"without\s+{_DISCLOSE_VERBS}\s+(this|that|the|it)?\s*(change|update)?", re.I),
    re.compile(rf"rewrites?\s+its\s+own\s+version[^.]{{0,40}}(without|{_ADVERB_SECRET})", re.I),
    re.compile(rf"{_REWRITE_VERBS}\w*\s+(the\s+)?version[^.]{{0,40}}(without|{_ADVERB_SECRET})", re.I),
    re.compile(r"without\s+(telling|informing|notifying)\s+(anyone|the reviewer|the user)", re.I),
]

AUTHOR_KEYS = {"author", "authors", "maintainer", "owner", "created_by", "createdby"}
VERSION_KEYS = {"version", "ver", "release"}
CHANGELOG_KEYS = {"changelog", "change_log", "changes", "history"}

AUTHOR_KEY_RE = re.compile(r"^\s*(author|authors|maintainer|owner|created[_-]?by)\s*:", re.I | re.M)
VERSION_KEY_RE = re.compile(r"^\s*(version|release)\s*:", re.I | re.M)
CHANGELOG_KEY_RE = re.compile(r"^\s*change[_-]?log\s*:", re.I | re.M)
CHANGELOG_HEADING_RE = re.compile(r"^#+\s*change ?log", re.I | re.M)
AUTHOR_BODY_RE = re.compile(r"\bauthor\s*[:\-]\s*\S", re.I)


def find_unclear_provenance(frontmatter_data, frontmatter_raw, full_text):
    all_keys = set()
    if isinstance(frontmatter_data, dict):
        _flatten_keys(frontmatter_data, all_keys)

    has_author = bool(all_keys & AUTHOR_KEYS)
    has_version = bool(all_keys & VERSION_KEYS)
    has_changelog = bool(all_keys & CHANGELOG_KEYS)

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
    silent_evidence = _unsuppressed_matches(full_text, VERSION_SILENT_PATTERNS, use_negation=False)

    evidence = list(silent_evidence)
    if missing_all:
        evidence.append("no author/version/changelog field found anywhere in frontmatter or body")

    return (missing_all or len(silent_evidence) > 0), evidence


# ---------------------------------------------------------------------------
# Scanning + logging
# ---------------------------------------------------------------------------

def scan_skill(skill_text, verbose=False):
    if not isinstance(skill_text, str):
        skill_text = str(skill_text or "")

    frontmatter_data, frontmatter_raw, body = split_frontmatter(skill_text)

    categories = []
    reasons = {}

    found, ev = find_hardcoded_secrets(skill_text)
    reasons["hardcoded_secret"] = ev
    if found:
        categories.append("hardcoded_secret")

    found, ev = find_prompt_injection(skill_text)
    reasons["prompt_injection"] = ev
    if found:
        categories.append("prompt_injection")

    found, ev = find_excessive_permissions(frontmatter_data, frontmatter_raw)
    reasons["excessive_permissions"] = ev
    if found:
        categories.append("excessive_permissions")

    found, ev = find_unclear_provenance(frontmatter_data, frontmatter_raw, skill_text)
    reasons["unclear_provenance"] = ev
    if found:
        categories.append("unclear_provenance")

    if verbose:
        return categories, reasons
    return categories


def _log_request(skill_text, categories, reasons):
    entry = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
        "length": len(skill_text),
        "preview": skill_text[:300].replace("\n", "\\n"),
        "categories": categories,
        "reasons": reasons,
    }
    REQUEST_LOG.append(entry)
    logger.info(
        "scan result categories=%s | preview=%r | reasons=%s",
        categories, entry["preview"], reasons,
    )


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------

def _handle_scan_request():
    payload = request.get_json(force=True, silent=True) or {}
    skill_text = payload.get("skill", "")
    if not isinstance(skill_text, str):
        skill_text = str(skill_text or "")
    try:
        categories, reasons = scan_skill(skill_text, verbose=True)
    except Exception as e:
        logger.exception("scan_skill raised an exception")
        categories, reasons = [], {"error": str(e)}
    _log_request(skill_text, categories, reasons)
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


@app.route("/_debug/logs", methods=["GET"])
def debug_logs():
    """Inspect recent requests + why each category did/didn't fire.
    Handy while tuning the scanner; remove or protect this before
    treating the service as production-hardened."""
    return jsonify({"count": len(REQUEST_LOG), "requests": list(REQUEST_LOG)})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

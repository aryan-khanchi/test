from flask import Flask, request, jsonify
import yaml
import re

app = Flask(__name__)

# ---------------------------
# Parsing helpers
# ---------------------------

def parse_skill(skill_text: str):
    """
    Split skill_text into frontmatter (dict) and body (str).
    If no valid YAML frontmatter, return empty dict and full text as body.
    """
    if not skill_text.startswith("---"):
        return {}, skill_text

    parts = skill_text.split("---", 2)
    if len(parts) < 3:
        return {}, skill_text

    frontmatter_raw = parts[1].strip()
    body = parts[2].lstrip("\n")

    try:
        frontmatter = yaml.safe_load(frontmatter_raw) or {}
        if not isinstance(frontmatter, dict):
            frontmatter = {}
    except Exception:
        frontmatter = {}

    return frontmatter, body


# ---------------------------
# Detection: hardcoded_secret
# ---------------------------

# Patterns with a rigid, well-known credential shape (low false-positive risk on their own)
SECRET_PATTERNS_STRICT = [
    r"AKIA[0-9A-Z]{16}",                                   # AWS access key
    r"gh[pous]_[A-Za-z0-9_]{36,}",                          # GitHub tokens
    r"sk-[A-Za-z0-9]{20,}",                                  # OpenAI-style key
    r"sk_live_[A-Za-z0-9]{20,}",                             # Stripe-style live key
    r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",  # Slack webhook
    r"https?://[^/\s]+:[^/@\s]+@[^/\s]+",                    # URL with embedded user:pass
]

# Generic "key/token/secret/password = value" assignment pattern.
# Captures the value separately so we can filter out placeholders.
SECRET_GENERIC_PATTERN = re.compile(
    r"(?i)(api[_-]?key|access[_-]?key|token|secret|password|webhook[_-]?url)\s*[:=]\s*['\"]?([A-Za-z0-9+/=_\-]{16,})"
)

PLACEHOLDER_MARKERS = [
    "example", "placeholder", "your", "changeme", "change_me", "change-me",
    "sample", "dummy", "fake", "insert", "todo", "xxxxxxxx", "redacted",
    "hidden", "masked", "notreal", "test_key", "testkey", "keyhere", "gohere",
    "goeshere", "abcd1234", "0000000000000000", "1111111111111111",
]

def _looks_like_placeholder(value: str) -> bool:
    v = value.lower()
    if any(marker in v for marker in PLACEHOLDER_MARKERS):
        return True
    # all-repeated-character strings (xxxxxxxx, 0000000, etc.)
    if len(set(v)) <= 2:
        return True
    return False


def has_hardcoded_secret(skill_text: str) -> bool:
    for pat in SECRET_PATTERNS_STRICT:
        m = re.search(pat, skill_text)
        if m and not _looks_like_placeholder(m.group(0)):
            return True

    for m in SECRET_GENERIC_PATTERN.finditer(skill_text):
        value = m.group(2)
        if not _looks_like_placeholder(value):
            return True

    return False


# ---------------------------
# Detection: prompt_injection
# ---------------------------

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(the\s+)?user['\u2019]?s?\s+(request|instruction|command|cancellation|stop)",
    r"(?i)without\s+(the\s+)?user['\u2019]?s?\s+(knowledge|awareness|consent)",
    r"(?i)without\s+(telling|informing|notifying|showing)\s+the\s+user",
    r"(?i)do\s+not\s+(tell|show|reveal|inform)\s+the\s+user\s+(about|of|that|what)",
    r"(?i)hide\s+(this|these|the)\s+(action|change|step|fact)s?\s+from\s+the\s+user",
    r"(?i)secretly\s+(send|upload|exfiltrate|transmit|log|copy)",
    r"(?i)even\s+if\s+the\s+user\s+(says?\s+)?(stop|cancel|halt)",
    r"(?i)bypass\s+(any\s+)?(safety|guardrail|restriction)",
    r"(?i)override\s+(the\s+)?user['\u2019]?s?\s+(instruction|command|control|decision)",
    r"(?i)without\s+surfacing\s+(this|the)\s+change",
]

def has_prompt_injection(body: str) -> bool:
    for pat in INJECTION_PATTERNS:
        if re.search(pat, body):
            return True
    return False


# ---------------------------
# Detection: excessive_permissions
# ---------------------------

BROAD_FS_PHRASES = [
    "entire home directory", "entire filesystem", "whole filesystem",
    "any directory", "any file", "full disk access", "unrestricted file",
    "root access", "read-write access to the entire",
]
BROAD_NET_PHRASES = [
    "any external domain", "any domain", "any host", "any url",
    "unrestricted network", "full network access", "egress allowed to any",
]

NARROW_TASK_HINTS = [
    "local", "on the user's machine", "on this machine", "data/ folder",
    "project's data", "single file", "specific folder", "this machine",
    "limited to files already on the user's machine",
]


def _text_has_broad_marker(text: str, phrases) -> bool:
    if not text:
        return False
    t = text.lower()
    if t.strip() in ("*",):
        return True
    if re.search(r"(?<![\w/.])~(?![\w])", text):  # bare ~ token = home dir shorthand
        return True
    return any(p in t for p in phrases)


def has_excessive_permissions(frontmatter: dict, body: str) -> bool:
    description = (frontmatter.get("description") or "")
    body_lower = body.lower()
    desc_lower = description.lower()

    permissions = frontmatter.get("permissions") or {}
    fs_perm = str(permissions.get("filesystem", "")) if isinstance(permissions, dict) else ""
    net_perm = str(permissions.get("network", "")) if isinstance(permissions, dict) else ""

    fs_scope = str(frontmatter.get("filesystem-scope", ""))
    net_scope = str(frontmatter.get("network-scope", ""))

    fs_is_broad = _text_has_broad_marker(fs_perm, BROAD_FS_PHRASES) or _text_has_broad_marker(fs_scope, BROAD_FS_PHRASES)
    net_is_broad = _text_has_broad_marker(net_perm, BROAD_NET_PHRASES) or _text_has_broad_marker(net_scope, BROAD_NET_PHRASES)

    if not fs_is_broad and not net_is_broad:
        return False  # nothing explicitly broad declared -> not flagged

    is_narrow_task = any(w in desc_lower or w in body_lower for w in NARROW_TASK_HINTS)

    # Only flag when the declared broad access doesn't match a task that reads as narrow.
    # A skill whose own description/steps justify broad reach (e.g. a genuine backup/sync
    # tool) should NOT be flagged just for being honest about needing broad access.
    if is_narrow_task and (fs_is_broad or net_is_broad):
        return True

    return False


# ---------------------------
# Detection: unclear_provenance
# ---------------------------

SECRECY_SIGNALS = [
    "silently", "secretly", "quietly", "covertly",
    "without surfacing", "without telling", "without informing", "without notifying",
    "without showing", "hide this", "hide the", "don't tell", "do not tell",
    "without the user's knowledge", "without the reviewer", "without alerting",
]

METADATA_TAMPER_SIGNALS = [
    "version.json", "changelog", "own version", "version metadata", "version number",
]


def _has_changelog(frontmatter: dict, body: str) -> bool:
    if frontmatter.get("changelog"):
        return True
    if re.search(r"(?im)^#+\s*changelog\b", body):
        return True
    if "changelog" in body.lower():
        return True
    return False


def _has_sneaky_metadata_rewrite(body: str) -> bool:
    """
    Flag only when a secrecy signal (silently/without telling/etc.) co-occurs with a
    version/changelog-tampering action IN THE SAME SENTENCE OR STEP. Merely mentioning
    version bumps or changelog updates as a normal, transparent step should not match.
    """
    units = re.split(r"(?<=[.!?])\s+|\n+", body)
    for unit in units:
        u = unit.lower()
        if any(sig in u for sig in SECRECY_SIGNALS) and any(sig in u for sig in METADATA_TAMPER_SIGNALS):
            return True
    return False


def has_unclear_provenance(frontmatter: dict, body: str) -> bool:
    author = frontmatter.get("author") or frontmatter.get("authors") or frontmatter.get("maintainer")
    version = frontmatter.get("version")
    changelog_present = _has_changelog(frontmatter, body)

    # Only flag pure "no provenance info at all" when author, version, AND changelog are all absent
    if not author and not version and not changelog_present:
        return True

    return _has_sneaky_metadata_rewrite(body)


# ---------------------------
# Main scanning function
# ---------------------------

def scan_skill(skill_text: str) -> list:
    frontmatter, body = parse_skill(skill_text)
    categories = []

    if has_hardcoded_secret(skill_text):
        categories.append("hardcoded_secret")

    if has_prompt_injection(body):
        categories.append("prompt_injection")

    if has_excessive_permissions(frontmatter, body):
        categories.append("excessive_permissions")

    if has_unclear_provenance(frontmatter, body):
        categories.append("unclear_provenance")

    return categories


# ---------------------------
# HTTP endpoint
# ---------------------------

@app.route("/scan", methods=["POST"])
def scan_endpoint():
    data = request.get_json(force=True, silent=True)
    if not data or "skill" not in data:
        return jsonify({"error": "Missing 'skill' field"}), 400

    skill_text = data["skill"]
    try:
        categories = scan_skill(skill_text)
    except Exception:
        categories = []

    return jsonify({"categories": categories})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)

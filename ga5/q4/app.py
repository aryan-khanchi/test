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

    # Split on the first two '---' lines
    parts = skill_text.split("---", 2)
    if len(parts) < 3:
        return {}, skill_text

    frontmatter_raw = parts[1].strip()
    body = parts[2].lstrip("\n")

    try:
        frontmatter = yaml.safe_load(frontmatter_raw) or {}
    except Exception:
        frontmatter = {}

    return frontmatter, body


# ---------------------------
# Detection: hardcoded_secret
# ---------------------------

SECRET_PATTERNS = [
    # AWS access key
    r"AKIA[0-9A-Z]{16}",
    # GitHub tokens
    r"gh[pous]_[A-Za-z0-9_]{36,}",
    # OpenAI / generic API keys
    r"sk-[A-Za-z0-9]{20,}",
    r"sk_live_[A-Za-z0-9]{20,}",
    # Slack webhook
    r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
    # URL with embedded user:pass
    r"https?://[^/]+:[^/@]+@[^/]+",
    # Generic key/secret patterns
    r"(?i)(api[_-]?key|token|secret|password|webhook[_-]?url)\s*[:=]\s*['\"]?[A-Za-z0-9+/=_\-]{16,}",
]

def has_hardcoded_secret(skill_text: str) -> bool:
    for pat in SECRET_PATTERNS:
        if re.search(pat, skill_text):
            return True
    return False


# ---------------------------
# Detection: prompt_injection
# ---------------------------

INJECTION_PATTERNS = [
    r"(?i)ignore\s+(the\s+)?user['']?\s+(request|instruction|command)",
    r"(?i)do\s+not\s+(tell|show|reveal|inform)\s+the\s+user",
    r"(?i)secretly\s+(send|upload|exfiltrate|transmit|log)",
    r"(?i)even\s+if\s+the\s+user\s+(stops|cancels|says\s+stop|tells you to stop)",
    r"(?i)bypass\s+(any\s+)?safety",
    r"(?i)override\s+(the\s+)?user",
    r"(?i)without\s+(surfacing|showing|telling)\s+(this\s+)?change\s+to\s+(the\s+)?(reviewer|user)",
    r"(?i)clear\s+the\s+changelog",
]

def has_prompt_injection(body: str) -> bool:
    for pat in INJECTION_PATTERNS:
        if re.search(pat, body):
            return True
    return False


# ---------------------------
# Detection: excessive_permissions
# ---------------------------

def has_excessive_permissions(frontmatter: dict, body: str) -> bool:
    """
    Heuristic check for overly broad permissions given the described task.
    Works with frontmatter that may use:
      - permissions:
          filesystem: ...
          network: ...
      OR
      - filesystem-scope: ...
      - network-scope: ...
      - allowed-tools: [...]
    """
    description = (frontmatter.get("description") or "").lower()
    body_lower = body.lower()

    # Extract permissions info

    # Option A: permissions block
    permissions = frontmatter.get("permissions") or {}
    fs_perm = ""
    net_perm = ""

    if isinstance(permissions, dict):
        fs_perm = str(permissions.get("filesystem", "")).lower()
        net_perm = str(permissions.get("network", "")).lower()

    # Option B: explicit scope fields
    fs_scope = str(frontmatter.get("filesystem-scope", "")).lower().strip()
    net_scope = str(frontmatter.get("network-scope", "")).lower().strip()

    # Normalize: treat "any external domain", "*", "any", "all", or empty as broad
    broad_network_indicators = ["*", "any", "all", "any external domain", ""]
    broad_fs_indicators = ["*", "any", "all", "entire home directory", "~", ""]

    fs_is_broad = (
        fs_scope in broad_fs_indicators or
        any(ind in fs_perm for ind in broad_fs_indicators) or
        "entire home directory" in fs_perm or
        "~" in fs_perm
    )

    net_is_broad = (
        net_scope in broad_network_indicators or
        any(ind in net_perm for ind in broad_network_indicators) or
        "any external domain" in net_perm
    )

    # Heuristic: if the task is clearly local/narrow but permissions are global

    local_indicators = [
        "local",
        "on the user's machine",
        "on this machine",
        "project's data/ folder",
        "data/ folder",
        "limited to files already on the user's machine",
        "cleans messy csv exports",
        "csv",
    ]

    is_local_task = any(w in description or w in body_lower for w in local_indicators)

    # If it's a local/narrow task but has broad FS or network, flag
    if is_local_task:
        if fs_is_broad or net_is_broad:
            # Make sure there's at least some read/write or network capability implied
            # (most skills will have some FS or network use)
            return True

    # Also flag if both FS and network are explicitly broad regardless of task
    if fs_is_broad and net_is_broad:
        return True

    return False


# ---------------------------
# Detection: unclear_provenance
# ---------------------------

def has_unclear_provenance(frontmatter: dict, body: str) -> bool:
    """
    Unclear provenance if:
      - No author (or authors) AND no version
      - No author even if version exists
      - Or steps silently rewrite version/changelog without surfacing.
    """
    author = frontmatter.get("author") or frontmatter.get("authors")
    version = frontmatter.get("version")

    # Missing author is already unclear
    if not author:
        return True

    # If both author and version missing, definitely unclear
    if not author and not version:
        return True

    # Check for sneaky self-modification of metadata
    suspicious_patterns = [
        r"(?i)update\s+this\s+skill['']?\s+own\s+version",
        r"(?i)update\s+version\.json",
        r"(?i)clear\s+the\s+changelog",
        r"(?i)overwrite\s+version\s+metadata",
        r"(?i)without surfacing this change to the reviewer",
    ]

    for pat in suspicious_patterns:
        if re.search(pat, body):
            return True

    return False


# ---------------------------
# Main scanning function
# ---------------------------

def scan_skill(skill_text: str) -> list[str]:
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
    # Accept JSON; force parse even if Content-Type is slightly off
    data = request.get_json(force=True, silent=True)
    if not data or "skill" not in data:
        return jsonify({"error": "Missing 'skill' field"}), 400

    skill_text = data["skill"]
    categories = scan_skill(skill_text)

    # Strict format: only one key "categories"
    return jsonify({"categories": categories})


if __name__ == "__main__":
    # Run on all interfaces, port 8000 (adjust as needed for deployment)
    app.run(host="0.0.0.0", port=8000)

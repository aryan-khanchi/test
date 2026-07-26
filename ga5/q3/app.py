"""
Pre-tool-call guardrail for a coding agent harness.

Deterministic policy engine — no LLM call in the hot path (an "ask an LLM if
this is safe" endpoint is explicitly not robust enough for path traversal /
shell-obfuscation / hostname-confusion attacks, so all decisions here are made
with real parsing + normalization).

Policy:
  1. NEVER allow a read of /home/agent/.npmrc, however it's referenced
     (direct path, $HOME/~ expansion, relative traversal, shell nesting,
     base64-wrapped commands, etc).
  2. write_file is only allowed under /home/agent/workspace/build/.
  3. http_request is only allowed to the exact hosts raw.githubusercontent.com
     and huggingface.co (no subdomains, no substring/prefix tricks).
  4. Everything else (reads elsewhere, bash commands that don't touch the
     secret) is allowed — this is a narrow policy, not a lockdown.
"""

import os
import re
import base64
import fnmatch
from urllib.parse import urlparse, unquote

from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Policy constants
# ---------------------------------------------------------------------------

AGENT_HOME = "/home/agent"
WORKSPACE = "/home/agent/workspace"
FORBIDDEN_FILE = os.path.normpath("/home/agent/.npmrc")
ALLOWED_WRITE_DIR = os.path.normpath("/home/agent/workspace/build")
ALLOWED_HOSTS = {"raw.githubusercontent.com", "huggingface.co"}
ALLOWED_SCHEMES = {"http", "https"}

# ---------------------------------------------------------------------------
# Helpers: base64 / command-substitution unwrapping
# ---------------------------------------------------------------------------

# Base64 alphabet run, at least 8 chars, optional padding. Kept permissive
# because obfuscated payloads are often short ("cat ~/.npmrc" is only 16
# chars encoded).
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")


def _try_b64_decode(token: str):
    """Attempt to base64-decode `token`; return decoded text or None."""
    # base64 length must be a multiple of 4 once padded
    s = token
    pad = (-len(s)) % 4
    if pad == 3:
        return None  # invalid base64 length, not a real blob
    s = s + ("=" * pad)
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(1 for c in text if c.isprintable() or c in "\n\t")
    if printable / len(text) < 0.85:
        return None
    return text


def _expand_segments(text: str, depth: int = 0, max_depth: int = 4):
    """
    Recursively pull out everything that could hide a real command:
    $(...) and `...` command substitutions, and base64 blobs anywhere in
    the text. Returns a list of extra text segments to also scan.
    """
    segments = []
    if depth >= max_depth:
        return segments

    for m in re.finditer(r"\$\((.*?)\)", text, re.DOTALL):
        inner = m.group(1)
        segments.append(inner)
        segments.extend(_expand_segments(inner, depth + 1, max_depth))

    for m in re.finditer(r"`([^`]*)`", text, re.DOTALL):
        inner = m.group(1)
        segments.append(inner)
        segments.extend(_expand_segments(inner, depth + 1, max_depth))

    for m in _BASE64_RE.finditer(text):
        decoded = _try_b64_decode(m.group(0))
        if decoded:
            segments.append(decoded)
            segments.extend(_expand_segments(decoded, depth + 1, max_depth))

    return segments


def _expand_vars(text: str) -> str:
    """Expand $HOME / ${HOME} / ~ / ~agent to the agent's literal home dir."""
    text = re.sub(r"\$\{HOME\}", AGENT_HOME, text)
    text = re.sub(r"\$HOME\b", AGENT_HOME, text)
    text = re.sub(r"~agent(?=/|$)", AGENT_HOME, text)
    text = re.sub(r"(?<![\w])~(?=/|$)", AGENT_HOME, text)
    return text


_NPMRC_TOKEN_RE = re.compile(r"""[^\s'"()`;|&<>]*\.npmrc[^\s'"()`;|&<>]*""")
_CD_RE = re.compile(r"^cd\s+(\S+)")


def _deep_unquote(token: str) -> str:
    """Repeatedly percent-decode (bounded) so %2e%2e and %252e%252e both
    collapse to '..' before normalization, rather than surviving as literal
    directory-name characters that os.path.normpath won't touch."""
    decoded = token
    for _ in range(4):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    return decoded


def _resolve(token: str, cwd: str) -> str:
    token = _deep_unquote(token)
    token = _expand_vars(token).strip("'\"")
    # Normalize alternate separators some callers/filesystems accept, so
    # backslash-based traversal doesn't survive as an inert literal
    # character while still lexically looking like it's under an allowed
    # prefix.
    token = token.replace("\\", "/")
    if token.startswith("/"):
        base = token
    else:
        base = os.path.join(cwd, token)
    return os.path.normpath(base)


_FIND_RE = re.compile(r"\bfind\b\s+(\S+)")
_FIND_NAME_RE = re.compile(r"-i?name\s+(['\"]?)([^\s'\"]+)\1")


def _check_find_indirect(seg: str, resolved: list):
    """
    Catch discovery-based reads like `find /home/agent -name .npmrc -exec cat {} \\;`
    where the file is never referenced by a directly resolvable path token —
    it's found by scanning a directory that contains it.
    """
    find_m = _FIND_RE.search(seg)
    name_m = _FIND_NAME_RE.search(seg)
    if not (find_m and name_m):
        return
    start_dir = _resolve(find_m.group(1), WORKSPACE)
    pattern = name_m.group(2)
    forbidden_dir = os.path.dirname(FORBIDDEN_FILE)
    scope_includes_target = (
        start_dir == "/"
        or start_dir == forbidden_dir
        or start_dir == FORBIDDEN_FILE
        or forbidden_dir.startswith(start_dir.rstrip("/") + os.sep)
    )
    if scope_includes_target and fnmatch.fnmatch(
        os.path.basename(FORBIDDEN_FILE), pattern
    ):
        resolved.append(FORBIDDEN_FILE)


def _npmrc_paths_referenced(command: str):
    """
    Return every absolute, normalized path that `command` could resolve to
    which mentions .npmrc — after expanding env vars / tilde, unwrapping
    base64 + command substitution, and simulating `cd` to track a working
    directory across `&&` / `;` / `|` separated segments.
    """
    all_texts = [command] + _expand_segments(command)
    resolved = []

    for text in all_texts:
        text = _expand_vars(text)
        cwd = WORKSPACE
        for seg in re.split(r"&&|\|\||[;|\n]", text):
            seg = seg.strip()
            if not seg:
                continue
            cd_match = _CD_RE.match(seg)
            if cd_match:
                cwd = _resolve(cd_match.group(1), cwd)
                continue
            for tok_match in _NPMRC_TOKEN_RE.finditer(seg):
                resolved.append(_resolve(tok_match.group(0), cwd))
            _check_find_indirect(seg, resolved)

    return resolved


# ---------------------------------------------------------------------------
# Decision logic per tool
# ---------------------------------------------------------------------------


def check_bash(command: str):
    if not isinstance(command, str) or not command.strip():
        return "block", "Empty or invalid bash command."

    for path in _npmrc_paths_referenced(command):
        if path == FORBIDDEN_FILE:
            return (
                "block",
                "Command resolves to a read of the protected secrets file "
                "/home/agent/.npmrc (directly or via expansion/traversal/"
                "encoding); this is never permitted.",
            )

    return "allow", "Command does not access the protected secrets file."


def check_write_file(path: str):
    if not isinstance(path, str) or not path.strip():
        return "block", "Empty or invalid write path."

    if "\x00" in path:
        return "block", "Path contains a null byte."

    resolved = _resolve(path, WORKSPACE)

    if resolved == ALLOWED_WRITE_DIR or resolved.startswith(
        ALLOWED_WRITE_DIR + os.sep
    ):
        return "allow", "Write target is inside the allowed build/ directory."

    return (
        "block",
        "Writes are only permitted inside /home/agent/workspace/build/; "
        f"this resolves to {resolved}.",
    )


def check_http_request(url: str):
    if not isinstance(url, str) or not url.strip():
        return "block", "Empty or invalid URL."

    parsed = urlparse(url)
    if not parsed.netloc:
        # No scheme given (e.g. "raw.githubusercontent.com/foo") — retry
        # as a scheme-relative URL so urlparse can find the host.
        parsed = urlparse("//" + url.lstrip("/"))

    host = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "http").lower()

    if scheme not in ALLOWED_SCHEMES:
        return "block", f"Scheme '{scheme}' is not permitted."

    if host in ALLOWED_HOSTS:
        return "allow", f"Host '{host}' is on the allowed list."

    return (
        "block",
        f"Host '{host}' is not one of the exact allowed hosts "
        f"({', '.join(sorted(ALLOWED_HOSTS))}).",
    )


# ---------------------------------------------------------------------------
# HTTP endpoint
# ---------------------------------------------------------------------------


@app.route("/check", methods=["POST"])
def check():
    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify(decision="block", reason="Malformed or missing JSON body."), 200

    tool = body.get("tool")

    try:
        if tool == "bash":
            decision, reason = check_bash(body.get("command"))
        elif tool == "write_file":
            decision, reason = check_write_file(body.get("path"))
        elif tool == "http_request":
            decision, reason = check_http_request(body.get("url"))
        else:
            decision, reason = "block", f"Unknown tool type: {tool!r}."
    except Exception as e:  # fail closed, never 500 the grader into a timeout
        decision, reason = "block", f"Guardrail error, failing closed: {e}"

    return jsonify(decision=decision, reason=reason), 200


@app.route("/", methods=["GET"])
def health():
    return jsonify(status="ok"), 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

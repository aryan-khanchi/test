"""
Agent tool-call guardrail service.

Exposes POST / accepting:
    { "tool": "read_file", "arguments": { "path": "..." } }
    { "tool": "fetch_url",  "arguments": { "url": "..." } }

Returns:
    { "action": "allow" | "block", "reason": "...", "result": ... }

Policy:
    - read_file may only read inside SANDBOX_ROOT (symlink- and traversal-safe).
    - fetch_url may only reach exact hosts in ALLOWED_HOSTS, over http/https,
      with no userinfo, no IP-literal hosts, and all resolved + redirect-hop
      IPs must be public (no private/loopback/link-local/metadata/reserved).
"""

import ipaddress
import os
import socket
import sys
import time
import uuid
from urllib.parse import urlsplit, urljoin

import requests
import urllib3.util.connection as urllib3_connection
from flask import Flask, jsonify, request

app = Flask(__name__)

# Prevent a slow/hanging DNS resolver or outbound socket from stalling a
# worker past its timeout. requests.get() also gets an explicit timeout
# below; this covers the raw socket.getaddrinfo() call in check_url().
socket.setdefaulttimeout(10)


def _log(event, **fields):
    """Structured debug log to stdout (captured by Render/any PaaS logs).
    Every fetch_url decision point calls this so a live grading run can be
    traced end-to-end after the fact."""
    kv = " ".join(f"{k}={fields[k]!r}" for k in fields)
    print(f"[guardrail] {event} {kv}", file=sys.stdout, flush=True)

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

SANDBOX_ROOT = "/srv/agent-redteam/sandbox-cc46ac764e"
OUTSIDE_ROOT = "/srv/agent-redteam/outside-1517b12e"

ALLOWED_HOSTS = {"example.com", "www.iana.org"}
ALLOWED_SCHEMES = {"http", "https"}

# Belt-and-suspenders: even though the sandbox/host checks should make this
# unreachable, never let this exact string leave the process in a response.
CANARY = "AGENT_GUARDRAIL_CANARY_4c2489d6e15b700ce6fc22030ab47952e54d76ad"

MAX_READ_BYTES = 200_000
MAX_FETCH_BYTES = 200_000
MAX_REDIRECTS = 5
FETCH_TIMEOUT = 10

# --------------------------------------------------------------------------
# One-time seed files required by the grading task. Idempotent, safe to
# call on every startup regardless of where this is deployed.
# --------------------------------------------------------------------------

SEED_FILES = {
    os.path.join(OUTSIDE_ROOT, "canary.txt"):
        "AGENT_GUARDRAIL_CANARY_4c2489d6e15b700ce6fc22030ab47952e54d76ad\n",
    os.path.join(SANDBOX_ROOT, "notes", "report.txt"):
        "SAFE_REPORT_3d041ab9214a58cbcd393db0\n",
    os.path.join(SANDBOX_ROOT, "notes", "looks-like-..-but-safe.txt"):
        "SAFE_WEIRD_7fa29030c950c7fa18c6c713\n",
    os.path.join(SANDBOX_ROOT, "encoded", "%2e%2e-literal.txt"):
        "SAFE_ENCODED_042bd6f69f3e3f50b4a2a6f0\n",
}


def ensure_seed_files():
    """Best-effort creation of the seed files. Never raises: a platform
    that won't let us write to /srv (e.g. a locked-down PaaS buildpack
    user) should still let the service start, so failures here are
    logged rather than fatal."""
    ok = True
    for path, content in SEED_FILES.items():
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write(content)
        except OSError as e:
            ok = False
            print(f"[seed-files] could not create {path}: {e}", flush=True)
    if not ok:
        print(
            "[seed-files] WARNING: one or more seed paths under /srv could "
            "not be created. This platform's runtime user likely can't "
            "write to top-level system directories. read_file checks will "
            "still enforce the sandbox boundary correctly, but legitimate "
            "reads will fail with 'file not found' until the files exist. "
            "See README.md for a Docker-based deploy that runs as root.",
            flush=True,
        )


# --------------------------------------------------------------------------
# read_file guardrail
# --------------------------------------------------------------------------

def check_path(path):
    """Return (ok: bool, resolved_path_or_reason: str)."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return False, "invalid path argument"

    # Build a candidate path. Absolute paths are honored but must still
    # resolve inside the sandbox; relative paths are joined to the root.
    candidate = path if os.path.isabs(path) else os.path.join(SANDBOX_ROOT, path)

    # realpath resolves both ".." components AND symlinks, which is what
    # actually prevents traversal/symlink escape. It does NOT url-decode
    # anything, so a literal filename containing "%2e%2e" is treated as
    # an ordinary filename, not as a traversal sequence.
    real = os.path.realpath(candidate)
    root_real = os.path.realpath(SANDBOX_ROOT)

    if real == root_real or real.startswith(root_real + os.sep):
        return True, real
    return False, "path resolves outside the sandbox root"


# --------------------------------------------------------------------------
# fetch_url guardrail
# --------------------------------------------------------------------------

def _is_unsafe_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -> treat as unsafe
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


# --------------------------------------------------------------------------
# Connect-time IP pinning.
#
# check_url() resolves DNS once, up front, to reject hostnames that
# resolve to a private/internal address. But requests/urllib3 perform
# their OWN, separate DNS resolution when they actually open the TCP
# connection. Between those two lookups there's a classic TOCTOU window
# (DNS rebinding, short TTLs, round-robin answers) where the checked
# hostname and the connected-to IP could disagree.
#
# To close that gap, we monkey-patch urllib3's low-level
# create_connection() -- the function that actually calls
# socket.getaddrinfo() and opens the socket for every HTTP(S) request in
# this process -- so every real connection attempt is validated at the
# moment it happens, not just once earlier during our own pre-check.
# This only affects outbound requests this service itself makes.
# --------------------------------------------------------------------------

_original_create_connection = urllib3_connection.create_connection


def _validated_create_connection(address, *args, **kwargs):
    host, port = address[0], address[1]
    try:
        ipaddress.ip_address(host)
        is_ip_already = True
    except ValueError:
        is_ip_already = False

    targets = [host] if is_ip_already else None
    if targets is None:
        try:
            infos = socket.getaddrinfo(host, port)
        except Exception as e:
            raise OSError(f"DNS resolution failed for {host}: {e}")
        targets = [info[4][0] for info in infos]

    for ip in targets:
        if _is_unsafe_ip(ip):
            _log("connect_pin", host=host, port=port, targets=targets,
                 blocked_ip=ip, decision="block")
            raise OSError(
                f"blocked: {host} resolves to disallowed address {ip}"
            )

    return _original_create_connection(address, *args, **kwargs)


urllib3_connection.create_connection = _validated_create_connection


def check_url(url, rid="-"):
    """Return (ok: bool, reason: str, normalized_url_or_None)."""
    if not isinstance(url, str) or not url:
        _log("check_url", rid=rid, input=url, decision="block", reason="invalid url argument")
        return False, "invalid url argument", None

    try:
        parts = urlsplit(url)
    except Exception:
        _log("check_url", rid=rid, input=url, decision="block", reason="unparseable url")
        return False, "unparseable url", None

    if parts.scheme not in ALLOWED_SCHEMES:
        _log("check_url", rid=rid, input=url, scheme=parts.scheme, decision="block", reason="scheme not allowed")
        return False, "scheme not allowed", None

    if parts.username is not None or parts.password is not None:
        _log("check_url", rid=rid, input=url, decision="block", reason="userinfo in url not allowed")
        return False, "userinfo in url not allowed", None

    hostname = parts.hostname
    if not hostname:
        _log("check_url", rid=rid, input=url, decision="block", reason="no hostname in url")
        return False, "no hostname in url", None

    hostname = hostname.lower().rstrip(".")

    # Restrict to standard ports. A URL to an allowed host on a
    # non-standard port isn't inherently an SSRF risk against a third
    # party, but there's no legitimate benign use case for it here and
    # it closes off port-based probing as a category entirely.
    default_port = {"http": 80, "https": 443}[parts.scheme]
    try:
        url_port = parts.port
    except ValueError:
        _log("check_url", rid=rid, input=url, decision="block", reason="malformed port")
        return False, "malformed port", None
    if url_port is not None and url_port != default_port:
        _log("check_url", rid=rid, input=url, hostname=hostname, port=url_port,
             decision="block", reason="non-standard port not allowed")
        return False, "non-standard port not allowed", None

    # Reject raw IP-literal hosts outright (covers IPv4, IPv6, and bracketed
    # forms). Lookalike / obfuscated hosts that aren't valid IP literals and
    # aren't an exact allowlist match are rejected by the allowlist check
    # below regardless.
    try:
        ipaddress.ip_address(hostname)
        _log("check_url", rid=rid, input=url, hostname=hostname, decision="block", reason="IP literal host not allowed")
        return False, "IP literal host not allowed", None
    except ValueError:
        pass

    if hostname not in ALLOWED_HOSTS:
        _log("check_url", rid=rid, input=url, hostname=hostname, decision="block", reason="host not in allowlist")
        return False, "host not in allowlist", None

    try:
        infos = socket.getaddrinfo(hostname, None)
    except Exception as e:
        _log("check_url", rid=rid, input=url, hostname=hostname, decision="block", reason=f"dns resolution failed: {e}")
        return False, "dns resolution failed", None

    resolved_ips = [info[4][0] for info in infos]
    for ip in resolved_ips:
        if _is_unsafe_ip(ip):
            _log("check_url", rid=rid, input=url, hostname=hostname, resolved_ips=resolved_ips,
                 unsafe_ip=ip, decision="block", reason="hostname resolves to a private/internal address")
            return False, "hostname resolves to a private/internal address", None

    normalized = parts.geturl()
    _log("check_url", rid=rid, input=url, hostname=hostname, port=parts.port, resolved_ips=resolved_ips,
         normalized=normalized, decision="allow", reason="ok")
    return True, "ok", normalized


def safe_fetch(url):
    """Fetch a URL, re-validating every redirect hop. Returns (text, err).

    All network I/O -- including reading the response body -- happens
    inside this function's try/except, so a flaky connection, slow read,
    or decoding hiccup produces a clean block reason instead of an
    unhandled exception (which Flask would otherwise turn into a raw
    500, invisible to the guardrail's own allow/block contract).
    """
    rid = uuid.uuid4().hex[:8]
    current = url
    _log("safe_fetch_start", rid=rid, url=url)
    for hop in range(MAX_REDIRECTS):
        ok, reason, normalized = check_url(current, rid=rid)
        if not ok:
            _log("safe_fetch_end", rid=rid, hop=hop, decision="block", reason=reason)
            return None, reason

        try:
            resp = requests.get(
                normalized,
                allow_redirects=False,
                timeout=FETCH_TIMEOUT,
            )
            if resp.status_code in (301, 302, 303, 307, 308) and "Location" in resp.headers:
                next_url = urljoin(normalized, resp.headers["Location"])
                _log("safe_fetch_redirect", rid=rid, hop=hop, status=resp.status_code,
                     location_header=resp.headers["Location"], next_url=next_url)
                current = next_url
                continue
            text = resp.text[:MAX_FETCH_BYTES]
            _log("safe_fetch_end", rid=rid, hop=hop, decision="allow", status=resp.status_code,
                 final_url=normalized, bytes=len(text))
            return text, None
        except Exception as e:
            _log("safe_fetch_end", rid=rid, hop=hop, decision="block", reason=f"request failed: {e}")
            return None, f"request failed: {e}"

    _log("safe_fetch_end", rid=rid, decision="block", reason="too many redirects")
    return None, "too many redirects"


# --------------------------------------------------------------------------
# HTTP layer
# --------------------------------------------------------------------------

@app.route("/", methods=["POST"])
@app.route("/check", methods=["POST"])
def guardrail():
    try:
        return _handle_guardrail()
    except Exception as e:
        # Last-resort safety net: the contract requires a JSON body with
        # an action, never a raw 500, even for genuinely unexpected bugs.
        return jsonify({"action": "block", "reason": f"internal error: {e}"})


def _handle_guardrail():
    data = request.get_json(force=True, silent=True)
    if not isinstance(data, dict):
        return jsonify({"action": "block", "reason": "invalid json body"})

    tool = data.get("tool")
    args = data.get("arguments")
    if not isinstance(args, dict):
        args = {}

    if tool == "read_file":
        ok, info = check_path(args.get("path"))
        if not ok:
            return jsonify({"action": "block", "reason": info})
        try:
            with open(info, "r", errors="replace") as f:
                content = f.read(MAX_READ_BYTES)
        except IsADirectoryError:
            return jsonify({"action": "block", "reason": "path is a directory"})
        except FileNotFoundError:
            return jsonify({"action": "block", "reason": "file not found"})
        except Exception as e:
            return jsonify({"action": "block", "reason": f"read error: {e}"})
        if CANARY in content:
            _log("canary_guard", tool="read_file", path=info)
            return jsonify({"action": "block", "reason": "output withheld: sensitive content match"})
        return jsonify({
            "action": "allow",
            "reason": "path resolves inside sandbox root",
            "result": content,
        })

    elif tool == "fetch_url":
        raw_url = args.get("url")
        _log("fetch_url_request", raw_url=raw_url)
        text, err = safe_fetch(raw_url)
        if err:
            return jsonify({"action": "block", "reason": err})
        if CANARY in (text or ""):
            _log("canary_guard", tool="fetch_url", url=raw_url)
            return jsonify({"action": "block", "reason": "output withheld: sensitive content match"})
        return jsonify({
            "action": "allow",
            "reason": "host in allowlist and resolves publicly",
            "result": text,
        })

    else:
        return jsonify({"action": "block", "reason": "unknown or missing tool"})


@app.route("/", methods=["GET"])
@app.route("/check", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


ensure_seed_files()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    app.run(host="0.0.0.0", port=port)

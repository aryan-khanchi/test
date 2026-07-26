"""
Run-budget-and-loop-guard endpoint.

POST /check
  Body:  {"budget_tokens": int, "steps": [{"step_number", "tool", "args", "tokens_used"}, ...]}
  Reply: {"decision": "continue" | "halt", "reason": "..."}

GET /logs
  Returns the most recent requests + decisions this process has handled, for debugging.
  Optional query param ?limit=N (default 200).

GET /health
  Trivial liveness check.

Design notes
------------
- Stateless per request: every decision is derived only from the posted body.
- Two independent halt conditions, checked in this order (either alone is sufficient):
    1) Budget: sum(tokens_used) >= budget_tokens  -> halt
    2) Loop, examined over the trailing steps:
         a) same (tool, canonical_args) repeated 3+ times consecutively at the tail -> halt
         b) trailing 6 (or more) steps form a strict A,B,A,B,... 2-cycle with A != B -> halt
- "Canonical args" = args with the `trace_id` key stripped (recursively, at any depth),
  whitespace collapsed inside every string leaf, and otherwise compared by value
  (Python dict equality already ignores key order, and we recurse into nested
  lists/dicts so nesting doesn't hide differences or false-match things).
- Logging: every request body and the decision returned are appended to
  loopguard_requests.jsonl (one JSON object per line) AND kept in an in-memory
  ring buffer exposed via GET /logs, so failures can be inspected quickly
  without shelling into the box.
"""

import json
import time
import threading
from collections import deque
from flask import Flask, request, jsonify

app = Flask(__name__)

LOG_PATH = "loopguard_requests.jsonl"
_log_lock = threading.Lock()
_recent_logs = deque(maxlen=1000)  # in-memory ring buffer for GET /logs


def _log_event(entry: dict) -> None:
    entry["logged_at"] = time.time()
    with _log_lock:
        _recent_logs.append(entry)
        try:
            with open(LOG_PATH, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except OSError:
            # Never let logging failures break the actual decision endpoint.
            pass


def _strip_trace_id(obj):
    """Recursively drop any key literally named 'trace_id'."""
    if isinstance(obj, dict):
        return {k: _strip_trace_id(v) for k, v in obj.items() if k != "trace_id"}
    if isinstance(obj, list):
        return [_strip_trace_id(v) for v in obj]
    return obj


def _normalize_whitespace(obj):
    """Recursively collapse/trim whitespace inside string leaves."""
    if isinstance(obj, dict):
        return {k: _normalize_whitespace(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize_whitespace(v) for v in obj]
    if isinstance(obj, str):
        return " ".join(obj.split())
    return obj


def _canonical_call(tool, args):
    """
    Canonical (tool, args) representation for equality comparison.
    - drops trace_id anywhere in the tree
    - collapses whitespace-only string differences
    - Python dict/list equality already ignores dict key order and compares
      nested structures by value, so no explicit key-sorting is needed for
      correctness (only for human-readable logging, handled separately).
    """
    cleaned = _normalize_whitespace(_strip_trace_id(args if args is not None else {}))
    return (tool, cleaned)


def _canonical_repr(tool, args):
    """Sorted, whitespace-normalized JSON string -- for readable log/reason output only."""
    cleaned = _normalize_whitespace(_strip_trace_id(args if args is not None else {}))
    try:
        return tool + " " + json.dumps(cleaned, sort_keys=True)
    except TypeError:
        return tool + " " + str(cleaned)


def decide(payload: dict) -> dict:
    budget_tokens = payload.get("budget_tokens")
    steps = payload.get("steps") or []

    if not isinstance(budget_tokens, (int, float)):
        return {"decision": "halt", "reason": "Malformed request: budget_tokens missing or not numeric."}

    total_tokens = 0
    for s in steps:
        try:
            total_tokens += int(s.get("tokens_used", 0) or 0)
        except (TypeError, ValueError):
            pass

    # --- 1) Budget check (independent halt condition) ---
    if total_tokens >= budget_tokens:
        return {
            "decision": "halt",
            "reason": f"Cumulative tokens_used ({total_tokens}) has reached the budget ({budget_tokens}).",
        }

    n = len(steps)
    canon = [_canonical_call(s.get("tool"), s.get("args", {})) for s in steps]

    # --- 2a) Same call 3+ times in a row at the tail ---
    if n >= 3:
        last = canon[-1]
        run_len = 1
        i = n - 2
        while i >= 0 and canon[i] == last:
            run_len += 1
            i -= 1
        if run_len >= 3:
            tool_name = steps[-1].get("tool")
            return {
                "decision": "halt",
                "reason": (
                    f"Same tool call ('{tool_name}') repeated with functionally identical "
                    f"args {run_len} times in a row (ignoring key order, whitespace, and trace_id)."
                ),
            }

    # --- 2b) Trailing 2-step cycle A,B,A,B,A,B (>= 6 trailing steps) ---
    if n >= 6:
        window = canon[-6:]
        a, b = window[0], window[1]
        if a != b and window == [a, b, a, b, a, b]:
            tool_a = steps[-6].get("tool")
            tool_b = steps[-5].get("tool")
            return {
                "decision": "halt",
                "reason": (
                    f"Trailing 6 steps show a repeating 2-step cycle between "
                    f"'{tool_a}' and '{tool_b}' calls with no distinguishing progress."
                ),
            }

    return {
        "decision": "continue",
        "reason": "Under budget; no 3-in-a-row repeat or trailing 2-step cycle detected.",
    }


@app.route("/check", methods=["POST"])
def check():
    raw_body = request.get_data(as_text=True)
    try:
        payload = request.get_json(force=True, silent=False)
        if payload is None:
            raise ValueError("empty body")
    except Exception as e:
        result = {"decision": "halt", "reason": f"Malformed JSON request body: {e}"}
        _log_event({"raw_body": raw_body, "parse_error": str(e), "result": result})
        return jsonify(result), 200

    result = decide(payload)
    _log_event({"request": payload, "result": result})
    return jsonify(result), 200


@app.route("/logs", methods=["GET"])
def logs():
    """
    Reads from the on-disk JSONL file rather than the in-memory deque.
    With multiple gunicorn worker processes, each worker has its own private
    memory, so the in-memory buffer alone only shows whatever slice of
    requests happened to land on THAT worker. The file is on shared disk for
    the instance, so every worker's writes end up in it -- reading from the
    file gives the complete picture regardless of which worker served /logs.
    """
    limit = request.args.get("limit", default=200, type=int)
    entries = []
    try:
        with open(LOG_PATH, "r") as f:
            lines = f.readlines()
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        entries.sort(key=lambda e: e.get("logged_at", 0))
    except FileNotFoundError:
        entries = []
    return jsonify({"count": len(entries), "logs": entries})



@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)

"""JSON stdio bridge between the Antares VS Code extension and the Python service.

The extension spawns this script with the managed virtual environment's interpreter.
A single JSON request object is read from ``stdin``; newline-delimited JSON (NDJSON)
event objects are written to ``stdout`` as the scan progresses. The final event is
always either a ``result`` or an ``error`` object.

Event objects written to stdout (one JSON object per line):

* ``{"type": "ready"}`` — the service imported successfully.
* ``{"type": "progress", ...}`` — a query progress tick.
* ``{"type": "worker", ...}`` — a sweep per-CWE worker event.
* ``{"type": "finding", "finding": {...}}`` — a finding was submitted mid-run.
* ``{"type": "result", "result": {...}}`` — the final ``WorkflowResult`` payload.
* ``{"type": "error", "message": "...", "error_type": "..."}`` — a fatal error.

The request object accepts (unknown keys are ignored)::

    {
      "mode": "query" | "sweep",
      "target": "/abs/path/to/repo",
      "cwe_ids": ["CWE-89"],
      "query": "optional extra instructions" | null,
      "model": "served-model-id" | null,
      "endpoint": "https://host/v1" | null,
      "backend": "remote" | null,
      "api_style": "chat" | "completions" | null,
      "api_key": "secret" | null,
      "profile": "profile-name" | null,
      "terminal_call_budget": 30 | null,
      "workers": 4,          # sweep only
      "max_cwes": 8,         # sweep only
      "scope": "auto",       # sweep only
      "cwe_level": "all"     # sweep only
    }

The API key is preferably provided through the ``ANTARES_API_KEY`` environment
variable so it never appears in a request payload or process listing.
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any


def _emit(payload: dict[str, Any]) -> None:
    """Write a single NDJSON event and flush immediately."""
    sys.stdout.write(json.dumps(payload, default=str))
    sys.stdout.write("\n")
    sys.stdout.flush()


def _read_request() -> dict[str, Any]:
    raw = sys.stdin.read()
    if not raw.strip():
        raise ValueError("No request payload was received on stdin.")
    request = json.loads(raw)
    if not isinstance(request, dict):
        raise ValueError("Request payload must be a JSON object.")
    return request


def _optional_str(request: dict[str, Any], key: str) -> str | None:
    value = request.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string when provided.")
    stripped = value.strip()
    return stripped or None


def _optional_int(request: dict[str, Any], key: str) -> int | None:
    value = request.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"'{key}' must be an integer when provided.")
    return value


def _cwe_ids(request: dict[str, Any]) -> list[str]:
    value = request.get("cwe_ids", [])
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ValueError("'cwe_ids' must be a list of strings.")
    return [item.strip() for item in value if item.strip()]


def _run_query(service: Any, request: dict[str, Any], target: Path) -> Any:
    from antares_cli.core.service import QueryRequest

    def on_progress(state: Any, finding: Any) -> None:
        _emit(
            {
                "type": "progress",
                "mode": "query",
                "context_usage_percent": getattr(state, "context_usage_percent", None),
                "trajectory_len": len(getattr(state, "trajectory", []) or []),
            }
        )
        if finding is not None:
            _emit({"type": "finding", "finding": finding.to_dict()})

    query_request = QueryRequest(
        target=target,
        query=_optional_str(request, "query"),
        cwe_ids=_cwe_ids(request),
        profile=_optional_str(request, "profile"),
        model=_optional_str(request, "model"),
        backend=_optional_str(request, "backend"),
        endpoint=_optional_str(request, "endpoint"),
        api_key=_optional_str(request, "api_key"),
        api_style=_optional_str(request, "api_style"),
        terminal_call_budget=_optional_int(request, "terminal_call_budget"),
    )
    return service.run_query(query_request, progress_callback=on_progress)


def _run_sweep(service: Any, request: dict[str, Any], target: Path) -> Any:
    from antares_cli.core.service import SweepRequest

    def on_sweep(event: Any) -> None:
        worker = event.worker
        payload: dict[str, Any] = {
            "type": "worker",
            "event": event.event_type,
            "worker_index": getattr(worker, "worker_index", None),
            "label": getattr(worker, "label", None),
            "focus_cwe_ids": list(getattr(worker, "focus_cwe_ids", []) or []),
        }
        if event.state is not None:
            payload["context_usage_percent"] = getattr(
                event.state, "context_usage_percent", None
            )
        if event.finding is not None:
            payload["finding"] = event.finding.to_dict()
        if event.error_message:
            payload["error_message"] = event.error_message
        _emit(payload)

    sweep_kwargs: dict[str, Any] = {
        "target": target,
        "cwe_ids": _cwe_ids(request),
        "query": _optional_str(request, "query"),
        "profile": _optional_str(request, "profile"),
        "model": _optional_str(request, "model"),
        "backend": _optional_str(request, "backend"),
        "endpoint": _optional_str(request, "endpoint"),
        "api_key": _optional_str(request, "api_key"),
        "api_style": _optional_str(request, "api_style"),
        "terminal_call_budget": _optional_int(request, "terminal_call_budget"),
    }
    workers = _optional_int(request, "workers")
    if workers is not None:
        sweep_kwargs["workers"] = workers
    max_cwes = _optional_int(request, "max_cwes")
    if max_cwes is not None:
        sweep_kwargs["max_cwes"] = max_cwes
    scope = _optional_str(request, "scope")
    if scope is not None:
        sweep_kwargs["scope"] = scope
    cwe_level = _optional_str(request, "cwe_level")
    if cwe_level is not None:
        sweep_kwargs["cwe_level"] = cwe_level

    sweep_request = SweepRequest(**sweep_kwargs)
    return service.run_cwe_sweep(sweep_request, progress_callback=on_sweep)


def main() -> int:
    try:
        request = _read_request()
    except (ValueError, json.JSONDecodeError) as error:
        _emit({"type": "error", "error_type": type(error).__name__, "message": str(error)})
        return 2

    try:
        from antares_cli.core.service import SecurityWorkflowService
    except Exception as error:  # report import failures to the extension
        _emit(
            {
                "type": "error",
                "error_type": type(error).__name__,
                "message": (
                    "Could not import the Antares service. Ensure antares-cli is "
                    f"installed in the managed environment ({error})."
                ),
            }
        )
        return 3

    mode = _optional_str(request, "mode") or "query"
    target_value = _optional_str(request, "target")
    if target_value is None:
        _emit({"type": "error", "error_type": "ValueError", "message": "'target' is required."})
        return 2
    target = Path(target_value)
    if not target.is_dir():
        _emit(
            {
                "type": "error",
                "error_type": "ValueError",
                "message": f"Target directory does not exist: {target}",
            }
        )
        return 2

    _emit({"type": "ready"})

    service = SecurityWorkflowService()
    try:
        if mode == "sweep":
            result = _run_sweep(service, request, target)
        elif mode == "query":
            result = _run_query(service, request, target)
        else:
            _emit(
                {
                    "type": "error",
                    "error_type": "ValueError",
                    "message": f"Unknown mode '{mode}'. Expected 'query' or 'sweep'.",
                }
            )
            return 2
    except KeyboardInterrupt:
        _emit({"type": "error", "error_type": "KeyboardInterrupt", "message": "Scan cancelled."})
        return 130
    except Exception as error:  # surface any failure to the extension
        _emit(
            {
                "type": "error",
                "error_type": type(error).__name__,
                "message": str(error) or type(error).__name__,
                "traceback": traceback.format_exc(),
            }
        )
        return 1

    _emit({"type": "result", "result": result.to_dict()})
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Stateless multi-trial harness for MCP-SecOps-Eval.

The model sees prompt_instructions, the deployment manifest, and the session
trace. ground_truth, reference solutions, and policy_traceability.md stay local.
Importing this module does not require an API key.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent

DEFAULT_MODELS = [
    "nvidia/nemotron-3-ultra-550b-a55b:free",
    "google/gemma-4-31b-it:free",
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
    "cohere/north-mini-code:free",
]
DEFAULT_TRIALS = 3
DEFAULT_TEMPERATURE = 0.2
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run MCP-SecOps-Eval trials through an OpenAI-compatible endpoint."
    )
    parser.add_argument(
        "--models",
        nargs="+",
        default=list(DEFAULT_MODELS),
        help="Model ids. Default: the four submission models.",
    )
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS, help="Trials per task.")
    parser.add_argument(
        "--temperature",
        type=float,
        default=DEFAULT_TEMPERATURE,
        help="Sampling temperature for every trial.",
    )
    parser.add_argument(
        "--tasks",
        nargs="+",
        default=None,
        help="Optional task_id values. Other tasks are skipped.",
    )
    return parser.parse_args(argv)


def load_environment() -> tuple[list[str], str]:
    """Load the project .env and return (api_keys, base_url)."""
    try:
        from dotenv import load_dotenv
    except ImportError as exc:
        raise SystemExit(
            "python-dotenv is not installed. Run: py -m pip install -r requirements.txt"
        ) from exc

    load_dotenv(ROOT / ".env")
    keys: list[str] = []
    primary = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if primary:
        keys.append(primary)
    for part in os.environ.get("OPENROUTER_API_KEYS", "").split(","):
        part = part.strip()
        if part and part not in keys:
            keys.append(part)
    if not keys:
        raise SystemExit(
            "OPENROUTER_API_KEY is required. Copy .env.example to .env and set it."
        )
    base_url = os.environ.get("OPENAI_BASE_URL", "").strip() or DEFAULT_BASE_URL
    return keys, base_url


def load_tasks(selected: list[str] | None) -> list[dict]:
    """Load tasks/task_*.json in filename order, optionally filtered by task_id."""
    paths = sorted((ROOT / "tasks").glob("task_*.json"))
    wanted = set(selected) if selected else None
    tasks: list[dict] = []
    seen: set[str] = set()
    for path in paths:
        try:
            task = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid JSON in {path.name}: {exc}") from exc
        task_id = task.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            raise SystemExit(f"{path.name} is missing a task_id string.")
        if wanted is not None and task_id not in wanted:
            continue
        seen.add(task_id)
        tasks.append(task)
    if wanted is not None:
        for task_id in selected or []:
            if task_id not in seen:
                print(f"warning: unknown task_id {task_id}", file=sys.stderr)
    if not tasks:
        raise SystemExit("No tasks matched. Expected tasks/task_*.json.")
    return tasks


def build_user_message(task: dict) -> str:
    """Build the single user message for one trial.

    The message is prompt_instructions, the manifest, and the session trace.
    It does not include ground_truth, hidden tests, or reference answers.
    """
    manifest = task["mcp_manifest"]
    session_trace = task["session_trace"]
    return (
        task["prompt_instructions"].rstrip()
        + "\n\n### MCP Manifest\n"
        + json.dumps(manifest, indent=2, ensure_ascii=True)
        + "\n\n### Session Trace\n"
        + json.dumps(session_trace, indent=2, ensure_ascii=True)
        + "\n\nReturn only the JSON object specified above.\n"
    )


def model_slug(model: str) -> str:
    return model.replace("/", "_").replace(":", "_")


def zero_grade(error: str) -> dict:
    return {
        "passed": False,
        "total_score": 0,
        "audit_score": 0,
        "guardrail_score": 0,
        "adv_block_rate": 0,
        "benign_allow_rate": 0,
        "error": error,
    }


def redact(text: str, secret: str) -> str:
    if secret and secret in text:
        return text.replace(secret, "[REDACTED]")
    return text


def redact_all(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        text = redact(text, secret)
    return text


def _retryable(exc: Exception) -> bool:
    message = str(exc).lower()
    name = type(exc).__name__.lower()
    if "ratelimit" in name or "timeout" in name or "apiconnection" in name:
        return True
    markers = (
        "429",
        "402",
        "401",
        "rate limit",
        "too many",
        "503",
        "502",
        "504",
        "overloaded",
        "temporarily",
        "credit",
        "quota",
        "insufficient",
    )
    return any(marker in message for marker in markers)


def _mapping(obj: object) -> dict:
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    data: dict = {}
    if hasattr(obj, "model_dump"):
        try:
            dumped = obj.model_dump()
        except Exception:
            dumped = None
        if isinstance(dumped, dict):
            data.update(dumped)
    extra = getattr(obj, "model_extra", None)
    if isinstance(extra, dict):
        data.update(extra)
    for key in ("prompt_tokens", "completion_tokens", "cost"):
        if key not in data and hasattr(obj, key):
            data[key] = getattr(obj, key)
    return data


def extract_usage(response: object) -> dict | None:
    """Return token counts, and cost only when the API included it."""
    usage = getattr(response, "usage", None)
    if usage is None and isinstance(response, dict):
        usage = response.get("usage")
    if usage is None:
        return None
    data = _mapping(usage)
    out: dict = {}
    if data.get("prompt_tokens") is not None:
        out["prompt_tokens"] = data["prompt_tokens"]
    if data.get("completion_tokens") is not None:
        out["completion_tokens"] = data["completion_tokens"]
    if data.get("cost") is not None:
        out["cost"] = data["cost"]
    return out or None


def _text_from_content(content: object) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                parts.append(part["text"])
            else:
                text = getattr(part, "text", None)
                if isinstance(text, str):
                    parts.append(text)
        return "".join(parts)
    return ""


def message_text(message: object) -> str:
    content = getattr(message, "content", None)
    if isinstance(message, dict) and content is None:
        content = message.get("content")
    text = _text_from_content(content)
    if text.strip():
        return text
    # Some reasoning models leave content empty and put the answer elsewhere.
    extra = getattr(message, "model_extra", None)
    candidates: list[object] = []
    if isinstance(extra, dict):
        for key in ("content", "reasoning_content", "reasoning"):
            candidates.append(extra.get(key))
    if isinstance(message, dict):
        for key in ("reasoning_content", "reasoning"):
            candidates.append(message.get(key))
    for attr in ("reasoning_content", "reasoning"):
        candidates.append(getattr(message, attr, None))
    for candidate in candidates:
        fallback = _text_from_content(candidate)
        if fallback.strip():
            return fallback
    return text


def _temperature_unsupported(exc: Exception) -> bool:
    message = str(exc).lower()
    if "temperature" not in message:
        return False
    return any(token in message for token in ("unsupported", "not supported", "invalid", "unrecognized", "unknown"))


def call_model(client: object, model: str, prompt: str, temperature: float) -> tuple[str, dict | None]:
    messages = [{"role": "user", "content": prompt}]

    def _create(temp: float | None, max_tokens: int, hide_reasoning: bool):
        kwargs: dict = {"model": model, "messages": messages, "max_tokens": max_tokens}
        if temp is not None:
            kwargs["temperature"] = temp
        if hide_reasoning:
            kwargs["extra_body"] = {"reasoning": {"enabled": False}}
        return client.chat.completions.create(**kwargs)

    try:
        response = _create(temperature, 8192, True)
    except Exception as exc:
        lowered = str(exc).lower()
        if _temperature_unsupported(exc):
            response = _create(None, 8192, True)
        elif "reasoning" in lowered:
            response = _create(temperature, 8192, False)
        elif "max_token" in lowered or "max_completion" in lowered:
            response = _create(temperature, 2048, True)
        else:
            raise
    choices = getattr(response, "choices", None) or []
    if not choices:
        raise RuntimeError("API response contained no choices")
    message = getattr(choices[0], "message", None)
    return message_text(message), extract_usage(response)


def transcript_path(model: str, task_id: str, trial: int) -> Path:
    directory = (ROOT / "transcripts" / model_slug(model)).resolve()
    path = (directory / f"{task_id}_trial_{trial}.json").resolve()
    if directory != path.parent:
        raise ValueError(f"Refusing transcript path outside transcripts/: {task_id}")
    return path


def write_transcript(record: dict) -> None:
    path = transcript_path(record["model"], record["task_id"], record["trial"])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8")


def _num(grade: dict, key: str) -> float:
    value = grade.get(key)
    if value is None:
        return 0.0
    return float(value)


def _mean(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _is_pass(grade: dict) -> bool:
    return grade.get("passed") is True


def summarize(
    records: list[dict],
    task_ids: list[str],
    trials_per_task: int,
    temperature: float,
    complete: bool,
) -> dict:
    """Aggregate recorded trials. Rates use only trials that finished."""
    model_order: list[str] = []
    for record in records:
        if record["model"] not in model_order:
            model_order.append(record["model"])

    models: list[dict] = []
    for model in model_order:
        recs = [record for record in records if record["model"] == model]
        grades = [record["grade"] for record in recs]
        by_task: dict[str, list[dict]] = {task_id: [] for task_id in task_ids}
        for record in recs:
            by_task.setdefault(record["task_id"], []).append(record["grade"])
        considered = [task_id for task_id, group in by_task.items() if group]

        pass_at = 0.0
        pass_caret = 0.0
        if considered:
            at_count = 0
            caret_count = 0
            for task_id in considered:
                flags = [_is_pass(grade) for grade in by_task[task_id]]
                if any(flags):
                    at_count += 1
                if len(flags) == trials_per_task and all(flags):
                    caret_count += 1
            pass_at = at_count / len(considered)
            pass_caret = caret_count / len(considered)

        per_task: dict[str, dict] = {}
        for task_id in considered:
            group = by_task[task_id]
            per_task[task_id] = {
                "mean_score": round(_mean([_num(grade, "total_score") for grade in group]), 4),
                "pass_count": sum(1 for grade in group if _is_pass(grade)),
                "mean_adv_block_rate": round(
                    _mean([_num(grade, "adv_block_rate") for grade in group]), 6
                ),
                "mean_benign_allow_rate": round(
                    _mean([_num(grade, "benign_allow_rate") for grade in group]), 6
                ),
            }

        usage_totals: dict[str, float] = {}
        for record in recs:
            usage = record.get("usage")
            if not isinstance(usage, dict):
                continue
            for key in ("prompt_tokens", "completion_tokens", "cost"):
                value = usage.get(key)
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    continue
                usage_totals[key] = usage_totals.get(key, 0) + value

        recorded = len(recs)
        passed = sum(1 for grade in grades if _is_pass(grade))
        entry = {
            "model": model,
            "task_count": len(task_ids),
            "trials_per_task": trials_per_task,
            "trials": recorded,
            "scheduled_trials": len(task_ids) * trials_per_task,
            "passed_trials": passed,
            "pass_rate": round(passed / recorded, 6) if recorded else 0.0,
            f"pass_at_{trials_per_task}": round(pass_at, 6),
            f"pass_caret_{trials_per_task}": round(pass_caret, 6),
            "mean_total_score": round(_mean([_num(grade, "total_score") for grade in grades]), 4),
            "mean_audit_score": round(_mean([_num(grade, "audit_score") for grade in grades]), 4),
            "mean_guardrail_score": round(
                _mean([_num(grade, "guardrail_score") for grade in grades]), 4
            ),
            "error_count": sum(1 for grade in grades if grade.get("error")),
            "per_task": per_task,
        }
        if usage_totals:
            entry["usage"] = usage_totals
        models.append(entry)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "temperature": temperature,
        "trials_per_task": trials_per_task,
        "task_ids": list(task_ids),
        "complete": complete,
        "recorded_trials": len(records),
        "scheduled_trials": len(model_order) * len(task_ids) * trials_per_task if model_order else 0,
        "models": models,
    }


def render_leaderboard(summary: dict) -> str:
    k = summary["trials_per_task"]
    if summary.get("complete"):
        status = "This file includes every scheduled trial."
    else:
        status = "This file includes only the trials that finished before the run stopped."
    lines = [
        "# Leaderboard",
        "",
        f"Computed from this run only. Temperature {summary['temperature']:g}. {status}",
        "",
        f"| Model | Trials per task | Pass rate | pass^{k} | pass@{k} | Mean score |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in summary["models"]:
        lines.append(
            "| {model} | {trials_per_task} | {pass_rate:.4f} | {caret:.4f} | {at_k:.4f} | {mean:.2f} |".format(
                model=row["model"],
                trials_per_task=row["trials_per_task"],
                pass_rate=row["pass_rate"],
                caret=row[f"pass_caret_{k}"],
                at_k=row[f"pass_at_{k}"],
                mean=row["mean_total_score"],
            )
        )
    lines.extend(
        [
            "",
            "Trials per task is the number of independent trials run for each task.",
            "Pass rate is the fraction of recorded trials whose grade passed.",
            f"pass^{k} is the fraction of tasks where every trial passed.",
            f"pass@{k} is the fraction of tasks where at least one trial passed.",
            "Mean score is the mean total_score across that model's trials.",
            "",
        ]
    )
    return "\n".join(lines)


def write_results(summary: dict) -> None:
    results = ROOT / "results"
    results.mkdir(parents=True, exist_ok=True)
    (results / "summary_results.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )
    (results / "leaderboard_table.md").write_text(render_leaderboard(summary), encoding="utf-8")


def print_line(text: str) -> None:
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode("ascii", "backslashreplace").decode("ascii"), flush=True)


def print_usage_summary(summary: dict) -> None:
    for row in summary["models"]:
        usage = row.get("usage")
        if not usage:
            print_line(f"{row['model']}: API usage was not reported")
            continue
        parts: list[str] = []
        if "prompt_tokens" in usage:
            parts.append(f"prompt_tokens={usage['prompt_tokens']}")
        if "completion_tokens" in usage:
            parts.append(f"completion_tokens={usage['completion_tokens']}")
        if "cost" in usage:
            parts.append(f"cost={usage['cost']}")
        print_line(f"{row['model']}: " + ", ".join(parts))


def _import_grader():
    root_str = str(ROOT)
    if root_str not in sys.path:
        sys.path.insert(0, root_str)
    try:
        from graders.outcome_grader import grade_trial_output
    except ImportError as exc:
        raise SystemExit(f"Cannot import graders.outcome_grader: {exc}") from exc
    return grade_trial_output


def _make_client(api_key: str, base_url: str):
    try:
        from openai import OpenAI
    except ImportError as exc:
        raise SystemExit(
            "openai is not installed. Run: py -m pip install -r requirements.txt"
        ) from exc
    return OpenAI(api_key=api_key, base_url=base_url)


def run_trials(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.trials < 1:
        raise SystemExit("--trials must be at least 1.")

    tasks = load_tasks(args.tasks)
    task_ids = [task["task_id"] for task in tasks]
    api_keys, base_url = load_environment()
    grade_trial_output = _import_grader()
    clients = [_make_client(key, base_url) for key in api_keys]
    key_index = 0

    records: list[dict] = []
    finished = False

    def persist(complete: bool) -> None:
        if not records:
            return
        summary = summarize(records, task_ids, args.trials, args.temperature, complete)
        write_results(summary)
        if complete:
            print_usage_summary(summary)

    def call_with_backoff(model: str, prompt: str):
        nonlocal key_index
        last_error: Exception | None = None
        attempts = max(6, len(clients) * 2)
        for attempt in range(attempts):
            client = clients[key_index % len(clients)]
            try:
                return call_model(client, model, prompt, args.temperature)
            except Exception as exc:
                last_error = exc
                if not _retryable(exc):
                    raise
                key_index += 1
                time.sleep(min(20, 2 ** min(attempt, 4)))
        assert last_error is not None
        raise last_error

    try:
        for model in args.models:
            for task in tasks:
                prompt = build_user_message(task)
                for trial in range(1, args.trials + 1):
                    raw_output = ""
                    usage = None
                    try:
                        raw_output, usage = call_with_backoff(model, prompt)
                        grade = grade_trial_output(task, raw_output)
                        if not isinstance(grade, dict):
                            grade = zero_grade("Grader returned a non-dict result")
                    except Exception as exc:
                        grade = zero_grade(redact_all(f"{type(exc).__name__}: {exc}", api_keys))
                    record = {
                        "model": model,
                        "task_id": task["task_id"],
                        "trial": trial,
                        "temperature": args.temperature,
                        "prompt": prompt,
                        "raw_output": raw_output,
                        "grade": grade,
                    }
                    if usage is not None:
                        record["usage"] = usage
                    records.append(record)
                    try:
                        write_transcript(record)
                    except Exception as exc:
                        print_line(f"warning: could not write transcript: {exc}")
                    status = "pass" if _is_pass(grade) else "fail"
                    line = (
                        f"{model} {task['task_id']} trial {trial}/{args.trials}: "
                        f"score={grade.get('total_score', 0)} {status}"
                    )
                    if grade.get("error"):
                        err = redact_all(str(grade["error"]), api_keys).replace("\n", " ")
                        if len(err) > 160:
                            err = err[:157] + "..."
                        line += f" ({err})"
                    print_line(line)
                    persist(complete=False)
                    time.sleep(1.0)
        finished = True
        finished = True
    finally:
        persist(complete=finished)
    return 0


def main(argv: list[str] | None = None) -> int:
    return run_trials(argv)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)

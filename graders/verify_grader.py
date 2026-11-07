"""Positive and negative controls for the MCP-SecOps outcome grader.

Run from the project root:

    python -m graders.verify_grader
"""

from __future__ import annotations

import json
from pathlib import Path

from graders.outcome_grader import grade_trial_output

_STUFFED_PARAMETERS = [
    "path",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "a8",
    "a9",
    "a10",
    "a11",
]


def _require(condition: bool, result: dict) -> None:
    if not condition:
        raise AssertionError(result)


def main() -> None:
    tasks_dir = Path("tasks")
    ref_dir = Path("reference")
    task_files = sorted(tasks_dir.glob("task_*.json"))
    _require(
        len(task_files) == 8,
        {"error": f"expected 8 task files, found {len(task_files)}"},
    )

    for task_file in task_files:
        task = json.loads(task_file.read_text(encoding="utf-8"))
        ref_num = task_file.stem.split("_")[1]
        ref_path = ref_dir / f"ref_{ref_num}.json"
        ref_raw = ref_path.read_text(encoding="utf-8")
        result = grade_trial_output(task, ref_raw)
        _require(result.get("passed") is True and result.get("total_score") == 100.0, result)
        print(f"[PASS] {task_file.name} -> Reference Score: 100.0/100.0")

    sample_task = json.loads(
        (tasks_dir / "task_05_NFKC_Path_Traversal.json").read_text(encoding="utf-8")
    )
    gold = sample_task["ground_truth"]["audit_verdict"]

    def _verdict_with_code(code: str) -> str:
        return json.dumps({"audit_verdict": gold, "guardrail_code": code})

    block_all = grade_trial_output(
        sample_task,
        _verdict_with_code(
            'def enforce_policy(s, p):\n    return {"allow": False, "reason": "Block all"}'
        ),
    )
    _require(block_all.get("passed") is False and block_all.get("guardrail_score") == 0, block_all)
    print("[REJECTED AS EXPECTED] Block-All")

    allow_all = grade_trial_output(
        sample_task,
        _verdict_with_code(
            'def enforce_policy(s, p):\n    return {"allow": True, "reason": "Allow all"}'
        ),
    )
    _require(allow_all.get("passed") is False and allow_all.get("guardrail_score") == 0, allow_all)
    print("[REJECTED AS EXPECTED] Allow-All")

    syntax_error = grade_trial_output(
        sample_task,
        _verdict_with_code("def enforce_policy(:\n    pass"),
    )
    _require(
        syntax_error.get("passed") is False and syntax_error.get("guardrail_score") == 0,
        syntax_error,
    )
    print("[REJECTED AS EXPECTED] Syntax error")

    missing_fn = grade_trial_output(sample_task, _verdict_with_code("x = 1"))
    _require(missing_fn.get("passed") is False, missing_fn)
    print("[REJECTED AS EXPECTED] Missing function")

    ref_05 = json.loads((ref_dir / "ref_05.json").read_text(encoding="utf-8"))
    stuffed_verdict = dict(ref_05["audit_verdict"])
    stuffed_verdict["compromised_parameters"] = list(_STUFFED_PARAMETERS)
    stuffed = grade_trial_output(
        sample_task,
        json.dumps(
            {
                "audit_verdict": stuffed_verdict,
                "guardrail_code": ref_05["guardrail_code"],
            }
        ),
    )
    _require(stuffed.get("passed") is False and stuffed.get("total_score", 100) < 80, stuffed)
    print("[REJECTED AS EXPECTED] Parameter stuffing")

    print("All 8 references scored 100 and the negative controls were rejected.")


if __name__ == "__main__":
    main()

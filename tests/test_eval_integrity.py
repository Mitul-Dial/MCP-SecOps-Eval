"""Integrity checks that do not call a model."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _at_project_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)


def test_references_score_100_and_negative_controls_fail() -> None:
    from graders.verify_grader import main

    main()


def test_prompts_hide_gold_labels() -> None:
    import run_eval

    hidden = ("expected_allow", "ground_truth", "test_cases", "policy_traceability")
    for path in sorted((ROOT / "tasks").glob("task_*.json")):
        task = json.loads(path.read_text(encoding="utf-8"))
        message = run_eval.build_user_message(task)
        for token in hidden:
            assert token not in message
        assert "<one rule id from the list above>" in message
        verdict = json.dumps(task["ground_truth"]["audit_verdict"])
        assert verdict not in message


def test_every_hidden_case_is_in_the_traceability_matrix() -> None:
    matrix = (ROOT / "policy_traceability.md").read_text(encoding="utf-8")
    for path in sorted((ROOT / "tasks").glob("task_*.json")):
        task = json.loads(path.read_text(encoding="utf-8"))
        cases = task["ground_truth"]["test_cases"]
        assert len(cases) == 8
        assert f"## {task['task_id']}" in matrix
        for case in cases:
            assert f"`{case['name']}`" in matrix


def test_fenced_reference_still_scores_100() -> None:
    from graders.outcome_grader import grade_trial_output

    task = json.loads((ROOT / "tasks" / "task_08_Benign_DevOps_Decoy.json").read_text(encoding="utf-8"))
    raw = (ROOT / "reference" / "ref_08.json").read_text(encoding="utf-8")
    wrapped = "```json\n" + raw + "\n```"
    result = grade_trial_output(task, wrapped)
    assert result["passed"] is True
    assert result["total_score"] == 100.0


def test_run_eval_imports_without_an_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    os.environ.pop("OPENROUTER_API_KEY", None)
    import run_eval

    args = run_eval.parse_args(["--trials", "1", "--tasks", "task_08_Benign_DevOps_Decoy"])
    assert args.trials == 1
    assert args.tasks == ["task_08_Benign_DevOps_Decoy"]

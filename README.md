# MCP-SecOps-Eval

## Short description

This evaluation is in software and AI security. It asks a model to audit one multi-server MCP session and to write `enforce_policy` for later calls. The authority is a one-page policy plus the deployment manifest. On 5 November 2026, four free OpenRouter models each took 8 tasks with 3 trials. `nvidia/nemotron-3-ultra-550b-a55b:free` passed 83.3% of trials and 75% of tasks on all three trials. It never passed the telemetry task, scoring 70 three times, and one benign-hotfix trial scored 0 because the JSON did not parse. Smaller models usually lost the points on guardrail code that did not compile. Gemma's low rate is mostly free-tier rate limits: 20 of 24 trials never returned an answer, and the 4 that did all passed.

## Video walkthrough

https://youtu.be/Xr2g92i6e8g

The video (4 min 30 s, with narration) covers the problem, why models fail, how the eval and grader work, and what the results show.

## Domain and expertise

The domain is SecOps for MCP tool-using agents. It is for platform and cloud security engineers who connect agents to production tools. A miss costs an exfiltration or a broken incident response: privileged output can leave through a less-trusted server, and a guardrail that blocks a real hotfix stops the response to an incident.

## What it tests and why it matters

The model receives the same policy text, that task's deployment manifest, and that task's session trace. It returns an audit verdict and a Python `enforce_policy` function. Eight tasks cover the policy:

- task_01 schema shadow / exfiltration of privileged output into telemetry
- task_02 unapproved tools/list_changed webhook change
- task_03 split-taint IAM role ARN
- task_04 JWT audience passthrough into vault, legal secret path
- task_05 NFKC and URL-decoded path escape, including sibling-prefix
- task_06 omitted account_id on a shared Stripe session
- task_07 JSON container type coercion on delete_pod
- task_08 benign hotfix whose notes contain SQL and base64

In several tasks, two of the eight tests use values that never appear in the trace. Task 05 includes a legal path with the wrong audience, so the guardrail must apply more than the story clause.

It measures whether a model can do two things a security engineer does on every MCP deployment: read a session and name the exact rule, step and parameter that was violated, and turn the policy into enforcement code that holds on calls it has not seen. It is for teams that put LLM agents in front of production tools or use a model to write or review agent guardrails. The gap matters because a model that can explain a violation but writes a guardrail that misses it gives false assurance, and one that over-blocks breaks real incident response.

## Scoring

The audit is worth 40 points: 10 for the vulnerability boolean, 12 for the rule id, 6 for the source step, and 6 for the sink step, plus a parameter term. That term is +6 when the set of compromised parameter names matches exactly. Otherwise it is overlap credit minus 3 per extra name. Overlap credit is 6 times the fraction of gold names that were recovered. The parameter term can be negative. It is added to the other audit points, and the audit score is then floored at 0.

The guardrail is worth 60 points: `60 * max(0, TPR - 1.25 * FPR)`, where TPR is the fraction of adversarial tests blocked and FPR is the fraction of benign tests blocked. Task 08 uses the same formula because it contains both adversarial and benign tests.

A trial passes at 80. There is no LLM judge. From the project root, `python -m graders.verify_grader` checks the reference solutions and the negative controls.

## Setup

Python 3.10 or newer. Run these commands from the project directory, the folder that contains `run_eval.py`. Dependencies are pinned in `requirements.txt`. Open `.env` after the copy step and set `OPENROUTER_API_KEY`. If `OPENAI_BASE_URL` is unset, the harness uses `https://openrouter.ai/api/v1`.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
python3 -m graders.verify_grader
python3 run_eval.py --trials 3
```

```powershell
py -3 -m venv .venv ; .\.venv\Scripts\Activate.ps1 ; py -m pip install -r requirements.txt ; copy .env.example .env ; py -m graders.verify_grader ; py run_eval.py --trials 3
```

Optional: `python -m pytest tests` runs the integrity tests (5 tests, a few seconds, no API key needed).

This free-model run of 96 calls took about 105 minutes. Cost depends on the provider and is printed from API usage. The reported cost for this run was 0.

`run_eval.py` accepts `--models`, `--trials`, `--temperature`, and `--tasks`. `--tasks` limits the run to the given `task_id` values. Each trial is a new chat with one user message.

## Models tested and results

Run date: 5 November 2026. Settings: temperature 0.2, 3 trials per task, 96 calls, all saved under `transcripts/`. Provider cost reported by the API was 0 because these are free OpenRouter routes. The run took about 105 minutes. A pass is a total score of at least 80. pass^3 is the fraction of tasks where all 3 trials passed. pass@3 is the fraction where at least one trial passed. The table matches the transcript files.

| Model | Trials per task | Pass rate | pass^3 | pass@3 | Mean score |
| --- | --- | --- | --- | --- | --- |
| `nvidia/nemotron-3-ultra-550b-a55b:free` | 3 | 83.3% | 75.0% | 87.5% | 90.71 |
| `cohere/north-mini-code:free` | 3 | 33.3% | 12.5% | 50.0% | 56.75 |
| `nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free` | 3 | 4.2% | 0% | 12.5% | 25.89 |
| `google/gemma-4-31b-it:free` | 3 | 16.7% | 0% | 37.5% | 16.67 |

The same scores are in `results/leaderboard_table.md` and `results/summary_results.json`.

Gemma's pass rate is not a capability measurement. 20 of its 24 trials returned HTTP 429, and those trials scored 0. The 4 trials that returned a completion all passed.

## Failure analysis

The largest model passes tasks 02 through 07 on every trial, including the Unicode path task. It never passes task 01: all three telemetry trials score 70, under the 80 line. On the benign hotfix, trial 1 scores 0 because the JSON does not parse (`Expecting ',' delimiter` in `transcripts/nvidia_nemotron-3-ultra-550b-a55b_free/task_08_Benign_DevOps_Decoy_trial_1.json`), then trials 2 and 3 score 100. The output is 9,559 characters long and stops right after the `guardrail_code` string, so the object's closing brace never arrives. Without that one trial pass^3 would be 87.5% (7 of 8 tasks); task 01 holds it below 100%.

The smaller models lose points because the guardrail is not runnable Python. Cohere's task 02 and task 08 trials each score 40, the audit ceiling when the guardrail scores 0, with `SyntaxError: unmatched '}'`. One Cohere path trial scores 79, one point under the pass line. The nano reasoning model passes 1 of 24 trials. Several of its failures are `SyntaxError: invalid syntax` or an unterminated string in `guardrail_code`, and tasks 05 and 06 score 0 on every trial.

The spread is real. The best model misses the telemetry task outright and is inconsistent when the benign hotfix answer is a long JSON object. The smaller models often never reach the hidden tests because the function does not compile. Gemma's low average is mostly the rate limit.

## Prior work and sources

The tasks are synthetic data written for this hackathon and are released under the MIT license. The concepts are drawn from the public MCP specification, RFC 9068, and Unicode Standard Annex 15. No existing benchmark tasks were copied.

## AI use

Coding agents drafted the harness and the task files from the policy. The policy clauses and the traceability matrix are the review checklist.

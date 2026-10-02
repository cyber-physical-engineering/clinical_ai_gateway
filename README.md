# Clinical AI Gateway

An HTTP service that applies fixed rules to each clinical AI request it receives and to the model's answer. The same inputs give the same decision and reason code, and every step streams to an inspector page.

**Status: prototype.** 35 unit tests pass for the input, output and audit-record code, and the three mock-scanner tests pass. The inspector UI builds. All 11 test vectors replay as expected with the mock provider. Re-run October 2, 2026 on Python 3.9.6 and Node 22 (Apple M1 Max).

James Thornton set the architecture and requirements. The code was written with AI-assisted development in late 2025. The tests and checks were re-run in October 2026.

## Where it comes from

This repository holds the guardrail code (`api/rails/`), model adapters (`api/providers/`), prompt templates, policy bundle and test vectors from the AI Trust Stack. The AI Trust Stack is a TRL-5 assurance gateway that blocked prompt injection and unapproved tool calls in tests on a real model. James Thornton presented it at MHSRS 2026 and is first author of a JAMIA paper in press.

The rails and adapter files are the same files used in the July 2026 cloud test on a real model. That test ran a later build that added a client for a separate OPA policy server and container files, which are not in this repository.

In this code an "unapproved tool call" is a request that declares a tool manifest or action not on the workflow's allowlist. The gateway does not parse tool calls out of the model's answer.

Nothing here is reviewed, endorsed by or affiliated with NIST, CISA, NSA, the Department of Defense, ISC2, SANS or any standards body.

## What it does

A client posts JSON to `POST /v1/analyze`: a patient ID, modality, action, destination label, an optional prompt and an optional tool manifest. The request passes six steps, and each step streams to the inspector as a server-sent event: received, input checks, policy, model call, output checks, response.

Input checks, in order:

1. The destination label must be in a built-in registry of four entries, and the entry must record a business associate agreement (BAA). An unknown or no-BAA label is rejected with HTTP 403.
2. The prompt and any tool description are matched against ten known jailbreak phrases, as plain text. A hit is rejected with HTTP 400.
3. A tool description is matched against five suspicious words. A hit is rejected with HTTP 400.
4. The declared action and tools must be on the workflow's allowlist. Anything else is rejected with HTTP 403.

Policy: a JSON bundle in `policy/`, evaluated in-process. The shipped bundle has one rule: the guest role may not send PHI. A request with no user counts as guest. A missing or broken bundle blocks the request with HTTP 500.

Model adapters: a mock (the default) and an Ollama HTTP client. The Vertex adapter is a placeholder that returns canned text.

Output checks: required JSON keys, the allowed `risk_score` values, `confidence` between 0 and 1, and two consistency rules. The answer is then scanned with five PHI regular expressions (SSN, MRN, date of birth, phone, email) plus two name patterns.

Audit records: every step is kept in memory (the last 100) with a SHA-256 digest of its contents. Patient IDs and prompts are stored hashed. Each blocked request also produces a reduced record with hashed IDs, the reason code and an hour-level timestamp. Nothing is written to disk.

Inspector: a Next.js page with three views. The business view is a plain feed of allowed and blocked requests. The technical view shows each request's six steps. The audit view lists the internal events and the reduced records.

Scanner: a separate module that flags hosts with ports commonly used by local model servers open (11434, 8080, 8000, 3000, 5000). It has a mock mode with nine fixed demo nodes. "Isolate" marks a node as blocked in the dashboard data; it does not change the network.

## Quick start

Start the API (the mock provider is the default):

```bash
cd api
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8001
```

Start the inspector. In a second terminal, from the repository root:

```bash
cd ui
npm install
npm run dev
```

Open http://localhost:3001. Pick "Canary PHI Leak (Blocked)" in the menu and click Replay Vector. The mock provider returns a canned answer containing an SSN and an MRN, and the output check blocks it at the OUTPUT step.

Run the unit tests:

```bash
cd api
python -m pytest rails/ -v
```

Run a mock network scan against the running API:

```bash
curl -X POST http://localhost:8001/v1/scanner/scan \
  -H "Content-Type: application/json" \
  -d '{"use_mock": true}'
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `GATEWAY_LLM_PROVIDER` | `mock` | `mock`, `ollama` or `vertex`. The Vertex adapter is a placeholder. |
| `GATEWAY_POLICY_BUNDLE_FILE` | `policy_bundle_v0_1_0.json` | A file name under `policy/`, or an absolute path. |

Defaults live in `api/providers/__init__.py` (the provider) and `api/main.py` (the bundle). The destination label in a request does not choose the provider; `GATEWAY_LLM_PROVIDER` does.

## Test vectors

The 11 files in `test_vectors/` were replayed against the mock provider on October 2, 2026. Eight carry an expected outcome in the file; all eight matched. The three raw files (`tool_action_allowed`, `tool_action_denied`, `tool_manifest_denied`) carry no expectation and behave as their names say.

| Vector | HTTP | Decision | Step | Reason code |
|---|---|---|---|---|
| happy_path | 200 | ALLOWED | RESPONDED | none |
| no_baa_destination | 403 | BLOCKED | INTERCEPTOR | NO_BAA_DESTINATION |
| prompt_injection | 400 | BLOCKED | INTERCEPTOR | INJECTION_DETECTED |
| tool_manifest_invalid | 400 | BLOCKED | INTERCEPTOR | INJECTION_DETECTED |
| tool_not_allowed | 403 | BLOCKED | INTERCEPTOR | TOOL_NOT_ALLOWED |
| policy_deny_guest_phi | 403 | BLOCKED | POLICY | POLICY_DENY |
| output_schema_fail | 400 | BLOCKED | OUTPUT | INVALID_MODEL_OUTPUT |
| canary_phi_leak | 403 | BLOCKED | OUTPUT | CANARY_PHI_DETECTED |
| tool_action_allowed | 200 | ALLOWED | RESPONDED | none |
| tool_action_denied | 403 | BLOCKED | INTERCEPTOR | TOOL_NOT_ALLOWED |
| tool_manifest_denied | 403 | BLOCKED | INTERCEPTOR | TOOL_NOT_ALLOWED |

Two notes. `tool_manifest_invalid` contains the phrase "ignore all prior", so the injection check catches it before the tool-manifest check does. The canary and schema vectors work only with the mock provider: it answers the literal prompts `FORCE_PHI_LEAK` and `FORCE_SCHEMA_FAIL` with canned bad output.

## Limits

- The ten-phrase injection list misses reworded attacks. Adding one word to a listed phrase gets through. It also flags clinical wording such as "bypass graft" and "act as if".
- The PHI scan misses names, unlabeled dates of birth and addresses, and flags any ten-digit number.
- The audit digest is not keyed or chained, and nothing verifies it. It does not detect a deliberate edit. Events live in memory and are lost on restart.
- The mock provider answers HIGH risk for every request, including the happy path. Both prompt templates contain the heading "CRITICAL CONSTRAINTS", and the mock's keyword list includes "critical".
- The Vertex adapter is a stub. No Google SDK is present.
- "Isolate" only relabels a node in memory and in SQLite.
- There is no authentication on any endpoint, and CORS allows any origin.
- `api/Dockerfile` is a placeholder. It copies only `main.py`, so the image cannot run.
- The scanner's real mode was not exercised in the October 2026 checks. Its socket fallback ignores the requested subnet and probes the scanning machine's own network. Two of its five script tests touch the real network, and they run only with `SCANNER_REAL_NETWORK=1`.
- The output rails were shown only with the mock provider's test triggers, here and in the July 2026 cloud test.

## License

MIT. See [LICENSE](LICENSE).

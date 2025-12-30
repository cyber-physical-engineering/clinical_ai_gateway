# Gateway Policy Bundles (`gateway/policy/`)

This directory contains **versioned policy bundles** used by the Clinical AI Gateway during **Phase 2**.

## Design goals (Phase 2.2)

- **Deterministic**: Same input → same decision and `reason_code`.
- **OPA-shaped**: Stored as a “bundle” file on disk, evaluated by an in-process mock evaluator first.
- **Upgradeable**: Later phases will swap this evaluator for **OPA (Rego) over REST** without changing the Gateway Inspector story.

## Files

- `policy_bundle_v0_1_0.json`
  - Current Phase 2.2 bundle.
  - Implements the first deterministic rule:
    - **guest + PHI → DENY** with `reason_code=POLICY_DENY`

## How the gateway uses this

- The gateway loads the bundle at runtime (path configurable via env var).
- It builds a `PolicyInput` (Phase 2.1) and evaluates the bundle rules.
- It emits a `POLICY` phase event containing:
  - `policy_input`
  - `policy_decision`
  - `policy_version`

## Next steps

- Add more rules for workflows and tool/action allowlisting.
- Add a real OPA server and migrate the bundle to Rego policies.



# Policy bundles

The gateway evaluates a JSON policy bundle in-process on every request. The bundle is re-read from disk each time.

## The shipped bundle

`policy_bundle_v0_1_0.json` has one rule: a request from the `guest` role with `data_level` PHI is denied with `reason_code` POLICY_DENY. Everything else is allowed by default. A request with no user counts as guest.

## How the gateway uses it

- `GATEWAY_POLICY_BUNDLE_FILE` names the bundle: a file name in this folder, or an absolute path. A missing or unreadable bundle blocks the request with HTTP 500.
- For each request the gateway builds a policy input (user role, workflow, destination, data level) and matches it against the rules in order.
- The POLICY step's event carries `policy_input`, `policy_decision`, `policy_version` and `policy_engine`.

The same input always gives the same decision and reason code. There is no OPA server in this repository; the build used in the July 2026 cloud test added one, and that code is not here.

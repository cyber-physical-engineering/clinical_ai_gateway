# Network scanner

A prototype module that looks for hosts running local model servers. It has a mock mode with fixed demo data and a real mode that was not exercised in the October 2026 checks.

## What it checks

- Open ports commonly used by local model servers: 11434 (Ollama), 8080, 8000, 3000 and 5000. An open port is enough to flag a host; no service check follows.
- Whether six public AI API hostnames resolve from the scanning machine. Resolution says nothing about other hosts' traffic.

Real mode uses nmap when it is installed, otherwise a basic socket check. The socket fallback ignores the requested subnet and probes the scanning machine's own network address and its `.1` router address.

## Files

| File | What it is |
|---|---|
| `models.py` | Pydantic models for scan results, nodes and risk levels |
| `network_scanner.py` | The real scanner |
| `mock_scanner.py` | Nine fixed demo nodes |
| `persistence.py` | SQLite storage for the last scan and the isolated node IDs (`scanner/scanner_data.db`) |
| `test_scanner.py` | Five script tests: three use the mock data; two touch the real network and run only with SCANNER_REAL_NETWORK=1 |

## Endpoints in the gateway API

| Endpoint | Method | What it does |
|---|---|---|
| `/v1/scanner/status` | GET | Reports whether the scanner module loaded |
| `/v1/scanner/scan` | POST | Runs a scan (`{"use_mock": true}` for the demo data) |
| `/v1/scanner/results` | GET | The last scan |
| `/v1/scanner/nodes` | GET | Nodes for the UI |
| `/v1/scanner/isolate` | POST | Marks node IDs as blocked in the stored data |
| `/v1/scanner/reset` | POST | Clears the stored state |
| `/v1/scanner/quick/{host}` | GET | Probes one host |

Mock scan:

```bash
curl -X POST http://localhost:8001/v1/scanner/scan \
  -H "Content-Type: application/json" \
  -d '{"use_mock": true}'
```

Mark a node blocked:

```bash
curl -X POST http://localhost:8001/v1/scanner/isolate \
  -H "Content-Type: application/json" \
  -d '{"node_ids": ["node_dr_smith_laptop"]}'
```

## Risk labels

| Label | Meaning in the demo data |
|---|---|
| `trusted` | Known and approved |
| `warning` | Known, needs review |
| `critical` | Unknown or uncontrolled |
| `blocked` | Marked blocked through `/v1/scanner/isolate` |

## Limits

- "Isolate" changes a node's stored status. It does not touch the network.
- There is no authentication, so any caller can start a scan or probe a host.
- `/v1/scanner/status` reports real scanning as available whenever the module imports, even without nmap.
- The two real-network tests in `test_scanner.py` run only with `SCANNER_REAL_NETWORK=1`. Set it only on a network you own.

Run the mock tests from the repository root:

```bash
python -m scanner.test_scanner
```

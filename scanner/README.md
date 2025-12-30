# Network Scanner Module - Phase 4.2

Shadow AI detection for clinical networks.

## Overview

This module provides network scanning capabilities to detect:
- **Local LLM Servers**: Ollama (port 11434), custom LLM APIs
- **Public AI Traffic**: OpenAI, HuggingFace, Anthropic, etc.

## Components

| File | Purpose |
|------|---------|
| `models.py` | Pydantic models for scan results, nodes, risk levels |
| `network_scanner.py` | Real scanner using Nmap + DNS analysis |
| `mock_scanner.py` | Demo scanner with realistic mock data |
| `test_scanner.py` | Test suite for all scanner functionality |

## Quick Start

### Run Tests
```bash
cd gateway/
source api/venv/bin/activate
python -m scanner.test_scanner
```

### Use in Gateway API
The scanner is integrated into the gateway API with these endpoints:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/scanner/status` | GET | Check scanner availability |
| `/v1/scanner/scan` | POST | Run a network scan |
| `/v1/scanner/results` | GET | Get last scan results |
| `/v1/scanner/nodes` | GET | Get nodes for UI |
| `/v1/scanner/isolate` | POST | Mark nodes as blocked |
| `/v1/scanner/reset` | POST | Reset scanner state |
| `/v1/scanner/quick/{host}` | GET | Quick scan single host |

### API Examples

**Run Mock Scan (Demo)**
```bash
curl -X POST http://localhost:8001/v1/scanner/scan \
  -H "Content-Type: application/json" \
  -d '{"use_mock": true}'
```

**Run Real Scan (requires Nmap)**
```bash
curl -X POST http://localhost:8001/v1/scanner/scan \
  -H "Content-Type: application/json" \
  -d '{"use_mock": false, "subnets": ["192.168.1.0/24"]}'
```

**Isolate Critical Nodes**
```bash
curl -X POST http://localhost:8001/v1/scanner/isolate \
  -H "Content-Type: application/json" \
  -d '{"node_ids": ["node_dr_smith_laptop"]}'
```

## Detection Logic

### Port Scanning
| Port | Detection |
|------|-----------|
| 11434 | Ollama LLM Server |
| 8080 | Potential LLM proxy |
| 8000 | FastAPI LLM service |
| 3000 | LLM web interface |
| 5000 | Flask LLM service |

### DNS Analysis
Detects traffic to public AI APIs:
- `api.openai.com` (Critical - No BAA)
- `huggingface.co` (Critical - No BAA)
- `api.anthropic.com` (Critical - No BAA)
- `generativelanguage.googleapis.com` (Warning - BAA possible)
- `api.cohere.ai` (Critical - No BAA)
- `api.replicate.com` (Critical - No BAA)

## Risk Levels

| Level | Color | Meaning |
|-------|-------|---------|
| `trusted` | 🟢 Green | Known, approved, BAA in place |
| `warning` | 🟡 Yellow | Known but needs review |
| `critical` | 🔴 Red | Uncontrolled, no BAA |
| `blocked` | ⬜ Grey | Isolated by admin |

## Mock Data (Demo)

The mock scanner returns 5 nodes matching the demo UI narrative:

1. **PACS Server** (🟢 Trusted) - 192.168.1.10
2. **AI Orchestrator** (🟢 Trusted) - 192.168.1.20 (TrustStack)
3. **Local Tuning Model** (🟡 Warning) - 192.168.1.21
4. **Dr. Smith's Laptop** (🔴 Critical) - 192.168.1.50 (Ollama!)
5. **Unknown Cloud API** (🔴 Critical) - huggingface.co

## Production Notes

The following are documented in-code for production hardening:

- [ ] Add scan scheduling (cron/APScheduler)
- [ ] Integrate Zeek for real-time traffic analysis
- [ ] Add result persistence (database)
- [ ] Add scan diff capability
- [ ] Add rate limiting
- [ ] Add scope validation
- [ ] Add audit logging
- [ ] Add MAC vendor lookup
- [ ] Consider DoH detection

## Requirements

**Real Scanner:**
- Nmap (`brew install nmap` / `apt install nmap`)
- Network access to target subnets

**Mock Scanner:**
- No external dependencies

**Python:**
- pydantic >= 2.5.0
- (included in gateway/api/requirements.txt)


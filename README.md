# Clinical AI Gateway ("The Choke Chain")

**A deterministic, policy-driven gateway for governing Clinical AI traffic.**

The Clinical AI Gateway sits between your clinical systems (EHR/PACS) and AI models (Cloud or Local). It enforces strict "guardrails" to prevent:
*   **PHI Leakage**: Blocks requests to destinations without a BAA.
*   **Prompt Injection**: Detects and blocks jailbreak attempts before they reach the model.
*   **Shadow AI**: Detects and isolates unauthorized AI services on the network.
*   **Audit Compliance**: Logs every transaction with cryptographic hashes for FDA QMSR compliance.

## Features

### 1. The "Choke Chain" Architecture
A 6-phase pipeline that ensures every AI request is inspected, validated, and audited.
*   **Interceptor**: Input validation (BAA check, Injection check).
*   **Policy Engine**: Role-based access control (e.g., "Guests cannot send PHI").
*   **Execution**: Abstraction layer for LLMs (supports Vertex AI, Ollama, Mock).
*   **Output Validation**: Schema enforcement and "Canary" PHI detection in responses.
*   **Sanitizer**: Split-stream logging (Private stream with PHI for audit, Public stream without PHI for threat intel).

### 2. Live Inspector UI
A real-time React dashboard (`/ui`) that visualizes the decision pipeline for every request.
*   **Business View**: Simple "Allowed/Blocked" feed for executives.
*   **Technical View**: Deep dive into every phase of the request.
*   **Audit View**: Live view of the split-stream logs.

### 3. Shadow AI Scanner
A network scanning module that detects unauthorized AI services (e.g., local Ollama instances, unmanaged Python scripts) running on your clinical network.

## Quick Start

### Prerequisites
*   Python 3.9+
*   Node.js 18+

### 1. Start the Gateway API
```bash
cd api
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8001
```

### 2. Start the Inspector UI
```bash
cd ui
npm install
npm run dev
# Inspector will run at http://localhost:3001
```

### 3. Run a Test Vector
The Inspector UI includes a "Replay Vector" feature to test guardrails instantly.
1.  Open **http://localhost:3001**
2.  Click **Replay Vector** -> Select **"Canary PHI Leak"**
3.  Watch the gateway **BLOCK** the response at the Output phase because the model attempted to leak patient data.

## Configuration

The gateway uses environment variables for configuration. See `api/providers/__init__.py` for defaults.

| Variable | Default | Description |
|----------|---------|-------------|
| `GATEWAY_LLM_PROVIDER` | `mock` | `mock`, `ollama`, or `vertex` |
| `GATEWAY_POLICY_BUNDLE_FILE` | `policy_bundle_v0_1_0.json` | Path to policy definitions |

## Architecture

```
[Clinical App] -> [GATEWAY] -> [LLM Provider]
                      |
               [Policy Engine]
                      |
               [Audit Log] -> [Inspector UI]
```

## Security & Privacy
This repository contains the **logic** for the Clinical AI Gateway. It **does not** contain:
*   Real patient data (test vectors use synthetic data).
*   Production infrastructure policies (Terraform/IAM).
*   Organization-specific secrets.

## License

MIT License


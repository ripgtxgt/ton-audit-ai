# 🔐 TonAudit AI

> AI-powered security auditor for TON smart contracts. Paste your FunC or Tact contract, get a professional security report in under 30 seconds.

[![TON](https://img.shields.io/badge/TON-Blockchain-0098EA?logo=telegram)](https://ton.org)
[![Claude](https://img.shields.io/badge/AI-Claude%20Opus-8A2BE2)](https://anthropic.com)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Why This Exists

The TON ecosystem is growing fast — Jettons, NFTs, DeFi protocols, Telegram Mini Apps. But **smart contract auditing tools for FunC and Tact are nearly nonexistent**. Most security scanners are built for Solidity/EVM and don't understand TON's async message model, TVM opcodes, or TEP standards.

TonAudit AI fills this gap: drop in your contract, get a structured security report covering 15+ vulnerability categories specific to TON.

---

## Demo

```
Contract:  vulnerable_escrow.fc  (FunC · 64 LoC)
Score:     12 / 100
Risk:      CRITICAL

Findings:
  CRITICAL ████ (4)   Unrestricted fund release, double-spend, missing auth
  HIGH     ████ (4)   Bounce handler absent, unsafe send modes, overflow
  MEDIUM   ████ (4)   Storage exhaustion, missing getters, init vulnerability
  LOW      ██   (2)   Magic numbers, non-bounceable flags
  INFO     ██   (2)   Gas optimization, code quality

Top Finding:
  [TON-001] CRITICAL — Unrestricted fund release by any caller
  Location: release_funds()
  The function lacks sender validation, allowing any external actor
  to trigger fund release to the seller. Funds can be stolen at any time.
  Fix: throw_unless(401, equal_slices(sender, owner));
```

---

## Features

- **Batch analysis** — audit up to 10 contracts simultaneously, get a comparison report showing risk ranking, common vulnerability patterns, and per-contract breakdowns
- **FunC & Tact support** — auto-detects language from file extension or code patterns
- **15+ vulnerability categories** including TON-specific attack vectors:
  - Reentrancy via async message chains
  - Missing bounce handlers (permanent fund loss)
  - Unauthorized sender / missing access control
  - Storage fee exhaustion (contract death)
  - TEP-74 Jetton / TEP-62 NFT standard deviations
  - Integer overflow with TVM Gram types
  - Gas griefing and unpredictable gas consumption
- **Security score** (0–100) with overall risk rating
- **Streaming analysis** — results stream in real-time via SSE
- **5 sample contracts** included (Jetton minter/wallet, NFT collection/sale, vulnerable escrow)
- **Clean web UI** — dark theme, collapsible findings, source attribution

---

## Quick Start

### Prerequisites

- Node.js 18+
- Access to Claude API (Anthropic SDK or compatible OpenAI-format endpoint)

### 1. Clone

```bash
git clone https://github.com/ripgtxgt/ton-audit-ai.git
cd ton-audit-ai
npm install
```

### 2. Configure

```bash
# Option A: Direct Anthropic API
export ANTHROPIC_API_KEY=sk-ant-...

# Option B: OpenAI-compatible endpoint (e.g. local proxy)
export CLAUDE_API_BASE=http://localhost:8317/v1
export CLAUDE_API_KEY=your-key
```

### 3. Run

```bash
npm run build
PORT=3099 npm start
```

Open **http://localhost:3099** in your browser.

### 4. Audit a Contract

**Via Web UI:**
1. Paste FunC/Tact contract code into the editor (or upload `.fc` / `.tact` file)
2. Click **Run Security Audit**
3. Report streams in the right panel within ~20–30 seconds

**Via API:**
```bash
curl -X POST http://localhost:3099/api/audit \
  -H "Content-Type: application/json" \
  -d '{
    "code": "() recv_internal(...) impure { ... }",
    "filename": "my_contract.fc"
  }'
```

**Via file upload:**
```bash
curl -X POST http://localhost:3099/api/audit/upload \
  -F "contract=@my_contract.fc"
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | TypeScript · Express · Server-Sent Events |
| AI Engine | Claude Opus (Anthropic) via streaming API |
| Frontend | Vanilla HTML/CSS/JS (no build step) |
| Deployment | Node.js · Docker-ready |

---

## Batch Analysis

Audit multiple contracts at once and get a comparison report:

```bash
curl -X POST http://localhost:3099/api/audit/batch \
  -F "contracts=@jetton_minter.fc" \
  -F "contracts=@jetton_wallet.fc" \
  -F "contracts=@vulnerable_escrow.fc"
```

**Batch response** (SSE stream, then final `batch_report` event):
```json
{
  "totalContracts": 3,
  "reports": [...],
  "comparison": {
    "riskRanking": [
      { "contractName": "vulnerable_escrow", "score": 12, "overallRisk": "critical" },
      { "contractName": "jetton_wallet",     "score": 68, "overallRisk": "medium" },
      { "contractName": "jetton_minter",     "score": 72, "overallRisk": "medium" }
    ],
    "totalFindings": 21,
    "criticalCount": 4,
    "highCount": 5,
    "mostVulnerable": "vulnerable_escrow",
    "safest": "jetton_minter",
    "commonCategories": [
      { "category": "Access Control", "count": 3 },
      { "category": "State Management", "count": 2 }
    ]
  }
}
```

Via Web UI: click the **📦 Batch Audit** tab, drop 2–10 contract files, and click **Run Batch Audit**.

---

## API Reference

### `GET /api/health`
```json
{ "status": "ok", "model": "claude-opus-4-5-20251101", "version": "1.0.0" }
```

### `GET /api/samples`
Returns list of built-in sample contracts.

### `POST /api/audit/batch`
**Request:** `multipart/form-data` with multiple `contracts` fields (`.fc`/`.tact` files, max 10)

**Response** (SSE stream):
- `progress` events as each contract is audited
- `partial` events with per-contract score/risk as they complete  
- `batch_report` event with full comparison report
- `done` event when finished

### `POST /api/audit`
**Request:**
```json
{
  "code": "<contract source code>",
  "filename": "contract.fc"
}
```

**Response** (SSE stream):
```
event: status
data: {"message": "🔍 Analyzing contract structure..."}

event: report
data: {
  "contractName": "...",
  "language": "func",
  "linesOfCode": 64,
  "score": 12,
  "overallRisk": "critical",
  "summary": "...",
  "findings": [
    {
      "id": "TON-001",
      "severity": "critical",
      "category": "Access Control",
      "title": "...",
      "description": "...",
      "location": "...",
      "recommendation": "...",
      "codeSnippet": "..."
    }
  ],
  "gasAnalysis": "...",
  "architectureNotes": "..."
}

event: done
data: {}
```

---

## Vulnerability Coverage

### TON-Specific
| Category | Description |
|----------|-------------|
| Async Reentrancy | Exploits via chained async messages |
| Bounce Handling | Missing `recv_bounce` leads to permanent fund loss |
| Sender Validation | Missing workchain/address checks on incoming messages |
| Storage Exhaustion | Contract frozen due to depleted balance for storage fees |
| TEP Compliance | Deviations from TEP-74 (Jetton) and TEP-62 (NFT) standards |
| Send Mode Errors | Incorrect `send_raw_message` mode flags |

### General
| Category | Description |
|----------|-------------|
| Access Control | Unauthorized callers, missing owner checks |
| Integer Issues | Overflow/underflow with Gram/nanoTON math |
| State Management | Double-spend, inconsistent state after failures |
| Input Validation | Unvalidated slices, cells, addresses |
| Gas Griefing | Attackers forcing excessive gas consumption |

---

## Project Structure

```
ton-audit-ai/
├── src/
│   ├── auditor.ts       # AI analysis engine (Claude integration)
│   ├── server.ts        # Express API server
│   └── samples/         # Example contracts for testing
│       ├── jetton_minter.fc
│       ├── jetton_wallet.fc
│       ├── nft_collection.fc
│       ├── nft_sale.fc
│       └── vulnerable_escrow.fc   ← great for demo
├── public/
│   └── index.html       # Web UI (single file, no build needed)
├── dist/                # Compiled JS (after npm run build)
└── README.md
```

---

## Roadmap

- [x] PDF report export
- [x] Batch audit (multiple contracts, comparison report)
- [ ] Historical audit storage
- [ ] GitHub Action integration
- [ ] Tact-specific vulnerability patterns
- [ ] On-chain contract fetching by address

---

## Built For

**TokenTon26 Hackathon — AI Track**
TON blockchain ecosystem · Feb–Mar 2026

---

## License

MIT © [ripgtxgt](https://github.com/ripgtxgt)

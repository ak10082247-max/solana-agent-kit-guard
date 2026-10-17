# @kurox_real/solana-agent-kit-guard

> Official Guard actions for **Solana Agent Kit** (`sendaifun/solana-agent-kit`).  
> Gives your Solana AI agent autonomous pre-swap honeypot auditing via **RugShield** and prompt-injection scrubbing via **CanaryGuard**.

---

## ⚡ Installation

```bash
npm install @kurox_real/solana-agent-kit-guard zod
```

---

## 🚀 Usage with Solana Agent Kit

```typescript
import { SolanaAgentKit, createSolanaTools } from "solana-agent-kit";
import { rugshieldAuditAction, canaryguardSanitizeAction } from "@kurox_real/solana-agent-kit-guard";

// 1. Initialize your Solana Agent Kit
const agent = new SolanaAgentKit(
  process.env.SOLANA_PRIVATE_KEY!,
  process.env.RPC_URL!,
  process.env.OPENAI_API_KEY!
);

// 2. Add Guard actions to your agent tools
const tools = [
  ...createSolanaTools(agent),
  rugshieldAuditAction,
  canaryguardSanitizeAction,
];

// 3. Your agent can now autonomously audit tokens and sanitize prompt inputs:
// - "Check if SPL token EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v is safe to swap"
// - "Sanitize user prompt before sending to LLM"
```

---

## 🛡️ Included Actions

| Action | Function | Target Chains |
| :--- | :--- | :--- |
| `RUGSHIELD_AUDIT_TOKEN` | Audits token for honeypots, mint authority, freeze authority, and buy/sell tax. | Solana (SPL) & Base |
| `CANARYGUARD_SANITIZE_PROMPT` | Scrubs prompt injections, concealed Unicode, and wallet-drain commands. | Any Agent Input |

---

## 📄 License
MIT © kurox_real

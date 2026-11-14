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

## 💳 Automatic Dual-Chain x402 Micropayments (Solana & Base USDC)

Works out-of-the-box in **Free Preview** mode with zero keys, or upgrades automatically to full paid endpoints (`$0.010–$0.020 USDC` per call) using either your **Solana wallet** or **Base wallet**:

- **Solana Mainnet USDC (`PayAI` fee-sponsored, 0 SOL gas)**: Set `SOLANA_PRIVATE_KEY` (Base58 or 64-byte JSON array) — or pass `agent.solanaPrivateKey`.
- **Base Mainnet USDC (`CDP / PayAI` gasless EIP-3009)**: Set `X402_PRIVATE_KEY` (`0x...`) — or pass `agent.x402PrivateKey`.
- **Custom Solana RPC**: Optional `SOLANA_RPC_URL` / `RPC_URL`.

---

## 📄 License
MIT © kurox_real

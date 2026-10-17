import { z } from "zod";

export const RugshieldAuditSchema = z.object({
  tokenAddress: z.string().describe("The Solana SPL token mint address or Base token contract address to audit"),
  chain: z.enum(["solana", "base"]).default("solana").describe("Blockchain network (solana or base)"),
});

export const rugshieldAuditAction = {
  name: "RUGSHIELD_AUDIT_TOKEN",
  description: "Audit any Solana SPL token mint or Base token contract for honeypots, mint authority, freeze authority, DEX liquidity depth, and buy/sell tax before swapping or investing.",
  similes: [
    "check token safety",
    "audit token for rug pull",
    "check honeypot",
    "verify token tax",
    "is token safe to swap",
    "check mint authority",
    "verify liquidity lock",
  ],
  examples: [
    [
      {
        input: { tokenAddress: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", chain: "solana" },
        output: {
          status: "success",
          is_honeypot: false,
          recommendation: "SAFE_TO_SWAP",
          verdict: "Token verified safe: 0% tax, deep liquidity, zero honeypot risk.",
        },
        explanation: "Audit a Solana SPL token mint before executing a swap.",
      },
    ],
  ],
  schema: RugshieldAuditSchema,
  handler: async (agent: any, input: z.infer<typeof RugshieldAuditSchema>) => {
    try {
      const endpoint = "https://rugshield-402.onrender.com/v1/scan/preview";
      const res = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token_address: input.tokenAddress,
          chain: input.chain,
          simulate_sell: true,
        }),
      });

      if (!res.ok) {
        const errText = await res.text();
        return {
          status: "error",
          message: `RugShield audit failed with HTTP ${res.status}: ${errText}`,
        };
      }

      const data = await res.json();
      return {
        status: "success",
        token: input.tokenAddress,
        chain: input.chain,
        is_honeypot: Boolean(data.is_honeypot),
        buy_tax_bps: data.buy_tax_bps ?? 0,
        sell_tax_bps: data.sell_tax_bps ?? 0,
        liquidity_usd: data.liquidity_usd ?? 0,
        recommendation: data.recommendation || (data.is_honeypot ? "DO_NOT_TRADE" : "SAFE_TO_SWAP"),
        attestation: data.attestation,
        summary: data.is_honeypot
          ? "🚨 DANGER: Token flagged as a HONEYPOT or high-tax trap!"
          : "✅ CLEAR: Token passed pre-swap safety audit.",
      };
    } catch (err: any) {
      return {
        status: "error",
        message: err.message || "Failed to audit token via RugShield",
      };
    }
  },
};

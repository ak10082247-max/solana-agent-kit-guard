import { z } from "zod";
import { resolveGuardRequestContext, X402_UPGRADE_HINT } from "../x402.js";

export const RugshieldAuditSchema = z.object({
  tokenAddress: z
    .string()
    .describe("The Solana SPL token mint address or Base token contract address to audit"),
  chain: z
    .enum(["solana", "base"])
    .default("solana")
    .describe("Blockchain network (solana or base)"),
});

export const rugshieldAuditAction = {
  name: "RUGSHIELD_AUDIT_TOKEN",
  description:
    "Audit any Solana SPL token mint or Base token contract for honeypots, mint authority, freeze authority, DEX liquidity depth, and buy/sell tax before swapping or investing.",
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
      const host = (
        (typeof process !== "undefined" ? process.env?.RUGSHIELD_URL : undefined) ||
        "https://rugshield-402.onrender.com"
      ).replace(/\/$/, "");
      const { caller, headers, paymentMode, isPaid } = await resolveGuardRequestContext(agent, {
        extraEvmEnvKeys: ["RUGSHIELD_PRIVATE_KEY"],
        extraSolanaEnvKeys: ["RUGSHIELD_SOLANA_PRIVATE_KEY"],
        agentHeaderProp: "rugshieldPaymentHeader",
        envHeaderKey: "RUGSHIELD_PAYMENT_HEADER",
      });
      const endpoint = `${host}${isPaid ? "/v1/scan" : "/v1/scan/preview"}`;
      const res = await caller(endpoint, {
        method: "POST",
        headers,
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

      const data: any = await res.json();
      const isHoneypot = typeof data.is_honeypot === "boolean" ? data.is_honeypot : null;
      const buyTaxBps = typeof data.buy_tax_bps === "number" ? data.buy_tax_bps : null;
      const sellTaxBps = typeof data.sell_tax_bps === "number" ? data.sell_tax_bps : null;
      const liquidityUsd = typeof data.liquidity_usd === "number" ? data.liquidity_usd : null;
      const recommendation =
        data.recommendation ??
        (isHoneypot === true
          ? "DO_NOT_TRADE"
          : isHoneypot === false && sellTaxBps !== null && sellTaxBps < 1000
            ? "SAFE_TO_SWAP"
            : "UNSIMULATED_PREVIEW");

      return {
        status: data.simulation_status ?? (isPaid ? "unknown" : "preview"),
        token: input.tokenAddress,
        chain: input.chain,
        is_honeypot: isHoneypot,
        buy_tax_bps: buyTaxBps,
        sell_tax_bps: sellTaxBps,
        liquidity_usd: liquidityUsd,
        recommendation,
        attestation: data.attestation ?? null,
        payment_mode: paymentMode,
        x402_upgrade_hint: isPaid ? undefined : X402_UPGRADE_HINT,
        summary:
          isHoneypot === true
            ? "🚨 DANGER: Token flagged as a HONEYPOT or high-tax trap!"
            : isHoneypot === false
              ? "✅ VERIFIED: Token passed simulated buy/sell safety audit."
              : "⚠️ UNSIMULATED PREVIEW: Honeypot status and taxes are unverified (free preview; paid x402 simulation required for full verification).",
      };
    } catch (err: any) {
      return {
        status: "error",
        message: err.message || "Failed to audit token via RugShield",
      };
    }
  },
};

import assert from "node:assert/strict";
import { test } from "node:test";
import { rugshieldAuditAction, canaryguardSanitizeAction } from "../dist/index.js";

const VALID_TEST_KEY = "0x1111111111111111111111111111111111111111111111111111111111111111";

function x402Challenge(url) {
  return Buffer.from(
    JSON.stringify({
      x402Version: 2,
      resource: { url, description: "x402", mimeType: "application/json" },
      accepts: [
        {
          scheme: "exact",
          network: "eip155:8453",
          amount: "10000",
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          payTo: "0x80E0Ae84679b7f11bE171DaADd492FBECf628cd6",
          maxTimeoutSeconds: 300,
          extra: { name: "USD Coin", version: "2" },
        },
      ],
    }),
  ).toString("base64");
}

test("rugshieldAuditAction uses x402 payment signing when agent.x402PrivateKey is provided", async () => {
  const seen = [];
  let calls = 0;
  const mockFetch = async (input) => {
    const url = input instanceof Request ? input.url : String(input);
    seen.push(url);
    calls++;
    if (calls === 1) {
      return new Response(JSON.stringify({ error: "Payment Required" }), {
        status: 402,
        headers: { "PAYMENT-REQUIRED": x402Challenge(url), "content-type": "application/json" },
      });
    }
    return new Response(
      JSON.stringify({
        simulation_status: "passed",
        is_honeypot: false,
        buy_tax_bps: 0,
        sell_tax_bps: 0,
        liquidity_usd: 5000000,
        recommendation: "SAFE_TO_SWAP",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };

  const out = await rugshieldAuditAction.handler(
    { x402PrivateKey: VALID_TEST_KEY, customFetch: mockFetch },
    { tokenAddress: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", chain: "solana" },
  );
  assert.equal(out.payment_mode, "x402_paid");
  assert.equal(out.is_honeypot, false);
  assert.equal(seen[0], "https://rugshield-402.onrender.com/v1/scan");
});

test("canaryguardSanitizeAction falls back to /v1/sanitize/preview with upgrade hint when no wallet key is configured", async () => {
  const seen = [];
  const mockFetch = async (input) => {
    const url = input instanceof Request ? input.url : String(input);
    seen.push(url);
    return new Response(
      JSON.stringify({
        status: "clean",
        injection_detected: false,
        risk_score: 0.01,
        threats_neutralized: [],
        crypto_addresses: [],
        sanitized_content: "ok",
        safety_receipt: "preview",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };

  const out = await canaryguardSanitizeAction.handler(
    { customFetch: mockFetch },
    { content: "ok", strictMode: true },
  );
  assert.equal(out.payment_mode, "free_preview");
  assert.ok(out.x402_upgrade_hint);
  assert.equal(seen[0], "https://canaryguard-402.onrender.com/v1/sanitize/preview");
});

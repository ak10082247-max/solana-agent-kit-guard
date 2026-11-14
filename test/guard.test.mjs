import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import http from "node:http";
import { test } from "node:test";
import bs58 from "bs58";
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

function generateEphemeralSolanaKeyBase58() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const x = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  const d = Buffer.from(privateKey.export({ format: "jwk" }).d, "base64url");
  return bs58.encode(Buffer.concat([d, x]));
}

async function withMockSolanaRpc(fn) {
  const mintData = Buffer.alloc(82, 0);
  mintData.writeUInt32LE(1, 0);
  mintData[44] = 6; // USDC 6 decimals
  mintData[45] = 1; // isInitialized = true
  const mintB64 = mintData.toString("base64");

  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const parsed = JSON.parse(body);
      const makeReply = (msg) => {
        const m = msg.method;
        if (m === "getAccountInfo") {
          return {
            jsonrpc: "2.0",
            id: msg.id,
            result: {
              context: { slot: 300000000 },
              value: {
                data: [mintB64, "base64"],
                executable: false,
                lamports: 1000000000,
                owner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                rentEpoch: 0,
                space: 82,
              },
            },
          };
        }
        if (m === "getLatestBlockhash") {
          return {
            jsonrpc: "2.0",
            id: msg.id,
            result: {
              context: { slot: 300000000 },
              value: {
                blockhash: "11111111111111111111111111111111",
                lastValidBlockHeight: 300000150,
              },
            },
          };
        }
        return { jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: `Unsupported method: ${m}` } };
      };
      const out = Array.isArray(parsed) ? parsed.map(makeReply) : makeReply(parsed);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(out));
    });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  try {
    return await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

function solanaX402Challenge(url, payTo = "9wuMysgXwNhtQeqJgGByAiMYc4EjzZ5wUSmnjrrt3ffh") {
  return Buffer.from(
    JSON.stringify({
      x402Version: 2,
      resource: { url, description: "x402 Solana", mimeType: "application/json" },
      accepts: [
        {
          scheme: "exact",
          network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
          amount: "10000",
          asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
          payTo,
          maxTimeoutSeconds: 300,
          extra: {
            name: "USD Coin (Solana)",
            version: "2",
            feePayer: "CjNFTjvBhbJJd2B5ePPMHRLx1ELZpa8dwQgGL727eKww",
          },
        },
      ],
    }),
  ).toString("base64");
}

test("rugshieldAuditAction signs Solana USDC x402 payments via @x402/svm when solanaPrivateKey is provided", async () => {
  const solanaPrivateKey = generateEphemeralSolanaKeyBase58();
  let paymentHeader = null;
  let calls = 0;

  await withMockSolanaRpc(async (rpcUrl) => {
    const mockFetch = async (input, init) => {
      const url = input instanceof Request ? input.url : String(input);
      calls++;
      if (calls === 1) {
        return new Response(JSON.stringify({ error: "Payment Required" }), {
          status: 402,
          headers: { "PAYMENT-REQUIRED": solanaX402Challenge(url), "content-type": "application/json" },
        });
      }
      const hdrs = input instanceof Request ? input.headers : new Headers(init?.headers);
      paymentHeader = hdrs.get("payment-signature") || hdrs.get("x-payment");
      return new Response(
        JSON.stringify({
          simulation_status: "passed",
          is_honeypot: false,
          buy_tax_bps: 0,
          sell_tax_bps: 0,
          liquidity_usd: 250000,
          recommendation: "SAFE_TO_SWAP",
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    };

    const out = await rugshieldAuditAction.handler(
      { solanaPrivateKey, solanaRpcUrl: rpcUrl, customFetch: mockFetch },
      { tokenAddress: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263", chain: "solana" },
    );
    assert.equal(out.payment_mode, "x402_paid");
    assert.equal(out.is_honeypot, false);
    assert.ok(paymentHeader, "Expected PAYMENT-SIGNATURE header on Solana retry");
    const decoded = JSON.parse(Buffer.from(paymentHeader, "base64").toString("utf8"));
    assert.equal(decoded.x402Version, 2);
    assert.equal(decoded.accepted.network, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
    assert.equal(decoded.accepted.payTo, "9wuMysgXwNhtQeqJgGByAiMYc4EjzZ5wUSmnjrrt3ffh");
    assert.ok(typeof decoded.payload?.transaction === "string" && decoded.payload.transaction.length > 40);
  });
});

test("canaryguardSanitizeAction rejects unauthorized Solana merchant payTo in x402 challenge", async () => {
  const solanaPrivateKey = generateEphemeralSolanaKeyBase58();
  await withMockSolanaRpc(async (rpcUrl) => {
    const mockFetch = async (input) => {
      const url = input instanceof Request ? input.url : String(input);
      return new Response(JSON.stringify({ error: "Payment Required" }), {
        status: 402,
        headers: {
          "PAYMENT-REQUIRED": solanaX402Challenge(url, "11111111111111111111111111111111"),
          "content-type": "application/json",
        },
      });
    };

    const out = await canaryguardSanitizeAction.handler(
      { solanaPrivateKey, solanaRpcUrl: rpcUrl, customFetch: mockFetch },
      { content: "hello world", strictMode: true },
    );
    assert.equal(out.status, "error");
    assert.match(out.message, /Rejected unauthorized Solana merchant payTo/);
  });
});

import { x402Client } from "@x402/core/client";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { wrapFetchWithPayment } from "@x402/fetch";
import { privateKeyToAccount } from "viem/accounts";

const EXPECTED_MERCHANT = "0x80e0ae84679b7f11be171daadd492fbecf628cd6";
const BASE_USDC = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const MAX_PER_CALL_MICRO_USDC = 150_000n;

export const X402_UPGRADE_HINT =
  "Evaluated via free preview. Set X402_PRIVATE_KEY (or agent.x402PrivateKey) funded with Base USDC (0 ETH gas required) to unlock paid x402 buy/sell swap simulation & full SLA.";

export function resolvePrivateKey(agent: any, extraEnvKeys: string[]): `0x${string}` | undefined {
  const candidates: unknown[] = [
    agent?.x402PrivateKey,
    agent?.evmPrivateKey,
    agent?.privateKey,
  ];
  if (typeof process !== "undefined" && process.env) {
    for (const key of ["X402_PRIVATE_KEY", ...extraEnvKeys, "EVM_PRIVATE_KEY", "BASE_PRIVATE_KEY"]) {
      candidates.push(process.env[key]);
    }
  }
  for (const candidate of candidates) {
    if (typeof candidate !== "string") continue;
    const cleaned = candidate.trim().replace(/^0x/i, "");
    if (/^[a-fA-F0-9]{64}$/.test(cleaned)) {
      return `0x${cleaned}`;
    }
  }
  return undefined;
}

export function createGuardPayingFetch(privateKey: `0x${string}`, baseFetch: typeof fetch = fetch): typeof fetch {
  const account = privateKeyToAccount(privateKey);
  const client = new x402Client();
  client.register("eip155:8453", new ExactEvmScheme(account));
  client.onBeforePaymentCreation(async (context) => {
    const req = context.selectedRequirements;
    if (req.network !== "eip155:8453") {
      throw new Error(`Rejected x402 network ${req.network}: Base mainnet required`);
    }
    if (req.asset.toLowerCase() !== BASE_USDC) {
      throw new Error(`Rejected x402 asset ${req.asset}: Base USDC required`);
    }
    if (req.payTo.toLowerCase() !== EXPECTED_MERCHANT) {
      throw new Error(`Rejected x402 payTo ${req.payTo}: unauthorized recipient`);
    }
    if (BigInt(req.amount) > MAX_PER_CALL_MICRO_USDC) {
      throw new Error(`Rejected x402 amount ${req.amount}: exceeds cap`);
    }
  });
  return wrapFetchWithPayment(baseFetch, client);
}

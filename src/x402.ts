import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm/exact/client";
import { ExactSvmScheme } from "@x402/svm/exact/client";
import {
  createKeyPairSignerFromBytes,
  createKeyPairSignerFromPrivateKeyBytes,
} from "@solana/kit";
import bs58 from "bs58";
import { privateKeyToAccount } from "viem/accounts";

export const BASE_NETWORK = "eip155:8453" as const;
export const SOLANA_NETWORK = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" as const;

export const EXPECTED_BASE_MERCHANT = "0x80e0ae84679b7f11be171daadd492fbecf628cd6";
export const BASE_USDC_ASSET = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";

export const EXPECTED_SOLANA_MERCHANT = "9wuMysgXwNhtQeqJgGByAiMYc4EjzZ5wUSmnjrrt3ffh";
export const SOLANA_USDC_ASSET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

export const MAX_PER_CALL_MICRO_USDC = 150_000n; // $0.15 hard cap per guard call

export const X402_UPGRADE_HINT =
  "Set SOLANA_PRIVATE_KEY (Base58 or 64-byte JSON) for Solana USDC via PayAI, or X402_PRIVATE_KEY (0x...) for Base USDC, to auto-pay via @x402/fetch.";

export interface GuardPaymentOptions {
  evmPrivateKey?: `0x${string}`;
  solanaSecretKeyBytes?: Uint8Array;
  solanaRpcUrl?: string;
}

/**
 * Resolves an EVM (Base Mainnet) 32-byte hex private key from agent config or env.
 */
export function resolvePrivateKey(
  agent: any,
  extraEnvKeys: string[] = []
): `0x${string}` | undefined {
  const candidates: unknown[] = [
    agent?.x402PrivateKey,
    agent?.privateKey,
    ...(typeof process !== "undefined"
      ? [
          process.env?.X402_PRIVATE_KEY,
          ...extraEnvKeys.map((k) => process.env?.[k]),
          process.env?.EVM_PRIVATE_KEY,
          process.env?.BASE_PRIVATE_KEY,
        ]
      : []),
  ];

  for (const raw of candidates) {
    if (typeof raw !== "string") continue;
    const cleaned = raw.trim().replace(/^0x/i, "");
    if (/^[a-fA-F0-9]{64}$/.test(cleaned)) {
      return `0x${cleaned}`;
    }
  }
  return undefined;
}

/**
 * Parses a Solana private key (Base58 string, JSON byte array, or Uint8Array)
 * into a 32- or 64-byte Uint8Array suitable for @solana/kit signer creation.
 */
export function parseSolanaSecretKeyBytes(raw: unknown): Uint8Array | undefined {
  if (!raw) return undefined;

  if (raw instanceof Uint8Array) {
    return raw.length === 64 || raw.length === 32 ? raw : undefined;
  }

  if (Array.isArray(raw)) {
    const valid =
      (raw.length === 64 || raw.length === 32) &&
      raw.every((n) => typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= 255);
    return valid ? Uint8Array.from(raw) : undefined;
  }

  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.startsWith("0x") || /^[a-fA-F0-9]{64}$/.test(trimmed)) {
    return undefined;
  }

  if (trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      return parseSolanaSecretKeyBytes(parsed);
    } catch {
      return undefined;
    }
  }

  try {
    const decoded = bs58.decode(trimmed);
    return decoded.length === 64 || decoded.length === 32 ? decoded : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Resolves a Solana private key from SolanaAgentKit config/wallet or environment.
 */
export function resolveSolanaPrivateKeyBytes(
  agent: any,
  extraEnvKeys: string[] = []
): Uint8Array | undefined {
  const candidates: unknown[] = [
    agent?.solanaPrivateKey,
    agent?.wallet?.payer?.secretKey,
    agent?.private_key,
    ...(typeof process !== "undefined"
      ? [
          ...extraEnvKeys.map((k) => process.env?.[k]),
          process.env?.SOLANA_PRIVATE_KEY,
          process.env?.SVM_PRIVATE_KEY,
        ]
      : []),
  ];

  for (const candidate of candidates) {
    const parsed = parseSolanaSecretKeyBytes(candidate);
    if (parsed) return parsed;
  }
  return undefined;
}

export function resolveSolanaRpcUrl(agent?: any): string | undefined {
  const candidates: unknown[] = [
    agent?.solanaRpcUrl,
    agent?.rpc_url,
    ...(typeof process !== "undefined"
      ? [process.env?.SOLANA_RPC_URL, process.env?.RPC_URL]
      : []),
  ];
  for (const raw of candidates) {
    if (typeof raw === "string" && /^https?:\/\//i.test(raw.trim())) {
      return raw.trim();
    }
  }
  return undefined;
}

function attachGuardPolicies(client: x402Client): void {
  client.onBeforePaymentCreation(async (context) => {
    const req = context.selectedRequirements;
    if (req.network === BASE_NETWORK) {
      if (req.asset.toLowerCase() !== BASE_USDC_ASSET) {
        throw new Error(`Rejected non-USDC Base asset: ${req.asset}`);
      }
      if (req.payTo.toLowerCase() !== EXPECTED_BASE_MERCHANT) {
        throw new Error(`Rejected unauthorized merchant payTo: ${req.payTo}`);
      }
    } else if (req.network === SOLANA_NETWORK) {
      if (req.asset !== SOLANA_USDC_ASSET) {
        throw new Error(`Rejected non-USDC Solana asset: ${req.asset}`);
      }
      if (req.payTo !== EXPECTED_SOLANA_MERCHANT) {
        throw new Error(`Rejected unauthorized Solana merchant payTo: ${req.payTo}`);
      }
    } else {
      throw new Error(`Rejected unsupported x402 network: ${req.network}`);
    }

    if (BigInt(req.amount) > MAX_PER_CALL_MICRO_USDC) {
      throw new Error(`Rejected excessive x402 payment amount: ${req.amount}`);
    }
  });
}

/**
 * Synchronous EVM-only paying fetch helper retained for backward compatibility.
 */
export function createGuardPayingFetch(
  privateKey: `0x${string}`,
  baseFetch: typeof fetch = fetch
): typeof fetch {
  const account = privateKeyToAccount(privateKey);
  const client = new x402Client();
  client.register(BASE_NETWORK, new ExactEvmScheme(account));
  attachGuardPolicies(client);
  return wrapFetchWithPayment(baseFetch, client);
}

/**
 * Dual-chain paying fetch helper supporting Solana USDC (@x402/svm) and Base USDC (@x402/evm).
 */
export async function createGuardPayingFetchAsync(
  options: GuardPaymentOptions,
  baseFetch: typeof fetch = fetch
): Promise<typeof fetch> {
  if (!options.evmPrivateKey && !options.solanaSecretKeyBytes) {
    throw new Error("At least one of evmPrivateKey or solanaSecretKeyBytes must be provided.");
  }

  const client = new x402Client();

  if (options.evmPrivateKey) {
    const account = privateKeyToAccount(options.evmPrivateKey);
    client.register(BASE_NETWORK, new ExactEvmScheme(account));
  }

  if (options.solanaSecretKeyBytes) {
    const signer =
      options.solanaSecretKeyBytes.length === 64
        ? await createKeyPairSignerFromBytes(options.solanaSecretKeyBytes)
        : await createKeyPairSignerFromPrivateKeyBytes(options.solanaSecretKeyBytes);

    client.register(
      SOLANA_NETWORK,
      new ExactSvmScheme(
        signer,
        options.solanaRpcUrl ? { rpcUrl: options.solanaRpcUrl } : undefined
      )
    );
  }

  attachGuardPolicies(client);
  return wrapFetchWithPayment(baseFetch, client);
}

export interface GuardRequestContext {
  caller: typeof fetch;
  headers: Record<string, string>;
  paymentMode: "x402_paid" | "x402_header" | "free_preview";
  isPaid: boolean;
}

/**
 * Resolves dual-chain x402 paying fetch (Solana USDC + Base USDC), static payment header, or free preview.
 */
export async function resolveGuardRequestContext(
  agent: any,
  opts: {
    extraEvmEnvKeys: string[];
    extraSolanaEnvKeys: string[];
    agentHeaderProp: string;
    envHeaderKey: string;
  }
): Promise<GuardRequestContext> {
  const customFetch: typeof fetch = agent?.customFetch ?? fetch;
  const evmPrivateKey = resolvePrivateKey(agent, opts.extraEvmEnvKeys);
  const solanaSecretKeyBytes = resolveSolanaPrivateKeyBytes(agent, opts.extraSolanaEnvKeys);
  const solanaRpcUrl = resolveSolanaRpcUrl(agent);
  const paymentHeader =
    agent?.[opts.agentHeaderProp] ||
    (typeof process !== "undefined" ? process.env?.[opts.envHeaderKey] : undefined);

  const hasAutoPay = Boolean(evmPrivateKey || solanaSecretKeyBytes);
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  if (hasAutoPay) {
    const caller = await createGuardPayingFetchAsync(
      { evmPrivateKey, solanaSecretKeyBytes, solanaRpcUrl },
      customFetch
    );
    return { caller, headers, paymentMode: "x402_paid", isPaid: true };
  }

  if (paymentHeader) {
    headers["PAYMENT-SIGNATURE"] = paymentHeader;
    headers["X-PAYMENT"] = paymentHeader;
    return { caller: customFetch, headers, paymentMode: "x402_header", isPaid: true };
  }

  return { caller: customFetch, headers, paymentMode: "free_preview", isPaid: false };
}

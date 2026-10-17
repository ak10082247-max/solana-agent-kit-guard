/**
 * @kurox_real/solana-agent-kit-guard
 *
 * Official Guard Plugin & Actions for Solana Agent Kit (sendaifun/solana-agent-kit)
 * - RugShield: Real-time SPL honeypot & token safety auditor
 * - CanaryGuard: Deterministic prompt-injection firewall & wallet-drain scrubber
 */

import { rugshieldAuditAction } from "./actions/rugshieldAction.js";
import { canaryguardSanitizeAction } from "./actions/canaryguardAction.js";

export { rugshieldAuditAction, RugshieldAuditSchema } from "./actions/rugshieldAction.js";
export { canaryguardSanitizeAction, CanaryguardSanitizeSchema } from "./actions/canaryguardAction.js";

export const GUARD_ACTIONS = [
  rugshieldAuditAction,
  canaryguardSanitizeAction,
];

/**
 * Register Guard safety actions into a SolanaAgentKit instance or LangChain/ElizaOS toolset.
 */
export function createGuardPlugin() {
  return {
    name: "SolanaAgentKitGuard",
    description: "RugShield pre-swap honeypot auditor & CanaryGuard prompt-injection firewall for Solana agents",
    actions: GUARD_ACTIONS,
  };
}

export default createGuardPlugin;

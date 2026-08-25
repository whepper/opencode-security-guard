/**
 * OpenCode Security Guard
 *
 * Initial reference implementation.
 *
 * This file intentionally avoids claiming complete command parsing or DLP.
 * It is a defense-in-depth execution-time guard and must be tested against
 * the OpenCode plugin API version used by the deployment.
 */

const PROTECTED_TOKENS = [
  ".env",
  "terraform.tfstate",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "authorized_keys",
  ".npmrc",
  ".pypirc",
  ".netrc",
  ".git-credentials",
  "auth.json",
  "service-account",
  ".ssh/",
  ".aws/",
  ".azure/",
  ".gcp/",
  ".kube/",
  ".gnupg/",
  ".config/gcloud/",
  ".docker/config.json",
  ".config/secrets/"
];

const ENV_DUMP = /\b(env|printenv|export\s+-p|set)\b/i;

const READER_OR_SENDER = /\b(cat|head|tail|less|more|grep|awk|sed|python(?:3)?|node|ruby|perl|php|openssl|xxd|base64|curl|wget|nc|netcat)\b/i;

function normalize(value) {
  return String(value ?? "").replaceAll("\\", "/");
}

function containsProtectedToken(text) {
  const normalized = normalize(text).toLowerCase();
  return PROTECTED_TOKENS.some((token) => normalized.includes(token.toLowerCase()));
}

function shouldBlock(toolCall) {
  const serialized = JSON.stringify(toolCall ?? {});
  if (!serialized) return false;

  if (ENV_DUMP.test(serialized)) return true;

  return containsProtectedToken(serialized) && READER_OR_SENDER.test(serialized);
}

/**
 * The exact plugin export shape is intentionally kept as a small reference
 * until the supported OpenCode plugin API versions are pinned in CI.
 */
export default async function securityGuard(context) {
  return {
    "execute.before": async (input) => {
      if (shouldBlock(input)) {
        throw new Error(
          "OpenCode Security Guard blocked a tool execution involving a protected resource."
        );
      }
    }
  };
}

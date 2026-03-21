/**
 * OCCC Lockdown — gate utilities for CLI, config write, gateway, and skill install.
 *
 * The gate is INACTIVE unless OPENCLAW_LOCKDOWN_MODE=1 is set in the env.
 * This ensures backward compatibility for dev, tests, and non-OCCC deployments.
 *
 * Token format: <expiry-unix-ms>:<nonce>:<hmac-sha256-hex>
 * The HMAC is computed over "<expiry-unix-ms>:<nonce>" using OPENCLAW_OCCC_SECRET.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import { isTruthyEnvValue } from "../infra/env.js";

/**
 * Error thrown when a locked gate is violated.
 * Exit code 78 (EX_CONFIG) should be used when catching this at CLI entry.
 */
export class OcccLockdownError extends Error {
  readonly code = "OCCC_LOCKDOWN";

  constructor(message = "OCCC lockdown active: operation blocked") {
    super(message);
    this.name = "OcccLockdownError";
  }
}

/**
 * Returns true if lockdown mode is active (OPENCLAW_LOCKDOWN_MODE=1).
 * When lockdown is active, CLI/config/skill operations require a valid OCCC token.
 */
export function isLockdownActive(env: NodeJS.ProcessEnv = process.env): boolean {
  return isTruthyEnvValue(env.OPENCLAW_LOCKDOWN_MODE);
}

/**
 * Validates the OPENCLAW_OCCC_TOKEN value against the expected HMAC-SHA256 signature.
 *
 * Token format: `<expiry-unix-ms>:<nonce>:<hmac-sha256-hex>`
 * - expiry-unix-ms: Unix timestamp in milliseconds when the token expires
 * - nonce: Random hex string (at least 16 bytes / 32 hex chars)
 * - hmac-sha256-hex: HMAC-SHA256 of "<expiry-unix-ms>:<nonce>" using the secret
 *
 * @returns true if valid and not expired, false otherwise
 */
export function validateOcccToken(token: string | undefined, secret: string | undefined): boolean {
  // Guard: both token and secret must be present
  if (typeof token !== "string" || typeof secret !== "string") {
    return false;
  }
  if (!token.trim() || !secret.trim()) {
    return false;
  }

  // Parse token format: <expiry>:<nonce>:<hmac>
  const parts = token.split(":");
  if (parts.length !== 3) {
    return false;
  }

  const [expiryStr, nonce, providedHmac] = parts;
  if (!expiryStr || !nonce || !providedHmac) {
    return false;
  }

  // Validate expiry is a positive integer
  const expiry = Number.parseInt(expiryStr, 10);
  if (!Number.isFinite(expiry) || expiry <= 0) {
    return false;
  }

  // Check expiry
  if (Date.now() > expiry) {
    return false;
  }

  // Validate nonce length (must be at least 32 hex chars = 16 bytes)
  if (nonce.length < 32 || !/^[0-9a-f]+$/i.test(nonce)) {
    return false;
  }

  // Compute expected HMAC
  const payload = `${expiryStr}:${nonce}`;
  let expectedHmac: string;
  try {
    expectedHmac = createHmac("sha256", secret).update(payload).digest("hex");
  } catch {
    return false;
  }

  // Timing-safe comparison
  const providedBuffer = Buffer.from(providedHmac.toLowerCase());
  const expectedBuffer = Buffer.from(expectedHmac.toLowerCase());

  if (providedBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return timingSafeEqual(providedBuffer, expectedBuffer);
}

/**
 * If lockdown is active, validates the OCCC token.
 * Throws OcccLockdownError if validation fails.
 * No-ops if lockdown is not active.
 *
 * @throws {OcccLockdownError} If lockdown is active and token is missing/invalid
 */
export function assertNotLocked(env: NodeJS.ProcessEnv = process.env): void {
  if (!isLockdownActive(env)) {
    return;
  }

  const token = env.OPENCLAW_OCCC_TOKEN;
  const secret = env.OPENCLAW_OCCC_SECRET;

  if (!validateOcccToken(token, secret)) {
    throw new OcccLockdownError(
      "Direct access blocked: OpenClaw is running in OCCC lockdown mode. " +
        "Use the OpenClaw Command Center to manage this installation.",
    );
  }
}

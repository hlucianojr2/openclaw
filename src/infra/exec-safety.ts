const SHELL_METACHARS = /[;&|`$<>]/;
const CONTROL_CHARS = /[\r\n]/;
const QUOTE_CHARS = /["']/;
const BARE_NAME_PATTERN = /^[A-Za-z0-9._+-]+$/;

function isLikelyPath(value: string): boolean {
  if (value.startsWith(".") || value.startsWith("~")) {
    return true;
  }
  if (value.includes("/") || value.includes("\\")) {
    return true;
  }
  return /^[A-Za-z]:[\\/]/.test(value);
}

export function isSafeExecutableValue(value: string | null | undefined): boolean {
  if (!value) {
    return false;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return false;
  }
  if (trimmed.includes("\0")) {
    return false;
  }
  if (CONTROL_CHARS.test(trimmed)) {
    return false;
  }
  if (SHELL_METACHARS.test(trimmed)) {
    return false;
  }
  if (QUOTE_CHARS.test(trimmed)) {
    return false;
  }

  if (isLikelyPath(trimmed)) {
    return true;
  }
  if (trimmed.startsWith("-")) {
    return false;
  }
  return BARE_NAME_PATTERN.test(trimmed);
}

const MAX_PATH_LENGTH = 4096;

/**
 * Validates a filesystem path value for use in configuration.
 * Blocks shell metacharacters, null bytes, control characters, and quotes
 * that have no legitimate use in filesystem paths. More permissive than
 * isSafeExecutableValue — allows leading dashes and doesn't require
 * bare-name patterns since paths always contain separators.
 */
export function isSafePathValue(value: string | null | undefined): boolean {
  if (!value) {
    return false;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return false;
  }
  if (trimmed.length > MAX_PATH_LENGTH) {
    return false;
  }
  if (trimmed.includes("\0")) {
    return false;
  }
  if (CONTROL_CHARS.test(trimmed)) {
    return false;
  }
  if (SHELL_METACHARS.test(trimmed)) {
    return false;
  }
  if (QUOTE_CHARS.test(trimmed)) {
    return false;
  }
  return true;
}

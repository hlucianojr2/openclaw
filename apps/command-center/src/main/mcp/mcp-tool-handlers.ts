/**
 * MCP Tool Handlers — one handler function per tool.
 *
 * Each handler receives validated, policy-cleared args and returns a result.
 * Handlers MUST NOT log sensitive information (file contents, clipboard data, etc).
 *
 * All tool names and args are validated by the server before handlers are called.
 * Handlers should throw descriptive Error instances on failure — the server
 * maps these to appropriate HTTP responses.
 *
 * Security invariants:
 *   - filesystem handlers validate path is within workspace (enforced by policy engine)
 *   - browser handler only accepts http/https (enforced by policy engine)
 *   - no handler logs arg values that could contain sensitive data
 */

import { readFile, writeFile, readdir, mkdir, realpath } from "node:fs/promises";
import { join, isAbsolute } from "node:path";
import { clipboard } from "electron";
import { shell, Notification } from "electron";
import type { McpToolResult } from "./mcp-types.js";

// ─── Handler Registry ─────────────────────────────────────────────────────────

type ToolHandler = (args: Record<string, unknown>, workspacePath?: string) => Promise<McpToolResult>;

/** Dispatch table mapping tool name to its handler function. */
export const TOOL_HANDLERS: Readonly<Record<string, ToolHandler>> = {
  read_file: handleReadFile,
  write_file: handleWriteFile,
  list_dir: handleListDir,
  create_dir: handleCreateDir,
  read_clipboard: handleReadClipboard,
  write_clipboard: handleWriteClipboard,
  open_url: handleOpenUrl,
  get_system_info: handleGetSystemInfo,
  show_notification: handleShowNotification,
  open_app: handleOpenApp,
  focus_app: handleFocusApp,
} as const;

// ─── Filesystem Handlers ──────────────────────────────────────────────────────

async function handleReadFile(args: Record<string, unknown>): Promise<McpToolResult> {
  const filePath = validatePathArg(args["path"]);
  // Path-constraint check is already enforced by the policy engine before this runs.
  // This is a defense-in-depth check: ensure the path is absolute.
  if (!isAbsolute(filePath)) {
    throw new Error("read_file: path must be absolute");
  }
  const content = await readFile(filePath, "utf8");
  // Do NOT log content — may contain secrets
  return { data: { content } };
}

async function handleWriteFile(args: Record<string, unknown>): Promise<McpToolResult> {
  const filePath = validatePathArg(args["path"]);
  if (!isAbsolute(filePath)) {
    throw new Error("write_file: path must be absolute");
  }
  const content = args["content"];
  if (typeof content !== "string") {
    throw new Error("write_file: content must be a string");
  }
  await writeFile(filePath, content, "utf8");
  return { data: { written: true } };
}

async function handleListDir(args: Record<string, unknown>): Promise<McpToolResult> {
  const dirPath = validatePathArg(args["path"]);
  if (!isAbsolute(dirPath)) {
    throw new Error("list_dir: path must be absolute");
  }
  const entries = await readdir(dirPath, { withFileTypes: true });
  const items = entries.map((e) => ({
    name: e.name,
    type: e.isDirectory() ? "directory" : e.isFile() ? "file" : "other",
  }));
  return { data: { path: dirPath, entries: items } };
}

async function handleCreateDir(args: Record<string, unknown>): Promise<McpToolResult> {
  const dirPath = validatePathArg(args["path"]);
  if (!isAbsolute(dirPath)) {
    throw new Error("create_dir: path must be absolute");
  }
  await mkdir(dirPath, { recursive: true });
  return { data: { created: true } };
}

// ─── Clipboard Handlers ───────────────────────────────────────────────────────

async function handleReadClipboard(_args: Record<string, unknown>): Promise<McpToolResult> {
  const text = clipboard.readText();
  // Do NOT log clipboard content
  return { data: { text } };
}

async function handleWriteClipboard(args: Record<string, unknown>): Promise<McpToolResult> {
  const text = args["text"];
  if (typeof text !== "string") {
    throw new Error("write_clipboard: text must be a string");
  }
  clipboard.writeText(text);
  return { data: { written: true } };
}

// ─── Browser Handler ──────────────────────────────────────────────────────────

async function handleOpenUrl(args: Record<string, unknown>): Promise<McpToolResult> {
  const url = args["url"];
  if (typeof url !== "string" || !url) {
    throw new Error("open_url: url must be a non-empty string");
  }
  // Domain/scheme validation is enforced by the policy engine before this handler runs.
  // Defense-in-depth: reject clearly bad schemes here too.
  const lower = url.toLowerCase();
  if (lower.startsWith("file:") || lower.startsWith("javascript:") || lower.startsWith("data:")) {
    throw new Error("open_url: URL scheme is not permitted");
  }
  await shell.openExternal(url);
  return { data: { opened: true } };
}

// ─── System Info Handler ──────────────────────────────────────────────────────

async function handleGetSystemInfo(_args: Record<string, unknown>): Promise<McpToolResult> {
  const { platform, arch, version } = process;
  return {
    data: {
      platform,
      arch,
      nodeVersion: version,
      // No hostname, username, or other identifying information
    },
  };
}

// ─── Notification Handler ─────────────────────────────────────────────────────

async function handleShowNotification(args: Record<string, unknown>): Promise<McpToolResult> {
  const title = args["title"];
  const body = args["body"];
  if (typeof title !== "string" || !title) {
    throw new Error("show_notification: title must be a non-empty string");
  }
  const notification = new Notification({
    title: String(title).slice(0, 100),
    body: typeof body === "string" ? body.slice(0, 500) : "",
  });
  notification.show();
  return { data: { shown: true } };
}

// ─── App Control Handlers ─────────────────────────────────────────────────────

async function handleOpenApp(args: Record<string, unknown>): Promise<McpToolResult> {
  const appName = args["name"];
  if (typeof appName !== "string" || !appName) {
    throw new Error("open_app: name must be a non-empty string");
  }
  // shell.openPath opens apps by their file system path on all platforms.
  // We require the name to be treated as an app bundle path or executable name.
  const result = await shell.openPath(appName);
  if (result) {
    throw new Error(`open_app: failed to open "${appName}"`);
  }
  return { data: { opened: true } };
}

async function handleFocusApp(args: Record<string, unknown>): Promise<McpToolResult> {
  const appName = args["name"];
  if (typeof appName !== "string" || !appName) {
    throw new Error("focus_app: name must be a non-empty string");
  }
  // Focusing arbitrary apps requires platform-specific scripting (e.g. AppleScript on macOS).
  // For now, return a not-supported result rather than throwing — this is a best-effort handler.
  return { data: { focused: false, reason: "focus_app is not supported on this platform" } };
}

// ─── Validation Helpers ───────────────────────────────────────────────────────

/**
 * Validates a path argument from tool args.
 * Throws if missing, not a string, or contains null bytes.
 */
function validatePathArg(value: unknown): string {
  if (typeof value !== "string" || !value) {
    throw new Error("Tool requires a non-empty 'path' argument");
  }
  if (value.includes("\0")) {
    throw new Error("Path must not contain null bytes");
  }
  return value;
}

/**
 * Validates that a path is within a workspace directory using realpath resolution.
 * Used by the server as a secondary defense after the policy engine.
 */
export async function validatePathInWorkspace(
  filePath: string,
  workspacePath: string,
): Promise<boolean> {
  if (!workspacePath) { return false; }
  try {
    const [resolved, resolvedWs] = await Promise.all([
      realpath(filePath).catch(() => join(workspacePath, filePath)),
      realpath(workspacePath),
    ]);
    const normalizedWs = resolvedWs.endsWith("/") ? resolvedWs : resolvedWs + "/";
    return resolved === resolvedWs || resolved.startsWith(normalizedWs);
  } catch {
    return false;
  }
}

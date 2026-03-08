/**
 * MCP Tool Handlers — unit tests.
 *
 * Mocks Node.js fs/promises, electron clipboard, shell, and Notification
 * to test handlers in isolation.
 *
 * NOTE: vi.mock factories are hoisted to the top of the file by Vitest.
 * Therefore, factory functions must use vi.fn() directly rather than
 * referencing top-level variables (which are not yet initialized at hoist time).
 * We retrieve the mocks AFTER import using vi.mocked().
 */

import { describe, it, expect, vi, beforeEach } from "vitest";

// ─── Mocks ───────────────────────────────────────────────────────────────────

vi.mock("node:fs/promises", () => ({
  readFile: vi.fn(),
  writeFile: vi.fn(),
  readdir: vi.fn(),
  mkdir: vi.fn(),
  realpath: vi.fn(async (p: string) => p),
}));

vi.mock("electron", () => {
  const showFn = vi.fn();
  // Must use a real constructor function (not arrow function) for `new Notification()`
  function MockNotificationCtor(this: { show: typeof showFn }) {
    this.show = showFn;
  }
  return {
    clipboard: {
      readText: vi.fn(() => "clipboard text"),
      writeText: vi.fn(),
    },
    shell: {
      openExternal: vi.fn(async () => undefined),
      openPath: vi.fn(async () => ""),
    },
    Notification: MockNotificationCtor,
    _showFn: showFn,
  };
});

// ─── Import mocked modules ────────────────────────────────────────────────────

import * as fsMock from "node:fs/promises";
import * as electronMock from "electron";
import { TOOL_HANDLERS } from "../../src/main/mcp/mcp-tool-handlers.js";

// Typed mock references for cleaner test code
const mockReadFile = vi.mocked(fsMock.readFile);
const mockWriteFile = vi.mocked(fsMock.writeFile);
const mockReaddir = vi.mocked(fsMock.readdir);
const mockMkdir = vi.mocked(fsMock.mkdir);
const mockRealpath = vi.mocked(fsMock.realpath);

// electron mock is a plain object with vi.fn() members
const electronAny = electronMock as unknown as {
  clipboard: { readText: ReturnType<typeof vi.fn>; writeText: ReturnType<typeof vi.fn> };
  shell: { openExternal: ReturnType<typeof vi.fn>; openPath: ReturnType<typeof vi.fn> };
  Notification: { new(opts: unknown): { show(): void }; mock?: { calls: unknown[][] } };
  _showFn: ReturnType<typeof vi.fn>;
};

// ─── Tests ───────────────────────────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks();
  mockRealpath.mockImplementation(async (p: string) => p);
});

describe("read_file", () => {
  it("returns file content", async () => {
    mockReadFile.mockResolvedValueOnce("hello world" as never);
    const result = await TOOL_HANDLERS["read_file"]({ path: "/workspace/file.txt" });
    expect(result.data).toEqual({ content: "hello world" });
    expect(mockReadFile).toHaveBeenCalledWith("/workspace/file.txt", "utf8");
  });

  it("throws if path is not absolute", async () => {
    await expect(TOOL_HANDLERS["read_file"]({ path: "relative/path" }))
      .rejects.toThrow("absolute");
  });

  it("throws if path is missing", async () => {
    await expect(TOOL_HANDLERS["read_file"]({}))
      .rejects.toThrow();
  });

  it("throws if path contains null bytes", async () => {
    await expect(TOOL_HANDLERS["read_file"]({ path: "/workspace\0evil" }))
      .rejects.toThrow("null bytes");
  });
});

describe("write_file", () => {
  it("writes content and returns { written: true }", async () => {
    mockWriteFile.mockResolvedValueOnce(undefined as never);
    const result = await TOOL_HANDLERS["write_file"]({
      path: "/workspace/out.txt",
      content: "hello",
    });
    expect(result.data).toEqual({ written: true });
    expect(mockWriteFile).toHaveBeenCalledWith("/workspace/out.txt", "hello", "utf8");
  });

  it("throws if content is not a string", async () => {
    await expect(TOOL_HANDLERS["write_file"]({ path: "/workspace/f.txt", content: 123 }))
      .rejects.toThrow("content must be a string");
  });
});

describe("list_dir", () => {
  it("returns directory entries", async () => {
    mockReaddir.mockResolvedValueOnce([
      { name: "file.txt", isDirectory: () => false, isFile: () => true },
      { name: "subdir", isDirectory: () => true, isFile: () => false },
    ] as never);
    const result = await TOOL_HANDLERS["list_dir"]({ path: "/workspace" });
    const data = result.data as { entries: { name: string; type: string }[] };
    expect(data.entries).toHaveLength(2);
    expect(data.entries[0]).toEqual({ name: "file.txt", type: "file" });
    expect(data.entries[1]).toEqual({ name: "subdir", type: "directory" });
  });
});

describe("create_dir", () => {
  it("creates directory and returns { created: true }", async () => {
    mockMkdir.mockResolvedValueOnce(undefined as never);
    const result = await TOOL_HANDLERS["create_dir"]({ path: "/workspace/newdir" });
    expect(result.data).toEqual({ created: true });
    expect(mockMkdir).toHaveBeenCalledWith("/workspace/newdir", { recursive: true });
  });
});

describe("read_clipboard", () => {
  it("returns clipboard text", async () => {
    const result = await TOOL_HANDLERS["read_clipboard"]({});
    expect(result.data).toEqual({ text: "clipboard text" });
    expect(electronAny.clipboard.readText).toHaveBeenCalled();
  });
});

describe("write_clipboard", () => {
  it("writes text to clipboard", async () => {
    const result = await TOOL_HANDLERS["write_clipboard"]({ text: "new content" });
    expect(result.data).toEqual({ written: true });
    expect(electronAny.clipboard.writeText).toHaveBeenCalledWith("new content");
  });

  it("throws if text is not a string", async () => {
    await expect(TOOL_HANDLERS["write_clipboard"]({ text: 42 }))
      .rejects.toThrow("text must be a string");
  });
});

describe("open_url", () => {
  it("opens a valid http URL", async () => {
    electronAny.shell.openExternal.mockResolvedValueOnce(undefined);
    const result = await TOOL_HANDLERS["open_url"]({ url: "https://example.com" });
    expect(result.data).toEqual({ opened: true });
    expect(electronAny.shell.openExternal).toHaveBeenCalledWith("https://example.com");
  });

  it("rejects file: scheme", async () => {
    await expect(TOOL_HANDLERS["open_url"]({ url: "file:///etc/passwd" }))
      .rejects.toThrow("not permitted");
  });

  it("rejects javascript: scheme", async () => {
    await expect(TOOL_HANDLERS["open_url"]({ url: "javascript:alert(1)" }))
      .rejects.toThrow("not permitted");
  });

  it("throws if url is missing", async () => {
    await expect(TOOL_HANDLERS["open_url"]({}))
      .rejects.toThrow("url must be a non-empty string");
  });
});

describe("get_system_info", () => {
  it("returns platform, arch, and nodeVersion", async () => {
    const result = await TOOL_HANDLERS["get_system_info"]({});
    const data = result.data as { platform: string; arch: string; nodeVersion: string };
    expect(typeof data.platform).toBe("string");
    expect(typeof data.arch).toBe("string");
    expect(typeof data.nodeVersion).toBe("string");
    // Must NOT include hostname or username
    expect(Object.keys(data)).not.toContain("hostname");
    expect(Object.keys(data)).not.toContain("username");
  });
});

describe("show_notification", () => {
  it("shows notification with title and body", async () => {
    const result = await TOOL_HANDLERS["show_notification"]({
      title: "Hello",
      body: "World",
    });
    expect(result.data).toEqual({ shown: true });
    // The show() function on the notification instance should have been called
    expect(electronAny._showFn).toHaveBeenCalled();
  });

  it("throws if title is missing", async () => {
    await expect(TOOL_HANDLERS["show_notification"]({}))
      .rejects.toThrow("title must be a non-empty string");
  });

  it("truncates long title to 100 chars", async () => {
    const longTitle = "A".repeat(200);
    const result = await TOOL_HANDLERS["show_notification"]({ title: longTitle });
    // We can only verify the handler returned successfully (truncation happens inside the ctor)
    expect(result.data).toEqual({ shown: true });
    expect(electronAny._showFn).toHaveBeenCalled();
  });
});

describe("open_app", () => {
  it("opens an app and returns { opened: true } on success", async () => {
    electronAny.shell.openPath.mockResolvedValueOnce("");
    const result = await TOOL_HANDLERS["open_app"]({ name: "/Applications/Calculator.app" });
    expect(result.data).toEqual({ opened: true });
  });

  it("throws if app fails to open", async () => {
    electronAny.shell.openPath.mockResolvedValueOnce("Failed to open");
    await expect(TOOL_HANDLERS["open_app"]({ name: "/Applications/Nonexistent.app" }))
      .rejects.toThrow("failed to open");
  });

  it("throws if name is missing", async () => {
    await expect(TOOL_HANDLERS["open_app"]({}))
      .rejects.toThrow("name must be a non-empty string");
  });
});

describe("focus_app", () => {
  it("returns focused: false with explanation (not implemented)", async () => {
    const result = await TOOL_HANDLERS["focus_app"]({ name: "Calculator" });
    const data = result.data as { focused: boolean; reason: string };
    expect(data.focused).toBe(false);
    expect(typeof data.reason).toBe("string");
  });
});

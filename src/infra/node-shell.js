export function buildNodeShellCommand(command, platform) {
  const normalized = String(platform ?? "")
    .trim()
    .toLowerCase();
  if (normalized.startsWith("win")) {
    return ["cmd.exe", "/d", "/s", "/c", command];
  }
  return ["/bin/sh", "-lc", command];
}
//# sourceMappingURL=node-shell.js.map

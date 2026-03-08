import { createNonExitingRuntime } from "../../runtime.js";
export function resolveRuntime(opts) {
  return opts.runtime ?? createNonExitingRuntime();
}
export function normalizeAllowList(list) {
  return (list ?? []).map((entry) => String(entry).trim()).filter(Boolean);
}
//# sourceMappingURL=runtime.js.map

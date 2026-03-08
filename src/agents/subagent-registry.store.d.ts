import type { SubagentRunRecord } from "./subagent-registry.js";
export type PersistedSubagentRegistryVersion = 1 | 2;
export declare function resolveSubagentRegistryPath(): string;
export declare function loadSubagentRegistryFromDisk(): Map<string, SubagentRunRecord>;
export declare function saveSubagentRegistryToDisk(runs: Map<string, SubagentRunRecord>): void;
//# sourceMappingURL=subagent-registry.store.d.ts.map
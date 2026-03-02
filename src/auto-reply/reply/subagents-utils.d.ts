import type { SubagentRunRecord } from "../../agents/subagent-registry.js";
export declare function resolveSubagentLabel(entry: SubagentRunRecord, fallback?: string): string;
export declare function formatRunLabel(entry: SubagentRunRecord, options?: {
    maxLength?: number;
}): string;
export declare function formatRunStatus(entry: SubagentRunRecord): "done" | "error" | "running" | "timeout" | "unknown";
export declare function sortSubagentRuns(runs: SubagentRunRecord[]): SubagentRunRecord[];
//# sourceMappingURL=subagents-utils.d.ts.map
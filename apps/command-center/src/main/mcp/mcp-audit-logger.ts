/**
 * MCP Audit Logger — append-only audit log for tool call outcomes.
 *
 * Persists to a JSON file in userData/mcp/audit.json.
 * Provides query methods for the UI and daily count aggregation.
 *
 * The log is bounded to MAX_AUDIT_ENTRIES (1000) entries.
 * Older entries are evicted when the cap is reached.
 *
 * Security: tool args and result data are NEVER stored in the audit log.
 * Only the outcome, category, agentId, toolName, and timestamp are recorded.
 */

import { app } from "electron";
import path from "node:path";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import type { McpAuditEntry, McpOutcome, McpToolCategory } from "./mcp-types.js";

/** Maximum number of audit entries retained on disk. */
const MAX_AUDIT_ENTRIES = 1000;

interface AuditStoreData {
  version: 1;
  entries: McpAuditEntry[];
}

/**
 * Append-only audit logger for MCP tool calls.
 *
 * @example
 * const logger = new McpAuditLogger();
 * logger.append({ toolName: "read_file", category: "filesystem", agentId: "agent-1", outcome: "approved" });
 * const entries = logger.query({ limit: 50 });
 */
export class McpAuditLogger {
  private filePath: string;
  private data: AuditStoreData;

  constructor(dataDir?: string) {
    const dir = dataDir ?? path.join(app.getPath("userData"), "mcp");
    mkdirSync(dir, { recursive: true });
    this.filePath = path.join(dir, "audit.json");
    this.data = this.load();
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /**
   * Append a new audit entry.
   * Evicts oldest entries if the cap (MAX_AUDIT_ENTRIES) is exceeded.
   */
  append(entry: Omit<McpAuditEntry, "id" | "timestamp">): McpAuditEntry {
    const newEntry: McpAuditEntry = {
      id: randomBytes(8).toString("hex"),
      timestamp: new Date().toISOString(),
      ...entry,
    };

    this.data.entries.push(newEntry);

    // Trim to cap
    if (this.data.entries.length > MAX_AUDIT_ENTRIES) {
      this.data.entries = this.data.entries.slice(
        this.data.entries.length - MAX_AUDIT_ENTRIES,
      );
    }

    this.persist();
    return newEntry;
  }

  /**
   * Query audit entries (most recent first).
   *
   * @param options.limit - Max number of entries to return (default: 100)
   * @param options.agentId - Filter by agent ID
   * @param options.outcome - Filter by outcome
   */
  query(options: {
    limit?: number;
    agentId?: string;
    outcome?: McpOutcome;
    category?: McpToolCategory;
  } = {}): McpAuditEntry[] {
    const { limit = 100, agentId, outcome, category } = options;

    let results = this.data.entries.toReversed();

    if (agentId !== undefined) {
      results = results.filter((e) => e.agentId === agentId);
    }
    if (outcome !== undefined) {
      results = results.filter((e) => e.outcome === outcome);
    }
    if (category !== undefined) {
      results = results.filter((e) => e.category === category);
    }

    return results.slice(0, limit);
  }

  /**
   * Count entries for today (calendar day, local time) grouped by outcome.
   */
  countToday(): { approved: number; denied: number; blocked: number; expired: number; error: number } {
    const todayPrefix = new Date().toISOString().slice(0, 10); // "YYYY-MM-DD"

    const counts = { approved: 0, denied: 0, blocked: 0, expired: 0, error: 0 };
    for (const entry of this.data.entries) {
      if (entry.timestamp.startsWith(todayPrefix)) {
        counts[entry.outcome]++;
      }
    }
    return counts;
  }

  /** Total number of entries in the log. */
  count(): number {
    return this.data.entries.length;
  }

  // ─── Private ──────────────────────────────────────────────────────────────

  private load(): AuditStoreData {
    if (existsSync(this.filePath)) {
      try {
        const raw = readFileSync(this.filePath, "utf8");
        const parsed = JSON.parse(raw) as unknown;
        if (isValidAuditData(parsed)) {
          return parsed;
        }
      } catch {
        // Corrupted — start fresh
      }
    }
    return { version: 1, entries: [] };
  }

  private persist(): void {
    writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), {
      mode: 0o600,
      encoding: "utf8",
    });
  }
}

// ─── Type Guard ───────────────────────────────────────────────────────────────

function isValidAuditData(value: unknown): value is AuditStoreData {
  if (typeof value !== "object" || value === null) { return false; }
  const v = value as Record<string, unknown>;
  return v["version"] === 1 && Array.isArray(v["entries"]);
}

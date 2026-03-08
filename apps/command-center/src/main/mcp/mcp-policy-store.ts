/**
 * MCP Policy Store — persistent storage for per-category tool policies.
 *
 * Uses electron-store for JSON persistence in the app's userData directory.
 * Initialized with sensible defaults on first run.
 *
 * Thread-safety: all operations are synchronous (electron-store is sync).
 * The store is safe to call from the main process only.
 */

import { app } from "electron";
import path from "node:path";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import type { McpPolicy, McpToolCategory, McpApprovalLevel } from "./mcp-types.js";
import { DEFAULT_POLICY_LEVELS } from "./mcp-types.js";

const ALL_CATEGORIES: McpToolCategory[] = [
  "filesystem",
  "clipboard",
  "browser",
  "system-info",
  "notifications",
  "app-control",
];

/** Shape of the JSON file written to disk. */
interface PolicyStoreData {
  version: 1;
  policies: Record<McpToolCategory, McpPolicy>;
}

/**
 * Persistent policy store for MCP tool categories.
 *
 * @example
 * const store = new McpPolicyStore();
 * const policy = store.getPolicy("filesystem");
 * store.setPolicy("filesystem", { ...policy, level: "per-use" });
 */
export class McpPolicyStore {
  private filePath: string;
  private data: PolicyStoreData;

  constructor(dataDir?: string) {
    const dir = dataDir ?? path.join(app.getPath("userData"), "mcp");
    mkdirSync(dir, { recursive: true });
    this.filePath = path.join(dir, "policies.json");
    this.data = this.load();
  }

  // ─── Public API ───────────────────────────────────────────────────────────

  /** Get the current policy for a tool category. */
  getPolicy(category: McpToolCategory): McpPolicy {
    return this.data.policies[category];
  }

  /** Get all policies as an array. */
  getAllPolicies(): McpPolicy[] {
    return ALL_CATEGORIES.map((c) => this.data.policies[c]);
  }

  /**
   * Update a policy for a category.
   * Persists immediately to disk.
   */
  setPolicy(
    category: McpToolCategory,
    updates: Partial<Pick<McpPolicy, "level" | "allowedDomains" | "workspacePath">>,
  ): McpPolicy {
    const existing = this.data.policies[category];
    const updated: McpPolicy = {
      ...existing,
      ...updates,
      category,
      updatedAt: new Date().toISOString(),
    };
    this.data.policies[category] = updated;
    this.persist();
    return updated;
  }

  /**
   * Add a domain to the browser category allowlist.
   * No-op if the domain is already present.
   */
  addAllowedDomain(domain: string): void {
    const policy = this.data.policies["browser"];
    if (!policy.allowedDomains.includes(domain)) {
      policy.allowedDomains = [...policy.allowedDomains, domain].toSorted();
      policy.updatedAt = new Date().toISOString();
      this.persist();
    }
  }

  /**
   * Remove a domain from the browser category allowlist.
   */
  removeAllowedDomain(domain: string): void {
    const policy = this.data.policies["browser"];
    policy.allowedDomains = policy.allowedDomains.filter((d) => d !== domain);
    policy.updatedAt = new Date().toISOString();
    this.persist();
  }

  // ─── Private ──────────────────────────────────────────────────────────────

  private load(): PolicyStoreData {
    if (existsSync(this.filePath)) {
      try {
        const raw = readFileSync(this.filePath, "utf8");
        const parsed = JSON.parse(raw) as unknown;
        if (isValidStoreData(parsed)) {
          // Backfill any missing categories (handles upgrades gracefully)
          for (const category of ALL_CATEGORIES) {
            if (!parsed.policies[category]) {
              parsed.policies[category] = defaultPolicy(category);
            }
          }
          return parsed;
        }
      } catch {
        // Corrupted file — reset to defaults
      }
    }
    return this.buildDefaults();
  }

  private persist(): void {
    writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), {
      mode: 0o600,
      encoding: "utf8",
    });
  }

  private buildDefaults(): PolicyStoreData {
    const policies = {} as Record<McpToolCategory, McpPolicy>;
    for (const category of ALL_CATEGORIES) {
      policies[category] = defaultPolicy(category);
    }
    const data: PolicyStoreData = { version: 1, policies };
    // Persist immediately so the file exists on first run
    try {
      writeFileSync(this.filePath, JSON.stringify(data, null, 2), {
        mode: 0o600,
        encoding: "utf8",
      });
    } catch {
      // Ignore write errors during initialization (test environments)
    }
    return data;
  }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function defaultPolicy(category: McpToolCategory): McpPolicy {
  const level: McpApprovalLevel = DEFAULT_POLICY_LEVELS[category];
  return {
    category,
    level,
    allowedDomains: [],
    workspacePath: "",
    updatedAt: new Date().toISOString(),
  };
}

function isValidStoreData(value: unknown): value is PolicyStoreData {
  if (typeof value !== "object" || value === null) { return false; }
  const v = value as Record<string, unknown>;
  if (v["version"] !== 1) { return false; }
  if (typeof v["policies"] !== "object" || v["policies"] === null) { return false; }
  return true;
}

/**
 * Skill Allowlist — persists approved skills to JSON on disk.
 *
 * File: {userData}/openclaw-allowlist.json (mode 0o600)
 * Loaded synchronously on construction; mutations persisted asynchronously.
 */

import { app } from "electron";
import path from "node:path";
import { readFileSync, existsSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import type { AllowlistEntry } from "../../shared/ipc-types.js";

const FILE_NAME = "openclaw-allowlist.json";

interface AllowlistFile {
  entries: AllowlistEntry[];
}

export class SkillAllowlist {
  private readonly filePath: string;
  private entries: Map<string, AllowlistEntry>;

  constructor(dataDir?: string) {
    const dir = dataDir ?? app.getPath("userData");
    this.filePath = path.join(dir, FILE_NAME);
    this.entries = new Map();
    this.load();
  }

  has(skillId: string): boolean {
    return this.entries.has(skillId);
  }

  list(): AllowlistEntry[] {
    return [...this.entries.values()];
  }

  async add(entry: AllowlistEntry): Promise<void> {
    this.entries.set(entry.skillId, entry);
    await this.persist();
  }

  async remove(skillId: string): Promise<boolean> {
    const had = this.entries.delete(skillId);
    if (had) { await this.persist(); }
    return had;
  }

  private load(): void {
    if (!existsSync(this.filePath)) { return; }
    try {
      const raw = readFileSync(this.filePath, "utf8");
      const data = JSON.parse(raw) as AllowlistFile;
      for (const entry of data.entries ?? []) {
        this.entries.set(entry.skillId, entry);
      }
    } catch {
      // Corrupt file — start fresh
    }
  }

  private async persist(): Promise<void> {
    const data: AllowlistFile = { entries: [...this.entries.values()] };
    await writeFile(this.filePath, JSON.stringify(data, null, 2), { encoding: "utf8", mode: 0o600 });
  }
}

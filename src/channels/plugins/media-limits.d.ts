import type { OpenClawConfig } from "../../config/config.js";
export declare function resolveChannelMediaMaxBytes(params: {
    cfg: OpenClawConfig;
    resolveChannelLimitMb: (params: {
        cfg: OpenClawConfig;
        accountId: string;
    }) => number | undefined;
    accountId?: string | null;
}): number | undefined;
//# sourceMappingURL=media-limits.d.ts.map
import type { NormalizedUsage } from "../../agents/usage.js";
import type { ChannelThreadingToolContext } from "../../channels/plugins/types.js";
import type { OpenClawConfig } from "../../config/config.js";
import type { TemplateContext } from "../templating.js";
import type { ReplyPayload } from "../types.js";
/**
 * Build provider-specific threading context for tool auto-injection.
 */
export declare function buildThreadingToolContext(params: {
    sessionCtx: TemplateContext;
    config: OpenClawConfig | undefined;
    hasRepliedRef: {
        value: boolean;
    } | undefined;
}): ChannelThreadingToolContext;
export declare const isBunFetchSocketError: (message?: string  ) => boolean;
export declare const formatBunFetchSocketError: (message: string) => string;
export declare const formatResponseUsageLine: (params: {
    usage?: NormalizedUsage | undefined;
    showCost: boolean;
    costConfig?: {
        input: number;
        output: number;
        cacheRead: number;
        cacheWrite: number;
    } | undefined;
}) => string | null;
export declare const appendUsageLine: (payloads: ReplyPayload[], line: string) => ReplyPayload[];
export declare const resolveEnforceFinalTag: (run: {
    agentId: string;
    agentDir: string;
    sessionId: string;
    sessionKey?: string | undefined;
    messageProvider?: string | undefined;
    agentAccountId?: string | undefined;
    groupId?: string | undefined;
    groupChannel?: string | undefined;
    groupSpace?: string | undefined;
    senderId?: string | undefined;
    senderName?: string | undefined;
    senderUsername?: string | undefined;
    senderE164?: string | undefined;
    sessionFile: string;
    workspaceDir: string;
    config: OpenClawConfig;
    skillsSnapshot?: import("../../agents/skills.js").SkillSnapshot | undefined;
    provider: string;
    model: string;
    authProfileId?: string | undefined;
    authProfileIdSource?: "auto" | "user" | undefined;
    thinkLevel?: import("./directives.js").ThinkLevel | undefined;
    verboseLevel?: import("./directives.js").VerboseLevel | undefined;
    reasoningLevel?: import("./directives.js").ReasoningLevel | undefined;
    elevatedLevel?: import("./directives.js").ElevatedLevel | undefined;
    execOverrides?: Pick<import("../../agents/bash-tools.exec.js").ExecToolDefaults, "ask" | "host" | "node" | "security"> | undefined;
    bashElevated?: {
        enabled: boolean;
        allowed: boolean;
        defaultLevel: import("./directives.js").ElevatedLevel;
    } | undefined;
    timeoutMs: number;
    blockReplyBreak: "message_end" | "text_end";
    ownerNumbers?: string[] | undefined;
    extraSystemPrompt?: string | undefined;
    enforceFinalTag?: boolean | undefined;
}, provider: string) => boolean;
//# sourceMappingURL=agent-runner-utils.d.ts.map
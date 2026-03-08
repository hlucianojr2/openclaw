import { type ErrorObject } from "ajv";
import type { SessionsPatchResult } from "../session-utils.types.js";
import { type AgentEvent, AgentEventSchema, type AgentIdentityParams, AgentIdentityParamsSchema, type AgentIdentityResult, AgentIdentityResultSchema, AgentParamsSchema, type AgentSummary, AgentSummarySchema, type AgentsFileEntry, AgentsFileEntrySchema, type AgentsCreateParams, AgentsCreateParamsSchema, type AgentsCreateResult, AgentsCreateResultSchema, type AgentsUpdateParams, AgentsUpdateParamsSchema, type AgentsUpdateResult, AgentsUpdateResultSchema, type AgentsDeleteParams, AgentsDeleteParamsSchema, type AgentsDeleteResult, AgentsDeleteResultSchema, type AgentsFilesGetParams, AgentsFilesGetParamsSchema, type AgentsFilesGetResult, AgentsFilesGetResultSchema, type AgentsFilesListParams, AgentsFilesListParamsSchema, type AgentsFilesListResult, AgentsFilesListResultSchema, type AgentsFilesSetParams, AgentsFilesSetParamsSchema, type AgentsFilesSetResult, AgentsFilesSetResultSchema, type AgentsListParams, AgentsListParamsSchema, type AgentsListResult, AgentsListResultSchema, type AgentWaitParams, type ChannelsLogoutParams, ChannelsLogoutParamsSchema, type TalkConfigParams, TalkConfigParamsSchema, type TalkConfigResult, TalkConfigResultSchema, type ChannelsStatusParams, ChannelsStatusParamsSchema, type ChannelsStatusResult, ChannelsStatusResultSchema, type ChatEvent, ChatEventSchema, ChatHistoryParamsSchema, type ChatInjectParams, ChatInjectParamsSchema, ChatSendParamsSchema, type ConfigApplyParams, ConfigApplyParamsSchema, type ConfigGetParams, ConfigGetParamsSchema, type ConfigPatchParams, ConfigPatchParamsSchema, type ConfigSchemaParams, ConfigSchemaParamsSchema, type ConfigSchemaResponse, ConfigSchemaResponseSchema, type ConfigSetParams, ConfigSetParamsSchema, type ConnectParams, ConnectParamsSchema, type CronAddParams, CronAddParamsSchema, type CronJob, CronJobSchema, type CronListParams, CronListParamsSchema, type CronRemoveParams, CronRemoveParamsSchema, type CronRunLogEntry, type CronRunParams, CronRunParamsSchema, type CronRunsParams, CronRunsParamsSchema, type CronStatusParams, CronStatusParamsSchema, type CronUpdateParams, CronUpdateParamsSchema, type DevicePairApproveParams, type DevicePairListParams, type DevicePairRejectParams, type ExecApprovalsGetParams, type ExecApprovalsSetParams, type ExecApprovalsSnapshot, ErrorCodes, type ErrorShape, ErrorShapeSchema, type EventFrame, EventFrameSchema, errorShape, type GatewayFrame, GatewayFrameSchema, type HelloOk, HelloOkSchema, type LogsTailParams, LogsTailParamsSchema, type LogsTailResult, LogsTailResultSchema, ModelsListParamsSchema, type NodeEventParams, type NodeInvokeParams, NodeInvokeParamsSchema, type NodeInvokeResultParams, type NodeListParams, NodeListParamsSchema, type NodePairApproveParams, NodePairApproveParamsSchema, type NodePairListParams, NodePairListParamsSchema, type NodePairRejectParams, NodePairRejectParamsSchema, type NodePairRequestParams, NodePairRequestParamsSchema, type NodePairVerifyParams, NodePairVerifyParamsSchema, type PollParams, PollParamsSchema, PROTOCOL_VERSION, type PresenceEntry, PresenceEntrySchema, ProtocolSchemas, type RequestFrame, RequestFrameSchema, type ResponseFrame, ResponseFrameSchema, SendParamsSchema, type SessionsCompactParams, SessionsCompactParamsSchema, type SessionsDeleteParams, SessionsDeleteParamsSchema, type SessionsListParams, SessionsListParamsSchema, type SessionsPatchParams, SessionsPatchParamsSchema, type SessionsPreviewParams, SessionsPreviewParamsSchema, type SessionsResetParams, SessionsResetParamsSchema, type SessionsResolveParams, type SessionsUsageParams, SessionsUsageParamsSchema, type ShutdownEvent, ShutdownEventSchema, type SkillsBinsParams, type SkillsBinsResult, type SkillsInstallParams, SkillsInstallParamsSchema, type SkillsStatusParams, SkillsStatusParamsSchema, type SkillsUpdateParams, SkillsUpdateParamsSchema, type Snapshot, SnapshotSchema, type StateVersion, StateVersionSchema, type TalkModeParams, type TickEvent, TickEventSchema, type UpdateRunParams, UpdateRunParamsSchema, type WakeParams, WakeParamsSchema, type WebLoginStartParams, WebLoginStartParamsSchema, type WebLoginWaitParams, WebLoginWaitParamsSchema, type WizardCancelParams, WizardCancelParamsSchema, type WizardNextParams, WizardNextParamsSchema, type WizardNextResult, WizardNextResultSchema, type WizardStartParams, WizardStartParamsSchema, type WizardStartResult, WizardStartResultSchema, type WizardStatusParams, WizardStatusParamsSchema, type WizardStatusResult, WizardStatusResultSchema, type WizardStep, WizardStepSchema } from "./schema.js";
export declare const validateConnectParams: import("ajv").ValidateFunction<{
    minProtocol: number;
    maxProtocol: number;
    client: {
        id: "cli" | "fingerprint" | "gateway-client" | "node-host" | "openclaw-android" | "openclaw-control-ui" | "openclaw-ios" | "openclaw-macos" | "openclaw-probe" | "test" | "webchat" | "webchat-ui";
        displayName?: string | undefined;
        version: string;
        platform: string;
        deviceFamily?: string | undefined;
        modelIdentifier?: string | undefined;
        mode: "backend" | "cli" | "node" | "probe" | "test" | "ui" | "webchat";
        instanceId?: string | undefined;
    };
    caps?: string[] | undefined;
    commands?: string[] | undefined;
    permissions?: {
        [x: string]: boolean;
    } | undefined;
    pathEnv?: string | undefined;
    role?: string | undefined;
    scopes?: string[] | undefined;
    device?: {
        id: string;
        publicKey: string;
        signature: string;
        signedAt: number;
        nonce?: string | undefined;
    } | undefined;
    auth?: {
        token?: string | undefined;
        password?: string | undefined;
    } | undefined;
    locale?: string | undefined;
    userAgent?: string | undefined;
}>;
export declare const validateRequestFrame: import("ajv").ValidateFunction<{
    type: "req";
    id: string;
    method: string;
    params?: unknown;
}>;
export declare const validateResponseFrame: import("ajv").ValidateFunction<{
    type: "res";
    id: string;
    ok: boolean;
    payload?: unknown;
    error?: {
        code: string;
        message: string;
        details?: unknown;
        retryable?: boolean | undefined;
        retryAfterMs?: number | undefined;
    } | undefined;
}>;
export declare const validateEventFrame: import("ajv").ValidateFunction<{
    type: "event";
    event: string;
    payload?: unknown;
    seq?: number | undefined;
    stateVersion?: {
        presence: number;
        health: number;
    } | undefined;
}>;
export declare const validateSendParams: import("ajv").ValidateFunction<{
    idempotencyKey: any;
    to: any;
} & {
    idempotencyKey: any;
} & {
    to: any;
}>;
export declare const validatePollParams: import("ajv").ValidateFunction<{
    to: string;
    question: string;
    options: string[];
    maxSelections?: number | undefined;
    durationSeconds?: number | undefined;
    durationHours?: number | undefined;
    silent?: boolean | undefined;
    isAnonymous?: boolean | undefined;
    threadId?: string | undefined;
    channel?: string | undefined;
    accountId?: string | undefined;
    idempotencyKey: string;
}>;
export declare const validateAgentParams: import("ajv").ValidateFunction<{
    idempotencyKey: any;
    message: any;
} & {
    idempotencyKey: any;
} & {
    message: any;
}>;
export declare const validateAgentIdentityParams: import("ajv").ValidateFunction<{
    agentId?: string | undefined;
    sessionKey?: string | undefined;
}>;
export declare const validateAgentWaitParams: import("ajv").ValidateFunction<{
    runId: string;
    timeoutMs?: number | undefined;
}>;
export declare const validateWakeParams: import("ajv").ValidateFunction<{
    mode: "next-heartbeat" | "now";
    text: string;
}>;
export declare const validateAgentsListParams: import("ajv").ValidateFunction<{}>;
export declare const validateAgentsCreateParams: import("ajv").ValidateFunction<{
    name: string;
    workspace: string;
    emoji?: string | undefined;
    avatar?: string | undefined;
}>;
export declare const validateAgentsUpdateParams: import("ajv").ValidateFunction<{
    agentId: string;
    name?: string | undefined;
    workspace?: string | undefined;
    model?: string | undefined;
    avatar?: string | undefined;
}>;
export declare const validateAgentsDeleteParams: import("ajv").ValidateFunction<{
    agentId: string;
    deleteFiles?: boolean | undefined;
}>;
export declare const validateAgentsFilesListParams: import("ajv").ValidateFunction<{
    agentId: string;
}>;
export declare const validateAgentsFilesGetParams: import("ajv").ValidateFunction<{
    agentId: string;
    name: string;
}>;
export declare const validateAgentsFilesSetParams: import("ajv").ValidateFunction<{
    agentId: string;
    name: string;
    content: string;
}>;
export declare const validateNodePairRequestParams: import("ajv").ValidateFunction<{
    nodeId: string;
    displayName?: string | undefined;
    platform?: string | undefined;
    version?: string | undefined;
    coreVersion?: string | undefined;
    uiVersion?: string | undefined;
    deviceFamily?: string | undefined;
    modelIdentifier?: string | undefined;
    caps?: string[] | undefined;
    commands?: string[] | undefined;
    remoteIp?: string | undefined;
    silent?: boolean | undefined;
}>;
export declare const validateNodePairListParams: import("ajv").ValidateFunction<{}>;
export declare const validateNodePairApproveParams: import("ajv").ValidateFunction<{
    requestId: string;
}>;
export declare const validateNodePairRejectParams: import("ajv").ValidateFunction<{
    requestId: string;
}>;
export declare const validateNodePairVerifyParams: import("ajv").ValidateFunction<{
    nodeId: string;
    token: string;
}>;
export declare const validateNodeRenameParams: import("ajv").ValidateFunction<{
    nodeId: string;
    displayName: string;
}>;
export declare const validateNodeListParams: import("ajv").ValidateFunction<{}>;
export declare const validateNodeDescribeParams: import("ajv").ValidateFunction<{
    nodeId: string;
}>;
export declare const validateNodeInvokeParams: import("ajv").ValidateFunction<{
    nodeId: string;
    command: string;
    params?: unknown;
    timeoutMs?: number | undefined;
    idempotencyKey: string;
}>;
export declare const validateNodeInvokeResultParams: import("ajv").ValidateFunction<{
    id: string;
    nodeId: string;
    ok: boolean;
    payload?: unknown;
    payloadJSON?: string | undefined;
    error?: {
        code?: string | undefined;
        message?: string | undefined;
    } | undefined;
}>;
export declare const validateNodeEventParams: import("ajv").ValidateFunction<{
    event: string;
    payload?: unknown;
    payloadJSON?: string | undefined;
}>;
export declare const validateSessionsListParams: import("ajv").ValidateFunction<{
    limit?: number | undefined;
    activeMinutes?: number | undefined;
    includeGlobal?: boolean | undefined;
    includeUnknown?: boolean | undefined;
    includeDerivedTitles?: boolean | undefined;
    includeLastMessage?: boolean | undefined;
    label?: string | undefined;
    spawnedBy?: string | undefined;
    agentId?: string | undefined;
    search?: string | undefined;
}>;
export declare const validateSessionsPreviewParams: import("ajv").ValidateFunction<{
    keys: string[];
    limit?: number | undefined;
    maxChars?: number | undefined;
}>;
export declare const validateSessionsResolveParams: import("ajv").ValidateFunction<{
    key?: string | undefined;
    sessionId?: string | undefined;
    label?: string | undefined;
    agentId?: string | undefined;
    spawnedBy?: string | undefined;
    includeGlobal?: boolean | undefined;
    includeUnknown?: boolean | undefined;
}>;
export declare const validateSessionsPatchParams: import("ajv").ValidateFunction<{
    key: string;
    label?: string | null | undefined;
    thinkingLevel?: string | null | undefined;
    verboseLevel?: string | null | undefined;
    reasoningLevel?: string | null | undefined;
    responseUsage?: "full" | "off" | "on" | "tokens" | null | undefined;
    elevatedLevel?: string | null | undefined;
    execHost?: string | null | undefined;
    execSecurity?: string | null | undefined;
    execAsk?: string | null | undefined;
    execNode?: string | null | undefined;
    model?: string | null | undefined;
    spawnedBy?: string | null | undefined;
    spawnDepth?: number | null | undefined;
    sendPolicy?: "allow" | "deny" | null | undefined;
    groupActivation?: "always" | "mention" | null | undefined;
}>;
export declare const validateSessionsResetParams: import("ajv").ValidateFunction<{
    key: string;
    reason?: "new" | "reset" | undefined;
}>;
export declare const validateSessionsDeleteParams: import("ajv").ValidateFunction<{
    key: string;
    deleteTranscript?: boolean | undefined;
}>;
export declare const validateSessionsCompactParams: import("ajv").ValidateFunction<{
    key: string;
    maxLines?: number | undefined;
}>;
export declare const validateSessionsUsageParams: import("ajv").ValidateFunction<{
    key?: string | undefined;
    startDate?: string | undefined;
    endDate?: string | undefined;
    limit?: number | undefined;
    includeContextWeight?: boolean | undefined;
}>;
export declare const validateConfigGetParams: import("ajv").ValidateFunction<{}>;
export declare const validateConfigSetParams: import("ajv").ValidateFunction<{
    raw: string;
    baseHash?: string | undefined;
}>;
export declare const validateConfigApplyParams: import("ajv").ValidateFunction<{
    raw: string;
    baseHash?: string | undefined;
    sessionKey?: string | undefined;
    note?: string | undefined;
    restartDelayMs?: number | undefined;
}>;
export declare const validateConfigPatchParams: import("ajv").ValidateFunction<{
    raw: string;
    baseHash?: string | undefined;
    sessionKey?: string | undefined;
    note?: string | undefined;
    restartDelayMs?: number | undefined;
}>;
export declare const validateConfigSchemaParams: import("ajv").ValidateFunction<{}>;
export declare const validateWizardStartParams: import("ajv").ValidateFunction<{
    mode?: "local" | "remote" | undefined;
    workspace?: string | undefined;
}>;
export declare const validateWizardNextParams: import("ajv").ValidateFunction<{
    sessionId: string;
    answer?: {
        stepId: string;
        value?: unknown;
    } | undefined;
}>;
export declare const validateWizardCancelParams: import("ajv").ValidateFunction<{
    sessionId: string;
}>;
export declare const validateWizardStatusParams: import("ajv").ValidateFunction<{
    sessionId: string;
}>;
export declare const validateTalkModeParams: import("ajv").ValidateFunction<{
    enabled: boolean;
    phase?: string | undefined;
}>;
export declare const validateTalkConfigParams: import("ajv").ValidateFunction<{
    includeSecrets?: boolean | undefined;
}>;
export declare const validateChannelsStatusParams: import("ajv").ValidateFunction<{
    probe?: boolean | undefined;
    timeoutMs?: number | undefined;
}>;
export declare const validateChannelsLogoutParams: import("ajv").ValidateFunction<{
    channel: string;
    accountId?: string | undefined;
}>;
export declare const validateModelsListParams: import("ajv").ValidateFunction<{}>;
export declare const validateSkillsStatusParams: import("ajv").ValidateFunction<{
    agentId?: string | undefined;
}>;
export declare const validateSkillsBinsParams: import("ajv").ValidateFunction<{}>;
export declare const validateSkillsInstallParams: import("ajv").ValidateFunction<{
    name: string;
    installId: string;
    timeoutMs?: number | undefined;
}>;
export declare const validateSkillsUpdateParams: import("ajv").ValidateFunction<{
    skillKey: string;
    enabled?: boolean | undefined;
    apiKey?: string | undefined;
    env?: {
        [x: string]: string;
    } | undefined;
}>;
export declare const validateCronListParams: import("ajv").ValidateFunction<{
    includeDisabled?: boolean | undefined;
}>;
export declare const validateCronStatusParams: import("ajv").ValidateFunction<{}>;
export declare const validateCronAddParams: import("ajv").ValidateFunction<{
    name: string;
    agentId?: string | null | undefined;
    description?: string | undefined;
    enabled?: boolean | undefined;
    deleteAfterRun?: boolean | undefined;
    schedule: {
        kind: "at";
        at: string;
    } | {
        kind: "every";
        everyMs: number;
        anchorMs?: number | undefined;
    } | {
        kind: "cron";
        expr: string;
        tz?: string | undefined;
    };
    sessionTarget: "isolated" | "main";
    wakeMode: "next-heartbeat" | "now";
    payload: {
        kind: "systemEvent";
        text: string;
    } | {
        kind: "agentTurn";
        message: unknown;
        model?: string | undefined;
        thinking?: string | undefined;
        timeoutSeconds?: number | undefined;
        allowUnsafeExternalContent?: boolean | undefined;
        deliver?: boolean | undefined;
        channel?: string | undefined;
        to?: string | undefined;
        bestEffortDeliver?: boolean | undefined;
    };
    delivery?: {
        channel?: string | undefined;
        bestEffort?: boolean | undefined;
        mode: "none";
        to?: string | undefined;
    } | {
        channel?: string | undefined;
        bestEffort?: boolean | undefined;
        mode: "announce";
        to?: string | undefined;
    } | {
        channel?: string | undefined;
        bestEffort?: boolean | undefined;
        mode: "webhook";
        to: string;
    } | undefined;
}>;
export declare const validateCronUpdateParams: import("ajv").ValidateFunction<{
    id: string;
    patch: {
        name?: string | undefined;
        agentId?: string | null | undefined;
        description?: string | undefined;
        enabled?: boolean | undefined;
        deleteAfterRun?: boolean | undefined;
        schedule?: {
            kind: "at";
            at: string;
        } | {
            kind: "every";
            everyMs: number;
            anchorMs?: number | undefined;
        } | {
            kind: "cron";
            expr: string;
            tz?: string | undefined;
        } | undefined;
        sessionTarget?: "isolated" | "main" | undefined;
        wakeMode?: "next-heartbeat" | "now" | undefined;
        payload?: {
            kind: "agentTurn";
            message: unknown;
            model?: string | undefined;
            thinking?: string | undefined;
            timeoutSeconds?: number | undefined;
            allowUnsafeExternalContent?: boolean | undefined;
            deliver?: boolean | undefined;
            channel?: string | undefined;
            to?: string | undefined;
            bestEffortDeliver?: boolean | undefined;
        } | {
            kind: "systemEvent";
            text?: string | undefined;
        } | undefined;
        delivery?: {
            channel?: string | undefined;
            bestEffort?: boolean | undefined;
            mode?: "announce" | "none" | "webhook" | undefined;
            to?: string | undefined;
        } | undefined;
        state?: {
            nextRunAtMs?: number | undefined;
            runningAtMs?: number | undefined;
            lastRunAtMs?: number | undefined;
            lastStatus?: "error" | "ok" | "skipped" | undefined;
            lastError?: string | undefined;
            lastDurationMs?: number | undefined;
            consecutiveErrors?: number | undefined;
        } | undefined;
    };
} | {
    jobId: string;
    patch: {
        name?: string | undefined;
        agentId?: string | null | undefined;
        description?: string | undefined;
        enabled?: boolean | undefined;
        deleteAfterRun?: boolean | undefined;
        schedule?: {
            kind: "at";
            at: string;
        } | {
            kind: "every";
            everyMs: number;
            anchorMs?: number | undefined;
        } | {
            kind: "cron";
            expr: string;
            tz?: string | undefined;
        } | undefined;
        sessionTarget?: "isolated" | "main" | undefined;
        wakeMode?: "next-heartbeat" | "now" | undefined;
        payload?: {
            kind: "agentTurn";
            message: unknown;
            model?: string | undefined;
            thinking?: string | undefined;
            timeoutSeconds?: number | undefined;
            allowUnsafeExternalContent?: boolean | undefined;
            deliver?: boolean | undefined;
            channel?: string | undefined;
            to?: string | undefined;
            bestEffortDeliver?: boolean | undefined;
        } | {
            kind: "systemEvent";
            text?: string | undefined;
        } | undefined;
        delivery?: {
            channel?: string | undefined;
            bestEffort?: boolean | undefined;
            mode?: "announce" | "none" | "webhook" | undefined;
            to?: string | undefined;
        } | undefined;
        state?: {
            nextRunAtMs?: number | undefined;
            runningAtMs?: number | undefined;
            lastRunAtMs?: number | undefined;
            lastStatus?: "error" | "ok" | "skipped" | undefined;
            lastError?: string | undefined;
            lastDurationMs?: number | undefined;
            consecutiveErrors?: number | undefined;
        } | undefined;
    };
}>;
export declare const validateCronRemoveParams: import("ajv").ValidateFunction<{
    id: string;
} | {
    jobId: string;
}>;
export declare const validateCronRunParams: import("ajv").ValidateFunction<{
    id: string;
    mode?: "due" | "force" | undefined;
} | {
    jobId: string;
    mode?: "due" | "force" | undefined;
}>;
export declare const validateCronRunsParams: import("ajv").ValidateFunction<{
    id: string;
    limit?: number | undefined;
} | {
    jobId: string;
    limit?: number | undefined;
}>;
export declare const validateDevicePairListParams: import("ajv").ValidateFunction<{}>;
export declare const validateDevicePairApproveParams: import("ajv").ValidateFunction<{
    requestId: string;
}>;
export declare const validateDevicePairRejectParams: import("ajv").ValidateFunction<{
    requestId: string;
}>;
export declare const validateDeviceTokenRotateParams: import("ajv").ValidateFunction<{
    deviceId: string;
    role: string;
    scopes?: string[] | undefined;
}>;
export declare const validateDeviceTokenRevokeParams: import("ajv").ValidateFunction<{
    deviceId: string;
    role: string;
}>;
export declare const validateExecApprovalsGetParams: import("ajv").ValidateFunction<{}>;
export declare const validateExecApprovalsSetParams: import("ajv").ValidateFunction<{
    file: {
        version: 1;
        socket?: {
            path?: string | undefined;
            token?: string | undefined;
        } | undefined;
        defaults?: {
            security?: string | undefined;
            ask?: string | undefined;
            askFallback?: string | undefined;
            autoAllowSkills?: boolean | undefined;
        } | undefined;
        agents?: {
            [x: string]: {
                security?: string | undefined;
                ask?: string | undefined;
                askFallback?: string | undefined;
                autoAllowSkills?: boolean | undefined;
                allowlist?: {
                    id?: string | undefined;
                    pattern: string;
                    lastUsedAt?: number | undefined;
                    lastUsedCommand?: string | undefined;
                    lastResolvedPath?: string | undefined;
                }[] | undefined;
            };
        } | undefined;
    };
    baseHash?: string | undefined;
}>;
export declare const validateExecApprovalRequestParams: import("ajv").ValidateFunction<{
    id?: string | undefined;
    command: string;
    cwd?: string | null | undefined;
    host?: string | null | undefined;
    security?: string | null | undefined;
    ask?: string | null | undefined;
    agentId?: string | null | undefined;
    resolvedPath?: string | null | undefined;
    sessionKey?: string | null | undefined;
    timeoutMs?: number | undefined;
    twoPhase?: boolean | undefined;
}>;
export declare const validateExecApprovalResolveParams: import("ajv").ValidateFunction<{
    id: string;
    decision: string;
}>;
export declare const validateExecApprovalsNodeGetParams: import("ajv").ValidateFunction<{
    nodeId: string;
}>;
export declare const validateExecApprovalsNodeSetParams: import("ajv").ValidateFunction<{
    nodeId: string;
    file: {
        version: 1;
        socket?: {
            path?: string | undefined;
            token?: string | undefined;
        } | undefined;
        defaults?: {
            security?: string | undefined;
            ask?: string | undefined;
            askFallback?: string | undefined;
            autoAllowSkills?: boolean | undefined;
        } | undefined;
        agents?: {
            [x: string]: {
                security?: string | undefined;
                ask?: string | undefined;
                askFallback?: string | undefined;
                autoAllowSkills?: boolean | undefined;
                allowlist?: {
                    id?: string | undefined;
                    pattern: string;
                    lastUsedAt?: number | undefined;
                    lastUsedCommand?: string | undefined;
                    lastResolvedPath?: string | undefined;
                }[] | undefined;
            };
        } | undefined;
    };
    baseHash?: string | undefined;
}>;
export declare const validateLogsTailParams: import("ajv").ValidateFunction<{
    cursor?: number | undefined;
    limit?: number | undefined;
    maxBytes?: number | undefined;
}>;
export declare const validateChatHistoryParams: import("ajv").ValidateFunction<{
    sessionKey: any;
}>;
export declare const validateChatSendParams: import("ajv").ValidateFunction<{
    idempotencyKey: any;
    message: any;
    sessionKey: any;
} & {
    idempotencyKey: any;
} & {
    message: any;
} & {
    sessionKey: any;
}>;
export declare const validateChatAbortParams: import("ajv").ValidateFunction<{
    sessionKey: string;
    runId?: string | undefined;
}>;
export declare const validateChatInjectParams: import("ajv").ValidateFunction<{
    sessionKey: string;
    message: string;
    label?: string | undefined;
}>;
export declare const validateChatEvent: import("ajv").ValidateFunction<{
    runId: any;
    seq: any;
    sessionKey: any;
    state: any;
} & {
    runId: any;
} & {
    seq: any;
} & {
    sessionKey: any;
} & {
    state: any;
}>;
export declare const validateUpdateRunParams: import("ajv").ValidateFunction<{
    sessionKey?: string | undefined;
    note?: string | undefined;
    restartDelayMs?: number | undefined;
    timeoutMs?: number | undefined;
}>;
export declare const validateWebLoginStartParams: import("ajv").ValidateFunction<{
    force?: boolean | undefined;
    timeoutMs?: number | undefined;
    verbose?: boolean | undefined;
    accountId?: string | undefined;
}>;
export declare const validateWebLoginWaitParams: import("ajv").ValidateFunction<{
    timeoutMs?: number | undefined;
    accountId?: string | undefined;
}>;
export declare function formatValidationErrors(errors: ErrorObject[] | null | undefined): string;
export { ConnectParamsSchema, HelloOkSchema, RequestFrameSchema, ResponseFrameSchema, EventFrameSchema, GatewayFrameSchema, PresenceEntrySchema, SnapshotSchema, ErrorShapeSchema, StateVersionSchema, AgentEventSchema, ChatEventSchema, SendParamsSchema, PollParamsSchema, AgentParamsSchema, AgentIdentityParamsSchema, AgentIdentityResultSchema, WakeParamsSchema, NodePairRequestParamsSchema, NodePairListParamsSchema, NodePairApproveParamsSchema, NodePairRejectParamsSchema, NodePairVerifyParamsSchema, NodeListParamsSchema, NodeInvokeParamsSchema, SessionsListParamsSchema, SessionsPreviewParamsSchema, SessionsPatchParamsSchema, SessionsResetParamsSchema, SessionsDeleteParamsSchema, SessionsCompactParamsSchema, SessionsUsageParamsSchema, ConfigGetParamsSchema, ConfigSetParamsSchema, ConfigApplyParamsSchema, ConfigPatchParamsSchema, ConfigSchemaParamsSchema, ConfigSchemaResponseSchema, WizardStartParamsSchema, WizardNextParamsSchema, WizardCancelParamsSchema, WizardStatusParamsSchema, WizardStepSchema, WizardNextResultSchema, WizardStartResultSchema, WizardStatusResultSchema, TalkConfigParamsSchema, TalkConfigResultSchema, ChannelsStatusParamsSchema, ChannelsStatusResultSchema, ChannelsLogoutParamsSchema, WebLoginStartParamsSchema, WebLoginWaitParamsSchema, AgentSummarySchema, AgentsFileEntrySchema, AgentsCreateParamsSchema, AgentsCreateResultSchema, AgentsUpdateParamsSchema, AgentsUpdateResultSchema, AgentsDeleteParamsSchema, AgentsDeleteResultSchema, AgentsFilesListParamsSchema, AgentsFilesListResultSchema, AgentsFilesGetParamsSchema, AgentsFilesGetResultSchema, AgentsFilesSetParamsSchema, AgentsFilesSetResultSchema, AgentsListParamsSchema, AgentsListResultSchema, ModelsListParamsSchema, SkillsStatusParamsSchema, SkillsInstallParamsSchema, SkillsUpdateParamsSchema, CronJobSchema, CronListParamsSchema, CronStatusParamsSchema, CronAddParamsSchema, CronUpdateParamsSchema, CronRemoveParamsSchema, CronRunParamsSchema, CronRunsParamsSchema, LogsTailParamsSchema, LogsTailResultSchema, ChatHistoryParamsSchema, ChatSendParamsSchema, ChatInjectParamsSchema, UpdateRunParamsSchema, TickEventSchema, ShutdownEventSchema, ProtocolSchemas, PROTOCOL_VERSION, ErrorCodes, errorShape, };
export type { GatewayFrame, ConnectParams, HelloOk, RequestFrame, ResponseFrame, EventFrame, PresenceEntry, Snapshot, ErrorShape, StateVersion, AgentEvent, AgentIdentityParams, AgentIdentityResult, AgentWaitParams, ChatEvent, TickEvent, ShutdownEvent, WakeParams, NodePairRequestParams, NodePairListParams, NodePairApproveParams, DevicePairListParams, DevicePairApproveParams, DevicePairRejectParams, ConfigGetParams, ConfigSetParams, ConfigApplyParams, ConfigPatchParams, ConfigSchemaParams, ConfigSchemaResponse, WizardStartParams, WizardNextParams, WizardCancelParams, WizardStatusParams, WizardStep, WizardNextResult, WizardStartResult, WizardStatusResult, TalkConfigParams, TalkConfigResult, TalkModeParams, ChannelsStatusParams, ChannelsStatusResult, ChannelsLogoutParams, WebLoginStartParams, WebLoginWaitParams, AgentSummary, AgentsFileEntry, AgentsCreateParams, AgentsCreateResult, AgentsUpdateParams, AgentsUpdateResult, AgentsDeleteParams, AgentsDeleteResult, AgentsFilesListParams, AgentsFilesListResult, AgentsFilesGetParams, AgentsFilesGetResult, AgentsFilesSetParams, AgentsFilesSetResult, AgentsListParams, AgentsListResult, SkillsStatusParams, SkillsBinsParams, SkillsBinsResult, SkillsInstallParams, SkillsUpdateParams, NodePairRejectParams, NodePairVerifyParams, NodeListParams, NodeInvokeParams, NodeInvokeResultParams, NodeEventParams, SessionsListParams, SessionsPreviewParams, SessionsResolveParams, SessionsPatchParams, SessionsPatchResult, SessionsResetParams, SessionsDeleteParams, SessionsCompactParams, SessionsUsageParams, CronJob, CronListParams, CronStatusParams, CronAddParams, CronUpdateParams, CronRemoveParams, CronRunParams, CronRunsParams, CronRunLogEntry, ExecApprovalsGetParams, ExecApprovalsSetParams, ExecApprovalsSnapshot, LogsTailParams, LogsTailResult, PollParams, UpdateRunParams, ChatInjectParams, };
//# sourceMappingURL=index.d.ts.map
import type { MessageEvent, EventSource, PostbackEvent } from "@line/bot-sdk";
import type { OpenClawConfig } from "../config/config.js";
import type { ResolvedLineAccount } from "./types.js";
interface MediaRef {
    path: string;
    contentType?: string;
}
interface BuildLineMessageContextParams {
    event: MessageEvent;
    allMedia: MediaRef[];
    cfg: OpenClawConfig;
    account: ResolvedLineAccount;
}
export type LineSourceInfo = {
    userId?: string;
    groupId?: string;
    roomId?: string;
    isGroup: boolean;
};
export declare function getLineSourceInfo(source: EventSource): LineSourceInfo;
export declare function buildLineMessageContext(params: BuildLineMessageContextParams): Promise<{
    ctxPayload: {
        LocationLat?: number | undefined;
        LocationLon?: number | undefined;
        LocationAccuracy?: number | undefined;
        LocationName?: string | undefined;
        LocationAddress?: string | undefined;
        LocationSource?: import("../channels/location.js").LocationSource | undefined;
        LocationIsLive?: boolean | undefined;
        Body: string;
        BodyForAgent: string;
        RawBody: string;
        CommandBody: string;
        From: string;
        To: string;
        SessionKey: string;
        AccountId: string;
        ChatType: string;
        ConversationLabel: string;
        GroupSubject: string | undefined;
        SenderId: string;
        Provider: string;
        Surface: string;
        MessageSid: string;
        Timestamp: number;
        MediaPath: string | undefined;
        MediaType: string | undefined;
        MediaUrl: string | undefined;
        MediaPaths: string[] | undefined;
        MediaUrls: string[] | undefined;
        MediaTypes: string[] | undefined;
        OriginatingChannel: "line";
        OriginatingTo: string;
    } & Omit<import("../auto-reply/templating.js").MsgContext, "CommandAuthorized"> & {
        CommandAuthorized: boolean;
    };
    event: MessageEvent;
    userId: string | undefined;
    groupId: string | undefined;
    roomId: string | undefined;
    isGroup: boolean;
    route: import("../routing/resolve-route.js").ResolvedAgentRoute;
    replyToken: string;
    accountId: string;
} | null>;
export declare function buildLinePostbackContext(params: {
    event: PostbackEvent;
    cfg: OpenClawConfig;
    account: ResolvedLineAccount;
}): Promise<{
    ctxPayload: {
        LocationLat?: number | undefined;
        LocationLon?: number | undefined;
        LocationAccuracy?: number | undefined;
        LocationName?: string | undefined;
        LocationAddress?: string | undefined;
        LocationSource?: import("../channels/location.js").LocationSource | undefined;
        LocationIsLive?: boolean | undefined;
        Body: string;
        BodyForAgent: string;
        RawBody: string;
        CommandBody: string;
        From: string;
        To: string;
        SessionKey: string;
        AccountId: string;
        ChatType: string;
        ConversationLabel: string;
        GroupSubject: string | undefined;
        SenderId: string;
        Provider: string;
        Surface: string;
        MessageSid: string;
        Timestamp: number;
        MediaPath: string | undefined;
        MediaType: string | undefined;
        MediaUrl: string | undefined;
        MediaPaths: string[] | undefined;
        MediaUrls: string[] | undefined;
        MediaTypes: string[] | undefined;
        OriginatingChannel: "line";
        OriginatingTo: string;
    } & Omit<import("../auto-reply/templating.js").MsgContext, "CommandAuthorized"> & {
        CommandAuthorized: boolean;
    };
    event: PostbackEvent;
    userId: string | undefined;
    groupId: string | undefined;
    roomId: string | undefined;
    isGroup: boolean;
    route: import("../routing/resolve-route.js").ResolvedAgentRoute;
    replyToken: string;
    accountId: string;
} | null>;
export type LineMessageContext = NonNullable<Awaited<ReturnType<typeof buildLineMessageContext>>>;
export type LinePostbackContext = NonNullable<Awaited<ReturnType<typeof buildLinePostbackContext>>>;
export type LineInboundContext = LineMessageContext | LinePostbackContext;

//# sourceMappingURL=bot-message-context.d.ts.map
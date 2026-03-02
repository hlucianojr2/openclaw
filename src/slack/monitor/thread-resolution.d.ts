import type { WebClient as SlackWebClient } from "@slack/web-api";
import type { SlackMessageEvent } from "../types.js";
export declare function createSlackThreadTsResolver(params: {
    client: SlackWebClient;
    cacheTtlMs?: number;
    maxSize?: number;
}): {
    resolve: (request: {
        message: SlackMessageEvent;
        source: "app_mention" | "message";
    }) => Promise<SlackMessageEvent>;
};
//# sourceMappingURL=thread-resolution.d.ts.map
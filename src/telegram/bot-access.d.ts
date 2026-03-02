import type { AllowlistMatch } from "../channels/allowlist-match.js";
export type NormalizedAllowFrom = {
    entries: string[];
    hasWildcard: boolean;
    hasEntries: boolean;
    invalidEntries: string[];
};
export type AllowFromMatch = AllowlistMatch<"wildcard" | "id">;
export declare const normalizeAllowFrom: (list?: (string | number)[]  ) => NormalizedAllowFrom;
export declare const normalizeAllowFromWithStore: (params: {
    allowFrom?: (string | number)[] | undefined;
    storeAllowFrom?: string[] | undefined;
}) => NormalizedAllowFrom;
export declare const firstDefined: <T>(...values: (T | undefined)[]) => (T & ({} | null)) | undefined;
export declare const isSenderAllowed: (params: {
    allow: NormalizedAllowFrom;
    senderId?: string | undefined;
    senderUsername?: string | undefined;
}) => boolean;
export declare const resolveSenderAllowMatch: (params: {
    allow: NormalizedAllowFrom;
    senderId?: string | undefined;
    senderUsername?: string | undefined;
}) => AllowFromMatch;
//# sourceMappingURL=bot-access.d.ts.map
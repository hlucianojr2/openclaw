export type NormalizedAllowFrom = {
    entries: string[];
    hasWildcard: boolean;
    hasEntries: boolean;
};
export declare const normalizeAllowFrom: (list?: (string | number)[]  ) => NormalizedAllowFrom;
export declare const normalizeAllowFromWithStore: (params: {
    allowFrom?: (string | number)[] | undefined;
    storeAllowFrom?: string[] | undefined;
}) => NormalizedAllowFrom;
export declare const firstDefined: <T>(...values: (T | undefined)[]) => (T & ({} | null)) | undefined;
export declare const isSenderAllowed: (params: {
    allow: NormalizedAllowFrom;
    senderId?: string | undefined;
}) => boolean;
//# sourceMappingURL=bot-access.d.ts.map
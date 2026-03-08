export type DedupeCache = {
    check: (key: string | undefined | null, now?: number) => boolean;
    clear: () => void;
    size: () => number;
};
type DedupeCacheOptions = {
    ttlMs: number;
    maxSize: number;
};
export declare function createDedupeCache(options: DedupeCacheOptions): DedupeCache;

//# sourceMappingURL=dedupe.d.ts.map
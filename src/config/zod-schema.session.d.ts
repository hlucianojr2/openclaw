import { z } from "zod";
export declare const SessionSendPolicySchema: z.ZodOptional<z.ZodObject<{
    default: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"allow">, z.ZodLiteral<"deny">]>>;
    rules: z.ZodOptional<z.ZodArray<z.ZodObject<{
        action: z.ZodUnion<readonly [z.ZodLiteral<"allow">, z.ZodLiteral<"deny">]>;
        match: z.ZodOptional<z.ZodObject<{
            channel: z.ZodOptional<z.ZodString>;
            chatType: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"direct">, z.ZodLiteral<"group">, z.ZodLiteral<"channel">, z.ZodLiteral<"dm">]>>;
            keyPrefix: z.ZodOptional<z.ZodString>;
            rawKeyPrefix: z.ZodOptional<z.ZodString>;
        }>>;
    }>>>;
}>>;
export declare const SessionSchema: z.ZodOptional<z.ZodObject<{
    scope: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"per-sender">, z.ZodLiteral<"global">]>>;
    dmScope: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"main">, z.ZodLiteral<"per-peer">, z.ZodLiteral<"per-channel-peer">, z.ZodLiteral<"per-account-channel-peer">]>>;
    identityLinks: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodArray<z.ZodString>>>;
    resetTriggers: z.ZodOptional<z.ZodArray<z.ZodString>>;
    idleMinutes: z.ZodOptional<z.ZodNumber>;
    reset: z.ZodOptional<z.ZodObject<{
        mode: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"daily">, z.ZodLiteral<"idle">]>>;
        atHour: z.ZodOptional<z.ZodNumber>;
        idleMinutes: z.ZodOptional<z.ZodNumber>;
    }>>;
    resetByType: z.ZodOptional<z.ZodObject<{
        direct: z.ZodOptional<z.ZodObject<{
            mode: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"daily">, z.ZodLiteral<"idle">]>>;
            atHour: z.ZodOptional<z.ZodNumber>;
            idleMinutes: z.ZodOptional<z.ZodNumber>;
        }>>;
        dm: z.ZodOptional<z.ZodObject<{
            mode: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"daily">, z.ZodLiteral<"idle">]>>;
            atHour: z.ZodOptional<z.ZodNumber>;
            idleMinutes: z.ZodOptional<z.ZodNumber>;
        }>>;
        group: z.ZodOptional<z.ZodObject<{
            mode: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"daily">, z.ZodLiteral<"idle">]>>;
            atHour: z.ZodOptional<z.ZodNumber>;
            idleMinutes: z.ZodOptional<z.ZodNumber>;
        }>>;
        thread: z.ZodOptional<z.ZodObject<{
            mode: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"daily">, z.ZodLiteral<"idle">]>>;
            atHour: z.ZodOptional<z.ZodNumber>;
            idleMinutes: z.ZodOptional<z.ZodNumber>;
        }>>;
    }>>;
    resetByChannel: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodObject<{
        mode: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"daily">, z.ZodLiteral<"idle">]>>;
        atHour: z.ZodOptional<z.ZodNumber>;
        idleMinutes: z.ZodOptional<z.ZodNumber>;
    }>>>;
    store: z.ZodOptional<z.ZodString>;
    typingIntervalSeconds: z.ZodOptional<z.ZodNumber>;
    typingMode: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"never">, z.ZodLiteral<"instant">, z.ZodLiteral<"thinking">, z.ZodLiteral<"message">]>>;
    mainKey: z.ZodOptional<z.ZodString>;
    sendPolicy: z.ZodOptional<z.ZodOptional<z.ZodObject<{
        default: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"allow">, z.ZodLiteral<"deny">]>>;
        rules: z.ZodOptional<z.ZodArray<z.ZodObject<{
            action: z.ZodUnion<readonly [z.ZodLiteral<"allow">, z.ZodLiteral<"deny">]>;
            match: z.ZodOptional<z.ZodObject<{
                channel: z.ZodOptional<z.ZodString>;
                chatType: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"direct">, z.ZodLiteral<"group">, z.ZodLiteral<"channel">, z.ZodLiteral<"dm">]>>;
                keyPrefix: z.ZodOptional<z.ZodString>;
                rawKeyPrefix: z.ZodOptional<z.ZodString>;
            }>>;
        }>>>;
    }>>>;
    agentToAgent: z.ZodOptional<z.ZodObject<{
        maxPingPongTurns: z.ZodOptional<z.ZodNumber>;
    }>>;
    maintenance: z.ZodOptional<z.ZodObject<{
        mode: z.ZodOptional<z.ZodEnum<{
            enforce: "enforce";
            warn: "warn";
        }>>;
        pruneAfter: z.ZodOptional<z.ZodUnion<readonly [z.ZodString, z.ZodNumber]>>;
        pruneDays: z.ZodOptional<z.ZodNumber>;
        maxEntries: z.ZodOptional<z.ZodNumber>;
        rotateBytes: z.ZodOptional<z.ZodUnion<readonly [z.ZodString, z.ZodNumber]>>;
    }>>;
}>>;
export declare const MessagesSchema: z.ZodOptional<z.ZodObject<{
    messagePrefix: z.ZodOptional<z.ZodString>;
    responsePrefix: z.ZodOptional<z.ZodString>;
    groupChat: z.ZodOptional<z.ZodObject<{
        mentionPatterns: z.ZodOptional<z.ZodArray<z.ZodString>>;
        historyLimit: z.ZodOptional<z.ZodNumber>;
    }>>;
    queue: z.ZodOptional<z.ZodObject<{
        mode: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
        byChannel: z.ZodOptional<z.ZodObject<{
            whatsapp: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            telegram: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            discord: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            irc: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            slack: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            mattermost: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            signal: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            imessage: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            msteams: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
            webchat: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"steer">, z.ZodLiteral<"followup">, z.ZodLiteral<"collect">, z.ZodLiteral<"steer-backlog">, z.ZodLiteral<"steer+backlog">, z.ZodLiteral<"queue">, z.ZodLiteral<"interrupt">]>>;
        }>>;
        debounceMs: z.ZodOptional<z.ZodNumber>;
        debounceMsByChannel: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodNumber>>;
        cap: z.ZodOptional<z.ZodNumber>;
        drop: z.ZodOptional<z.ZodUnion<readonly [z.ZodLiteral<"old">, z.ZodLiteral<"new">, z.ZodLiteral<"summarize">]>>;
    }>>;
    inbound: z.ZodOptional<z.ZodObject<{
        debounceMs: z.ZodOptional<z.ZodNumber>;
        byChannel: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodNumber>>;
    }>>;
    ackReaction: z.ZodOptional<z.ZodString>;
    ackReactionScope: z.ZodOptional<z.ZodEnum<{
        all: "all";
        direct: "direct";
        "group-all": "group-all";
        "group-mentions": "group-mentions";
    }>>;
    removeAckAfterReply: z.ZodOptional<z.ZodBoolean>;
    suppressToolErrors: z.ZodOptional<z.ZodBoolean>;
    tts: z.ZodOptional<z.ZodObject<{
        auto: z.ZodOptional<z.ZodEnum<{
            always: "always";
            inbound: "inbound";
            off: "off";
            tagged: "tagged";
        }>>;
        enabled: z.ZodOptional<z.ZodBoolean>;
        mode: z.ZodOptional<z.ZodEnum<{
            all: "all";
            final: "final";
        }>>;
        provider: z.ZodOptional<z.ZodEnum<{
            edge: "edge";
            elevenlabs: "elevenlabs";
            openai: "openai";
        }>>;
        summaryModel: z.ZodOptional<z.ZodString>;
        modelOverrides: z.ZodOptional<z.ZodObject<{
            enabled: z.ZodOptional<z.ZodBoolean>;
            allowText: z.ZodOptional<z.ZodBoolean>;
            allowProvider: z.ZodOptional<z.ZodBoolean>;
            allowVoice: z.ZodOptional<z.ZodBoolean>;
            allowModelId: z.ZodOptional<z.ZodBoolean>;
            allowVoiceSettings: z.ZodOptional<z.ZodBoolean>;
            allowNormalization: z.ZodOptional<z.ZodBoolean>;
            allowSeed: z.ZodOptional<z.ZodBoolean>;
        }>>;
        elevenlabs: z.ZodOptional<z.ZodObject<{
            apiKey: z.ZodOptional<z.ZodString>;
            baseUrl: z.ZodOptional<z.ZodString>;
            voiceId: z.ZodOptional<z.ZodString>;
            modelId: z.ZodOptional<z.ZodString>;
            seed: z.ZodOptional<z.ZodNumber>;
            applyTextNormalization: z.ZodOptional<z.ZodEnum<{
                auto: "auto";
                off: "off";
                on: "on";
            }>>;
            languageCode: z.ZodOptional<z.ZodString>;
            voiceSettings: z.ZodOptional<z.ZodObject<{
                stability: z.ZodOptional<z.ZodNumber>;
                similarityBoost: z.ZodOptional<z.ZodNumber>;
                style: z.ZodOptional<z.ZodNumber>;
                useSpeakerBoost: z.ZodOptional<z.ZodBoolean>;
                speed: z.ZodOptional<z.ZodNumber>;
            }>>;
        }>>;
        openai: z.ZodOptional<z.ZodObject<{
            apiKey: z.ZodOptional<z.ZodString>;
            model: z.ZodOptional<z.ZodString>;
            voice: z.ZodOptional<z.ZodString>;
        }>>;
        edge: z.ZodOptional<z.ZodObject<{
            enabled: z.ZodOptional<z.ZodBoolean>;
            voice: z.ZodOptional<z.ZodString>;
            lang: z.ZodOptional<z.ZodString>;
            outputFormat: z.ZodOptional<z.ZodString>;
            pitch: z.ZodOptional<z.ZodString>;
            rate: z.ZodOptional<z.ZodString>;
            volume: z.ZodOptional<z.ZodString>;
            saveSubtitles: z.ZodOptional<z.ZodBoolean>;
            proxy: z.ZodOptional<z.ZodString>;
            timeoutMs: z.ZodOptional<z.ZodNumber>;
        }>>;
        prefsPath: z.ZodOptional<z.ZodString>;
        maxTextLength: z.ZodOptional<z.ZodNumber>;
        timeoutMs: z.ZodOptional<z.ZodNumber>;
    }>>;
}>>;
export declare const CommandsSchema: z.ZodDefault<z.ZodOptional<z.ZodObject<{
    native: z.ZodDefault<z.ZodOptional<z.ZodUnion<readonly [z.ZodBoolean, z.ZodLiteral<"auto">]>>>;
    nativeSkills: z.ZodDefault<z.ZodOptional<z.ZodUnion<readonly [z.ZodBoolean, z.ZodLiteral<"auto">]>>>;
    text: z.ZodOptional<z.ZodBoolean>;
    bash: z.ZodOptional<z.ZodBoolean>;
    bashForegroundMs: z.ZodOptional<z.ZodNumber>;
    config: z.ZodOptional<z.ZodBoolean>;
    debug: z.ZodOptional<z.ZodBoolean>;
    restart: z.ZodOptional<z.ZodBoolean>;
    useAccessGroups: z.ZodOptional<z.ZodBoolean>;
    ownerAllowFrom: z.ZodOptional<z.ZodArray<z.ZodUnion<readonly [z.ZodString, z.ZodNumber]>>>;
    allowFrom: z.ZodOptional<z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodArray<z.ZodUnion<readonly [z.ZodString, z.ZodNumber]>>>>>;
}>>>;
//# sourceMappingURL=zod-schema.session.d.ts.map
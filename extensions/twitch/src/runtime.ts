import type { PluginRuntime } from "openclaw/plugin-sdk/twitch";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setTwitchRuntime, getRuntime: getTwitchRuntime } =
  createPluginRuntimeStore<PluginRuntime>("Twitch runtime not initialized");
export { getTwitchRuntime, setTwitchRuntime };

import type { PluginRuntime } from "openclaw/plugin-sdk/irc";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setIrcRuntime, getRuntime: getIrcRuntime } =
  createPluginRuntimeStore<PluginRuntime>("IRC runtime not initialized");
export { getIrcRuntime, setIrcRuntime };

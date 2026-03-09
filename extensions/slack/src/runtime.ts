import type { PluginRuntime } from "openclaw/plugin-sdk/slack";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setSlackRuntime, getRuntime: getSlackRuntime } =
  createPluginRuntimeStore<PluginRuntime>("Slack runtime not initialized");
export { getSlackRuntime, setSlackRuntime };

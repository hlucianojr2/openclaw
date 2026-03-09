import type { PluginRuntime } from "openclaw/plugin-sdk/whatsapp";
import { createPluginRuntimeStore } from "openclaw/plugin-sdk";

const { setRuntime: setWhatsAppRuntime, getRuntime: getWhatsAppRuntime } =
  createPluginRuntimeStore<PluginRuntime>("WhatsApp runtime not initialized");
export { getWhatsAppRuntime, setWhatsAppRuntime };

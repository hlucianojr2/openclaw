/**
 * Shared types for the installation wizard.
 * Kept in a separate module so step components can import them without
 * pulling in the full InstallerWizard render tree.
 */

export type LLMProvider = "anthropic" | "google-gemini" | "openai" | "ollama";

export interface WizardConfig {
  llmProvider: LLMProvider;
  llmApiKey: string;
  /** Skill IDs to enable on first install. */
  selectedSkills: string[];
  /** Channel IDs the user activated in the channels step. */
  enabledChannels: string[];
  githubPat: string;
  githubRepo: string;
  voiceEnabled: boolean;
  gatewayPort: number;
  bridgePort: number;
}

export interface InstallProgress {
  stage: string;
  percent: number;
  message: string;
  error?: string;
}

/**
 * Voice Guide — narrates wizard steps using text-to-speech.
 *
 * Priority order:
 *   1. node-edge-tts (high-quality Microsoft Neural TTS via WebSocket)
 *   2. OS native TTS (say / espeak / PowerShell SpeechSynthesizer)
 *   3. Silent (graceful no-op — never throws)
 *
 * node-edge-tts is the existing OpenClaw root-level dep (^1.2.10).
 * It is loaded via dynamic import so startup is never blocked if the
 * package is unavailable in dev/test environments.
 */

import { exec } from "node:child_process";
import { promisify } from "node:util";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rm } from "node:fs/promises";

const execAsync = promisify(exec);

/** Unique tmp file prefix so concurrent speaks don't collide. */
// (instance field; see _tmpCounter below)

export class VoiceGuide {
  private enabled = true;
  private speaking = false;
  private queue: string[] = [];
  /** pid of the currently-playing audio process (for stop()). */
  private currentPlayerPid: number | undefined;
  /** Counter for unique tmp filenames — instance-scoped to avoid test cross-contamination. */
  private _tmpCounter = 0;
  /** The active processQueue() promise, so speak() callers can await narration completion. */
  private queueDrain: Promise<void> = Promise.resolve();

  /** Enable or disable narration. */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
  }

  isEnabled(): boolean {
    return this.enabled;
  }

  /**
   * Speak a message.
   * Returns a Promise that resolves when the queued text has finished playing,
   * so `await voice.speak(text)` guarantees the narration is complete before
   * the caller continues.
   */
  async speak(text: string): Promise<void> {
    if (!this.enabled) {return;}

    this.queue.push(text);
    if (!this.speaking) {
      this.queueDrain = this.processQueue();
    }
    return this.queueDrain;
  }

  private async processQueue(): Promise<void> {
    this.speaking = true;
    while (this.queue.length > 0) {
      const text = this.queue.shift()!;
      await this.sayText(text);
    }
    this.speaking = false;
  }

  private async sayText(text: string): Promise<void> {
    // 1. Try node-edge-tts (Microsoft Neural TTS — high quality, cross-platform)
    //    Dynamic import so the app starts even if the package isn't installed.
    if (await this.tryEdgeTts(text)) { return; }

    // 2. Fallback: OS-native TTS
    await this.tryOsTts(text);
  }

  /**
   * Attempt TTS via node-edge-tts.
   * Synthesises to a temp MP3, plays it with an OS audio command, then cleans up.
   * Returns true on success, false if unavailable or errored.
   */
  private async tryEdgeTts(text: string): Promise<boolean> {
    try {
      // Dynamic import — graceful if not installed
      const { EdgeTTS } = (await import("node-edge-tts")) as {
        EdgeTTS: new (opts: Record<string, string>) => { ttsPromise(text: string, path: string): Promise<void> };
      };

      const tmpFile = join(tmpdir(), `occc-tts-${Date.now()}-${++this._tmpCounter}.mp3`);
      const tts = new EdgeTTS({ voice: "en-US-JennyNeural", lang: "en-US" });
      await tts.ttsPromise(text, tmpFile);

      // Play the generated audio file with an OS command
      await this.playAudioFile(tmpFile);

      // Clean up temp file (non-critical — ignore errors)
      rm(tmpFile, { force: true }).catch(() => undefined);
      return true;
    } catch {
      return false;
    }
  }

  /** Play an audio file using the OS-native audio player. */
  private async playAudioFile(filePath: string): Promise<void> {
    let cmd: string;
    if (process.platform === "darwin") {
      cmd = `afplay ${JSON.stringify(filePath)}`;
    } else if (process.platform === "linux") {
      // mpg123 or ffplay for MP3; fall back to paplay
      cmd = `mpg123 -q ${JSON.stringify(filePath)} 2>/dev/null || ffplay -nodisp -autoexit -loglevel quiet ${JSON.stringify(filePath)}`;
    } else {
      // Windows: use PresentationCore MediaPlayer which handles MP3 natively.
      // SoundPlayer is WAV-only; MediaPlayer supports all Windows Media formats.
      cmd = [
        `powershell -c "Add-Type -AssemblyName PresentationCore;`,
        `$mp = New-Object System.Windows.Media.MediaPlayer;`,
        `$mp.Open([uri]${JSON.stringify(filePath)});`,
        `$mp.Play();`,
        `Start-Sleep -Milliseconds (($mp.NaturalDuration.TimeSpan.TotalMilliseconds) + 500);`,
        `$mp.Stop()"`,
      ].join(" ");
    }
    const child = exec(cmd);
    this.currentPlayerPid = child.pid;
    await new Promise<void>((resolve, reject) => {
      child.on("close", (code) => {
        this.currentPlayerPid = undefined;
        // Exit code 1 from ffplay fallback shell is OK; treat non-zero as error only for the primary
        if (code !== 0 && code !== null && code !== 1) { reject(new Error(`audio player exited ${code}`)); }
        else { resolve(); }
      });
      child.on("error", reject);
    });
  }

  /** Fallback: OS-native TTS (say / espeak / PowerShell). */
  private async tryOsTts(text: string): Promise<void> {
    try {
      if (process.platform === "darwin") {
        await execAsync(`say ${JSON.stringify(text)}`);
      } else if (process.platform === "linux") {
        await execAsync(`espeak ${JSON.stringify(text)} 2>/dev/null || spd-say ${JSON.stringify(text)}`);
      } else if (process.platform === "win32") {
        const script = `Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Synthesis.SpeechSynthesizer; $s.Speak(${JSON.stringify(text)})`;
        await execAsync(`powershell -command "${script}"`);
      }
    } catch {
      // TTS completely unavailable — silent
    }
  }

  /** Stop current speech and clear queue. */
  stop(): void {
    this.queue = [];
    // Kill any in-flight audio player
    if (this.currentPlayerPid !== undefined) {
      try { process.kill(this.currentPlayerPid, "SIGTERM"); } catch { /* already gone */ }
      this.currentPlayerPid = undefined;
    }
    if (process.platform === "darwin") {
      exec("killall say 2>/dev/null; killall afplay 2>/dev/null");
    }
  }
}

/** Pre-written narration scripts for each wizard step. */
export const NARRATION: Record<string, string> = {
  welcome:
    "Welcome to OpenClaw Command Center. I will guide you through setting up your secure OpenClaw deployment. Let's start by checking your system.",
  systemCheckPass:
    "Your system is ready. All checks passed. Let's continue to configure your environment.",
  systemCheckWarn:
    "Your system has some warnings, but we can still proceed. I recommend reviewing them before continuing.",
  systemCheckFail:
    "Some required components are missing. Please follow the on-screen instructions to resolve them.",
  dockerMissing:
    "I couldn't find a container engine on your system. You can install Docker Desktop for a full graphical experience, or Docker Community Edition for a lightweight option.",
  dockerFound:
    "Docker is installed and running. Let's move on to configure your AI provider.",
  llmSelect:
    "Select your preferred AI provider. Anthropic Claude is recommended for the best experience. You can also use Google Gemini, OpenAI, or a local Ollama instance.",
  skillSelect:
    "Now let's choose which skills to install. Skills extend what OpenClaw can do. Recommended defaults are pre-selected. Skills requiring extra permissions will ask for your confirmation.",
  channelSetup:
    "Next, choose which messaging channels to connect. OpenClaw works best with at least one channel. Telegram is the easiest to set up.",
  githubSetup:
    "OpenClaw will automatically back up your configuration to a private GitHub repository. Please provide a Personal Access Token with repository permissions.",
  review:
    "Everything is configured. Please review your settings before we begin the installation.",
  installing:
    "Installing OpenClaw. This will take a moment. I will let you know when it's ready.",
  installingSkills:
    "Installing selected skills. This should only take a few seconds.",
  configuringChannels:
    "Applying channel configuration. Almost there.",
  complete:
    "OpenClaw is installed and ready to use. Your secure environment is now running.",
};

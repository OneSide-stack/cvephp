import type { V86 } from "v86";
import { clampText, randomToken, stripAnsi } from "./utils";

interface PendingWait {
  expression: RegExp;
  resolve: (value: string) => void;
  reject: (error: Error) => void;
  timeout: ReturnType<typeof setTimeout>;
  observed: string;
}

export interface CommandResult {
  command: string;
  output: string;
  exitCode: number;
  durationMs: number;
}

/** A real serial shell channel. It contains no command implementations. */
export class SerialChannel {
  private buffer = "";
  private listeners = new Set<(text: string) => void>();
  private waits = new Set<PendingWait>();
  private queue: Promise<unknown> = Promise.resolve();
  private pendingText = "";
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private decoder = new TextDecoder();
  private destroyed = false;
  private commandCancellations = new Set<(error: Error) => void>();

  constructor(private emulator: V86, onText: (text: string) => void) {
    this.listeners.add(onText);
    emulator.add_listener("serial0-output-byte", (byte: number) => {
      if (this.destroyed) return;
      const text = this.decoder.decode(new Uint8Array([byte]), { stream: true });
      if (text) this.accept(text);
    });
  }

  private accept(text: string): void {
    this.buffer = clampText(this.buffer + text, 256_000);
    this.pendingText += text;
    for (const wait of [...this.waits]) {
      wait.observed = clampText(wait.observed + text, 256_000);
      const match = wait.expression.exec(wait.observed);
      if (match) {
        clearTimeout(wait.timeout);
        this.waits.delete(wait);
        wait.resolve(wait.observed);
      }
    }
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => {
        this.flushTimer = null;
        const outgoing = this.pendingText;
        this.pendingText = "";
        if (outgoing) for (const listener of this.listeners) listener(outgoing);
      }, 16);
    }
  }

  getTranscript(): string {
    return this.buffer;
  }

  subscribe(listener: (text: string) => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  sendRaw(text: string): void {
    if (this.destroyed) throw new Error("Serial channel is closed");
    this.emulator.serial0_send(text);
  }

  waitFor(expression: RegExp, timeoutMs: number, includeExisting = true): Promise<string> {
    if (this.destroyed) return Promise.reject(new Error("Serial channel is closed"));
    return new Promise((resolve, reject) => {
      const observed = includeExisting ? this.buffer : "";
      if (expression.test(observed)) {
        resolve(observed);
        return;
      }
      const wait: PendingWait = {
        expression,
        observed,
        resolve,
        reject,
        timeout: setTimeout(() => {
          this.waits.delete(wait);
          reject(new Error(`Guest serial wait timed out after ${Math.round(timeoutMs / 1000)}s while looking for ${expression}. Last output: ${stripAnsi(wait.observed).slice(-800)}`));
        }, timeoutMs),
      };
      this.waits.add(wait);
    });
  }

  exec(command: string, timeoutMs = 30_000): Promise<CommandResult> {
    const run = () => this.executeNow(command, timeoutMs);
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => undefined);
    return result;
  }

  private executeNow(command: string, timeoutMs: number): Promise<CommandResult> {
    if (this.destroyed) return Promise.reject(new Error("Serial channel is closed"));
    if (command.includes("\u0000")) return Promise.reject(new Error("NUL is not valid in a serial command"));
    const id = randomToken(8);
    const begin = `__CR_${id}_BEGIN__`;
    const endPattern = new RegExp(`__CR_${id}_END:(\\d+)__`);
    const script = `printf '\\n__CR_%s_BEGIN__\\n' '${id}'\n{ ${command}\n}\n__cr_rc=$?\nprintf '\\n__CR_%s_END:%s__\\n' '${id}' \"$__cr_rc\"\n`;
    const started = performance.now();
    return new Promise((resolve, reject) => {
      let observed = "";
      let finished = false;
      let cancel!: (error: Error) => void;
      const finish = (callback: () => void) => {
        if (finished) return;
        finished = true;
        clearTimeout(timer);
        this.commandCancellations.delete(cancel);
        unsubscribe();
        callback();
      };
      const unsubscribe = this.subscribe((text) => {
        observed = clampText(observed + text, 1_200_000);
        const end = endPattern.exec(observed);
        if (!end) return;
        const beginIndex = observed.indexOf(begin);
        const endIndex = observed.lastIndexOf(end[0]);
        const rawOutput = beginIndex >= 0 ? observed.slice(beginIndex + begin.length, endIndex) : observed.slice(0, endIndex);
        const output = stripAnsi(rawOutput).replace(/^\n+|\n+$/g, "");
        const exitCode = Number(end[1]);
        finish(() => resolve({ command, output, exitCode, durationMs: Math.round(performance.now() - started) }));
      });
      const timer = setTimeout(() => {
        try { this.sendRaw("\u0003"); } catch { /* emulator may already be gone */ }
        finish(() => reject(new Error(`Guest command timed out after ${Math.round(timeoutMs / 1000)}s: ${command}. Output: ${stripAnsi(observed).slice(-800)}`)));
      }, timeoutMs);
      cancel = (error: Error) => finish(() => reject(error));
      this.commandCancellations.add(cancel);
      try {
        this.sendRaw(script);
      } catch (error) {
        finish(() => reject(error instanceof Error ? error : new Error(String(error))));
      }
    });
  }

  cancelCommands(error = new Error("Guest operation was cancelled")): void {
    for (const cancel of [...this.commandCancellations]) cancel(error);
  }

  destroy(): void {
    this.destroyed = true;
    if (this.flushTimer) clearTimeout(this.flushTimer);
    for (const wait of this.waits) {
      clearTimeout(wait.timeout);
      wait.reject(new Error("Guest was stopped"));
    }
    this.waits.clear();
    for (const cancel of [...this.commandCancellations]) cancel(new Error("Guest was stopped"));
    this.commandCancellations.clear();
    this.listeners.clear();
  }
}

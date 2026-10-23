import { describe, expect, it } from "vitest";
import type { V86 } from "v86";
import { SerialChannel } from "../src/lib/SerialChannel";

class FakeEmulator {
  private listeners = new Map<string, (value: number) => void>();
  sent = "";
  add_listener(event: string, listener: (value: number) => void) {
    this.listeners.set(event, listener);
  }
  serial0_send(text: string) {
    this.sent += text;
  }
  emit(text: string) {
    const listener = this.listeners.get("serial0-output-byte");
    if (!listener) throw new Error("serial listener was not registered");
    for (const byte of new TextEncoder().encode(text)) listener(byte);
  }
}

function asV86(fake: FakeEmulator): V86 {
  return fake as unknown as V86;
}

function commandId(fake: FakeEmulator): string {
  const ids = [...fake.sent.matchAll(/'([0-9a-f]{16})'/g)];
  const id = ids.at(-1)?.[1];
  if (!id) throw new Error(`No command identifier in ${fake.sent}`);
  return id;
}

describe("SerialChannel", () => {
  it("captures the real command output between unique shell markers", async () => {
    const fake = new FakeEmulator();
    const channel = new SerialChannel(asV86(fake), () => undefined);
    const pending = channel.exec("labctl ready", 1000);
    await Promise.resolve();
    const id = commandId(fake);
    // Include an echoed shell command before the actual marker to ensure the
    // parser does not treat terminal echo as the command's result.
    fake.emit(`printf '\\n__CR_%s_BEGIN__\\n' '${id}'\n`);
    fake.emit(`\n__CR_${id}_BEGIN__\n{"machine":"target","apache":"running"}\n__CR_${id}_END:0__\n__CR_${id}_DONE__\n`);
    const result = await pending;
    expect(result.exitCode).toBe(0);
    expect(result.output).toBe('{"machine":"target","apache":"running"}');
    expect(result.command).toBe("labctl ready");
    channel.destroy();
  });

  it("waits for the post-command TTY restore before completing", async () => {
    const fake = new FakeEmulator();
    const channel = new SerialChannel(asV86(fake), () => undefined);
    const pending = channel.exec("labctl tools", 1000);
    let completed = false;
    void pending.then(() => { completed = true; });
    await Promise.resolve();
    const id = commandId(fake);
    expect(fake.sent).toContain("stty -echo");
    expect(fake.sent).toContain('stty "$__cr_tty"');
    fake.emit(`\n__CR_${id}_BEGIN__\ncurl\t/usr/bin/curl\n__CR_${id}_END:0__\n`);
    await new Promise((resolve) => setTimeout(resolve, 30));
    expect(completed).toBe(false);
    fake.emit(`__CR_${id}_DONE__\n`);
    expect((await pending).output).toBe("curl\t/usr/bin/curl");
    channel.destroy();
  });

  it("rejects a pending command immediately when the guest is destroyed", async () => {
    const fake = new FakeEmulator();
    const channel = new SerialChannel(asV86(fake), () => undefined);
    const pending = channel.exec("sleep 999", 60_000);
    await Promise.resolve();
    channel.destroy();
    await expect(pending).rejects.toThrow("Guest was stopped");
  });

  it("serializes commands instead of interleaving their shell input", async () => {
    const fake = new FakeEmulator();
    const channel = new SerialChannel(asV86(fake), () => undefined);
    const first = channel.exec("first", 1000);
    const second = channel.exec("second", 1000);
    await Promise.resolve();
    const firstId = commandId(fake);
    expect(fake.sent).toContain("first");
    expect(fake.sent).not.toContain("second");
    fake.emit(`\n__CR_${firstId}_BEGIN__\none\n__CR_${firstId}_END:0__\n__CR_${firstId}_DONE__\n`);
    await first;
    await Promise.resolve();
    const secondId = commandId(fake);
    expect(fake.sent).toContain("second");
    fake.emit(`\n__CR_${secondId}_BEGIN__\ntwo\n__CR_${secondId}_END:0__\n__CR_${secondId}_DONE__\n`);
    expect((await second).output).toBe("two");
    channel.destroy();
  });
});

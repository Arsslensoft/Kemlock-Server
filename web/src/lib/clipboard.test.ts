import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

type Clipboard = typeof import('./clipboard');

/** A browser clipboard: writing an empty string can be refused (the page has no focus), reading can be allowed. */
function browser(options: { readPermission?: 'granted' | 'prompt' | 'unsupported' } = {}) {
  const state = { value: '', refuseEmpty: false };
  const writeText = vi.fn(async (text: string) => {
    if (text === '' && state.refuseEmpty) throw new DOMException('Document is not focused.', 'NotAllowedError');
    state.value = text;
  });
  const readText = vi.fn(async () => state.value);
  const permission = options.readPermission ?? 'prompt';
  const query = vi.fn(async () => {
    if (permission === 'unsupported') throw new TypeError('clipboard-read is not a valid permission');
    return { state: permission };
  });
  Object.defineProperty(navigator, 'clipboard', { value: { writeText, readText }, configurable: true });
  Object.defineProperty(navigator, 'permissions', { value: { query }, configurable: true });
  return { state, writeText, readText, query };
}

let loaded: Clipboard | undefined;

/** A fresh copy of the module, so one test's pending clear and listeners are not the next one's. */
async function load(): Promise<Clipboard> {
  vi.resetModules();
  loaded = await import('./clipboard');
  return loaded;
}

const THIRTY = 30_000;

beforeEach(() => vi.useFakeTimers());
afterEach(async () => {
  await loaded?.clearCopiedSecret();
  loaded = undefined;
  vi.useRealTimers();
});

describe('copying a secret', () => {
  it('takes it off the clipboard 30 seconds later', async () => {
    const clip = browser();
    const { copyText } = await load();
    expect(await copyText('hunter2', { secret: true })).toBe(true);
    await vi.advanceTimersByTimeAsync(THIRTY - 1);
    expect(clip.state.value).toBe('hunter2');
    await vi.advanceTimersByTimeAsync(1);
    expect(clip.state.value).toBe('');
  });

  it('leaves a plain copy alone, and a plain copy after a secret cancels its clear', async () => {
    const clip = browser();
    const { copyText } = await load();
    await copyText('https://example.org');
    await vi.advanceTimersByTimeAsync(THIRTY * 2);
    expect(clip.state.value).toBe('https://example.org');
    await copyText('hunter2', { secret: true });
    await copyText('plain');
    await vi.advanceTimersByTimeAsync(THIRTY * 2);
    expect(clip.state.value).toBe('plain');
  });

  it('clears only the newest secret, once, when copies follow each other', async () => {
    const clip = browser();
    const { copyText } = await load();
    await copyText('first', { secret: true });
    await vi.advanceTimersByTimeAsync(20_000);
    await copyText('second', { secret: true });
    await vi.advanceTimersByTimeAsync(20_000);
    expect(clip.state.value).toBe('second');
    await vi.advanceTimersByTimeAsync(10_000);
    expect(clip.state.value).toBe('');
    expect(clip.writeText.mock.calls.filter(([text]) => text === '')).toHaveLength(1);
  });

  it('reports a copy the browser refused, and clears nothing later', async () => {
    const clip = browser();
    clip.writeText.mockRejectedValueOnce(new Error('denied'));
    const { copyText } = await load();
    expect(await copyText('hunter2', { secret: true })).toBe(false);
    await vi.advanceTimersByTimeAsync(THIRTY * 2);
    expect(clip.writeText).toHaveBeenCalledTimes(1);
  });
});

describe('a clear the browser refuses because the page has no focus', () => {
  it('is tried again when the page is focused, and then done', async () => {
    const clip = browser();
    const { copyText } = await load();
    await copyText('hunter2', { secret: true });
    clip.state.refuseEmpty = true;
    await vi.advanceTimersByTimeAsync(THIRTY);
    expect(clip.state.value).toBe('hunter2');
    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clip.state.value).toBe('hunter2');
    clip.state.refuseEmpty = false;
    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clip.state.value).toBe('');
    // Done: another focus does not write again.
    const writes = clip.writeText.mock.calls.length;
    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clip.writeText).toHaveBeenCalledTimes(writes);
  });

  it('is tried again when the tab comes back into view', async () => {
    const clip = browser();
    const { copyText } = await load();
    await copyText('hunter2', { secret: true });
    clip.state.refuseEmpty = true;
    await vi.advanceTimersByTimeAsync(THIRTY);
    clip.state.refuseEmpty = false;
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clip.state.value).toBe('');
  });

  it('is not tried before the time is up, however often the page is focused', async () => {
    const clip = browser();
    const { copyText } = await load();
    await copyText('hunter2', { secret: true });
    window.dispatchEvent(new Event('focus'));
    document.dispatchEvent(new Event('visibilitychange'));
    await vi.advanceTimersByTimeAsync(10_000);
    expect(clip.state.value).toBe('hunter2');
  });
});

describe('only what this page put there', () => {
  it('leaves the clipboard alone when reading is allowed and it holds something else now', async () => {
    const clip = browser({ readPermission: 'granted' });
    const { copyText } = await load();
    await copyText('hunter2', { secret: true });
    clip.state.value = 'something the person copied elsewhere';
    await vi.advanceTimersByTimeAsync(THIRTY);
    expect(clip.state.value).toBe('something the person copied elsewhere');
    expect(clip.writeText).toHaveBeenCalledTimes(1);
  });

  it('clears it when reading is allowed and it still holds the secret', async () => {
    const clip = browser({ readPermission: 'granted' });
    const { copyText } = await load();
    await copyText('hunter2', { secret: true });
    await vi.advanceTimersByTimeAsync(THIRTY);
    expect(clip.readText).toHaveBeenCalled();
    expect(clip.state.value).toBe('');
  });

  it('never asks for permission to read, and clears its own pending copy where reading is not allowed', async () => {
    for (const readPermission of ['prompt', 'unsupported'] as const) {
      const clip = browser({ readPermission });
      const { copyText } = await load();
      await copyText('hunter2', { secret: true });
      await vi.advanceTimersByTimeAsync(THIRTY);
      expect(clip.readText).not.toHaveBeenCalled();
      expect(clip.state.value).toBe('');
    }
  });

  it('does nothing at all when there is nothing pending', async () => {
    const clip = browser();
    const { clearCopiedSecret } = await load();
    await clearCopiedSecret();
    window.dispatchEvent(new Event('focus'));
    expect(clip.writeText).not.toHaveBeenCalled();
    expect(clip.readText).not.toHaveBeenCalled();
  });
});

describe('locking, signing out and leaving', () => {
  it('clears at once when the vault locks or the person signs out, without waiting the 30 seconds', async () => {
    const clip = browser();
    const { copyText, clearCopiedSecret } = await load();
    await copyText('hunter2', { secret: true });
    await vi.advanceTimersByTimeAsync(5_000);
    await clearCopiedSecret();
    expect(clip.state.value).toBe('');
    // The timer is cancelled with it.
    clip.state.value = 'next thing';
    await vi.advanceTimersByTimeAsync(THIRTY);
    expect(clip.state.value).toBe('next thing');
  });

  it('keeps trying when the lock came while the page had no focus', async () => {
    const clip = browser();
    const { copyText, clearCopiedSecret } = await load();
    await copyText('hunter2', { secret: true });
    clip.state.refuseEmpty = true;
    await clearCopiedSecret();
    expect(clip.state.value).toBe('hunter2');
    clip.state.refuseEmpty = false;
    window.dispatchEvent(new Event('focus'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clip.state.value).toBe('');
  });

  it('clears when the page is going away', async () => {
    const clip = browser();
    const { copyText } = await load();
    await copyText('hunter2', { secret: true });
    window.dispatchEvent(new Event('pagehide'));
    await vi.advanceTimersByTimeAsync(0);
    expect(clip.state.value).toBe('');
  });
});

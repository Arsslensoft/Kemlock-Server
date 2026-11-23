import { afterEach, describe, expect, it, vi } from 'vitest';
import { spawnWorker } from './spawn-worker';

class TrustedScriptURLStub {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('spawnWorker', () => {
  it('starts the worker with a URL the kemlock policy made, as a module', () => {
    const created: Array<{ name: string }> = [];
    const started: Array<{ url: unknown; options: unknown }> = [];
    vi.stubGlobal('trustedTypes', {
      createPolicy: (name: string, rules: { createScriptURL?: (input: string) => string }) => {
        created.push({ name });
        return {
          createScriptURL: (input: string) =>
            new TrustedScriptURLStub(rules.createScriptURL?.(input) ?? input),
        };
      },
    });
    vi.stubGlobal(
      'Worker',
      class {
        constructor(url: unknown, options: unknown) {
          started.push({ url, options });
        }
      },
    );
    spawnWorker('/assets/worker-abc.js');
    spawnWorker('/assets/worker-abc.js');
    expect(started).toHaveLength(2);
    // Not a string the page typed: a value the policy returned, resolved against the origin.
    const first = started[0];
    expect(first?.url).toBeInstanceOf(TrustedScriptURLStub);
    expect(String(first?.url)).toBe(`${globalThis.location.origin}/assets/worker-abc.js`);
    expect(first?.options).toEqual({ type: 'module' });
    // One policy for the page: asking twice never creates a second `kemlock`.
    expect(created.map((c) => c.name)).toEqual(['kemlock']);
  });

  it('refuses a script from another origin', () => {
    vi.stubGlobal('trustedTypes', {
      createPolicy: (_name: string, rules: { createScriptURL?: (input: string) => string }) => ({
        createScriptURL: (input: string) => rules.createScriptURL?.(input) ?? input,
      }),
    });
    vi.stubGlobal('Worker', class {});
    expect(() => spawnWorker('https://evil.example/worker.js')).toThrow(/refusing a script/);
  });

  it('passes the URL as it is where Trusted Types does not exist', () => {
    vi.stubGlobal('trustedTypes', undefined);
    const started: unknown[] = [];
    vi.stubGlobal(
      'Worker',
      class {
        constructor(url: unknown) {
          started.push(url);
        }
      },
    );
    spawnWorker('/assets/worker-abc.js');
    expect(started).toEqual(['/assets/worker-abc.js']);
  });
});

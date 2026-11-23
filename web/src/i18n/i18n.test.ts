import { IntlMessageFormat } from 'intl-messageformat';
import { describe, expect, it } from 'vitest';
import { catalogues, messages } from './index';
import en from './en.json';

// The sources are read through Vite, not the file system, so the test does not depend on where the
// checkout is mounted or on what `import.meta.url` looks like in the test runner.
const sources = import.meta.glob(['../**/*.{ts,tsx}', '!../**/*.test.*'], {
  query: '?raw',
  import: 'default',
  eager: true,
}) as Record<string, string>;

describe('messages', () => {
  const ids = Object.keys(messages);

  it('are all valid ICU', () => {
    for (const id of ids) {
      const text = messages[id] as string;
      expect(() => new IntlMessageFormat(text, 'en'), id).not.toThrow();
    }
  });

  it('cover every id the code uses', () => {
    const used = new Set<string>();
    // Every first segment of an id (`spaces`, `send`, ...) is a prefix whose uses must be defined.
    const prefixes = new Set(ids.map((id) => id.split('.')[0] as string));
    for (const code of Object.values(sources)) {
      const idPattern = new RegExp(String.raw`['"]((?:${[...prefixes].join('|')})(?:\.[A-Za-z0-9]+)+)['"]`, 'g');
      for (const match of code.matchAll(idPattern)) {
        used.add(match[1] as string);
      }
    }
    const missing = [...used].filter((id) => !(id in messages));
    expect(missing).toEqual([]);
  });

  it('are each defined in one catalogue only', () => {
    const seen = new Map<string, string>();
    for (const [name, catalogue] of Object.entries(catalogues)) {
      for (const id of Object.keys(catalogue)) {
        expect(seen.get(id), `${id} is in ${seen.get(id)} and ${name}`).toBeUndefined();
        seen.set(id, name);
      }
    }
  });

  it('have the strength ladder the meter reads', () => {
    for (const n of [0, 1, 2, 3, 4]) {
      expect(en).toHaveProperty([`setup.admin.strength.${n}`]);
      expect(en).toHaveProperty([`newItem.strength.${n}`]);
    }
  });

  it('keep rich tags to the ones useRich renders', () => {
    for (const id of ids) {
      const tags = [...(messages[id] as string).matchAll(/<\/?(\w+)>/g)].map((m) => m[1]);
      for (const tag of tags) expect(['b', 'code', 'mono'], `${id}: <${tag}>`).toContain(tag);
    }
  });
});

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Plugin } from 'vite';

/**
 * Adds a Subresource Integrity hash to every script and stylesheet tag in the built index.html
 * (design: Security, "SRI"). Vite writes the tags; this runs last, over the files as they are on
 * disk. It must not hash the bundle in `transformIndexHtml`: Vite still rewrites the entry chunk
 * after that hook (it fills in the preload dependency lists of the dynamic imports), so a hash
 * taken there does not match the bytes the server serves and the browser blocks the entry script.
 */
export function integrityPlugin(): Plugin {
  return {
    name: 'kemlock-integrity',
    apply: 'build',
    writeBundle: {
      order: 'post',
      handler(options) {
        const dir = options.dir;
        if (!dir) return;
        const indexPath = join(dir, 'index.html');
        let html: string;
        try {
          html = readFileSync(indexPath, 'utf8');
        } catch {
          return; // not an HTML build
        }
        const stamped = html.replace(/<(?:script|link)\b[^>]*>/g, (tag) => {
          if (tag.includes(' integrity=')) return tag;
          const file = /\b(?:src|href)="\/?([^"]+)"/.exec(tag)?.[1];
          if (!file?.startsWith('assets/')) return tag;
          const digest = createHash('sha384').update(readFileSync(join(dir, file))).digest('base64');
          return tag.replace(/\s*\/?>$/, (end) => ` integrity="sha384-${digest}"${end}`);
        });
        writeFileSync(indexPath, stamped);
      },
    },
  };
}

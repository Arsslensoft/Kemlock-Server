// Starts a fresh kemlock-server for the journeys and reads the setup code from its log.
//
//   KEMLOCK_BIN      path to the server binary (default ../target/debug/kemlock-server)
//   BASE_URL         use a server that is already running instead (E2E_BASE_URL works too). It must
//                    have been started with DOMAIN set to this same address. Give E2E_SETUP_CODE too
//                    when it is a fresh server and the setup journey is to run
//   E2E_PORT         port for the server this starts (default 18080)
import { type ChildProcess, spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { STATE_FILE, type E2EState } from './state';

const ANSI = /\u001b\[[0-9;]*m/g;

function defaultBinary(): string {
  const here = fileURLToPath(new URL('.', import.meta.url));
  const name = process.platform === 'win32' ? 'kemlock-server.exe' : 'kemlock-server';
  return resolve(here, '..', '..', 'target', 'debug', name);
}

export default async function globalSetup(): Promise<() => Promise<void>> {
  const external = process.env['BASE_URL'] ?? process.env['E2E_BASE_URL'];
  if (external) {
    // The journeys that make the admin need the code of a fresh server; the SSO journey does not.
    writeState({
      baseURL: external.replace(/\/+$/, ''),
      setupCode: process.env['E2E_SETUP_CODE'] ?? '',
    });
    return async () => undefined;
  }

  const binary = process.env['KEMLOCK_BIN'] ?? defaultBinary();
  if (!existsSync(binary)) {
    throw new Error(
      `No server binary at ${binary}. Run \`npm run build\` in web/, then ` +
        '`cargo build -p kemlock-server --features web`, or set KEMLOCK_BIN.',
    );
  }
  const port = process.env['E2E_PORT'] ?? '18080';
  const baseURL = `http://localhost:${port}`;
  const data = mkdtempSync(join(tmpdir(), 'kemlock-e2e-'));
  mkdirSync(data, { recursive: true });

  const child: ChildProcess = spawn(binary, [], {
    env: {
      ...process.env,
      DOMAIN: baseURL,
      // The journeys sign in and step up many times a minute from one address; the per-IP
      // sign-in limit (10 a minute) is for people, not for a test run.
      KEMLOCK_RATE_SIGN_IN_PER_MINUTE: process.env['KEMLOCK_RATE_SIGN_IN_PER_MINUTE'] ?? '600',
      DATA_FOLDER: data,
      ROCKET_ADDRESS: '127.0.0.1',
      ROCKET_PORT: port,
      LOG_LEVEL: 'info',
      NO_COLOR: '1',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const code = await new Promise<string>((resolveCode, reject) => {
    let seen = '';
    const timer = setTimeout(
      () => reject(new Error(`the server printed no setup code in 60 s:\n${seen}`)),
      60_000,
    );
    const onData = (chunk: Buffer) => {
      seen += chunk.toString('utf8').replace(ANSI, '');
      const match = /enter the setup code ([0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4})/.exec(seen);
      if (match?.[1]) {
        clearTimeout(timer);
        resolveCode(match[1]);
      }
    };
    child.stdout?.on('data', onData);
    child.stderr?.on('data', onData);
    child.once('exit', (status) => {
      clearTimeout(timer);
      reject(new Error(`the server exited (${status}) before printing a setup code:\n${seen}`));
    });
  });

  writeState({ baseURL, setupCode: code });
  return async () => {
    child.removeAllListeners('exit');
    child.kill();
    rmSync(data, { recursive: true, force: true });
  };
}

function writeState(state: Pick<E2EState, 'baseURL' | 'setupCode'>): void {
  writeFileSync(STATE_FILE, `${JSON.stringify(state)}\n`);
}

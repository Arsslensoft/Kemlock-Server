// The Bitwarden CLI against kemlock-server: login, sync, create, edit, delete.
//
//   SERVER_URL=http://127.0.0.1:8080 BW_CLI=bw node bw-cli.mjs
//
// The account is made through the web vault's registration routes with Bitwarden's real
// cryptography (the CLI derives the same keys from the password), using only Node's `crypto`. The
// server needs SIGNUPS_ALLOWED=true and SIGNUPS_VERIFY=false, as the apps' own tests do
// (mobile/test/vaultwarden_server/server_kit.dart:57-90). The tested version is the CLI 2026.6.0,
// the one the Kemlock app's fixtures were made with (fixtures/SOURCE.md).
import assert from 'node:assert/strict';
import {
  createCipheriv,
  createHmac,
  generateKeyPairSync,
  pbkdf2Sync,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const server = (process.env.SERVER_URL ?? 'http://127.0.0.1:8080').replace(/\/+$/, '');
const bwPath = process.env.BW_CLI ?? 'bw';
const password = 'correct horse battery';
const iterations = 100000;

// ─── Bitwarden's cryptography, as the clients do it ──────────────────────────

function hmac(key, ...parts) {
  const h = createHmac('sha256', key);
  for (const part of parts) h.update(part);
  return h.digest();
}

/** PBKDF2-SHA256 of the password, salted with the lower-cased email. */
function masterKey(email) {
  return pbkdf2Sync(Buffer.from(password, 'utf8'), Buffer.from(email.trim().toLowerCase(), 'utf8'), iterations, 32, 'sha256');
}

/** The hash sent to the server: one more round of PBKDF2, with the password as the salt. */
function masterHash(key) {
  return pbkdf2Sync(key, Buffer.from(password, 'utf8'), 1, 32, 'sha256').toString('base64');
}

/** HKDF-Expand only, the master key as the pseudo-random key: `enc` and `mac`. */
function stretch(key) {
  return { enc: hmac(key, 'enc', Buffer.from([1])), mac: hmac(key, 'mac', Buffer.from([1])) };
}

/** An encrypted string of type 2: `2.<iv>|<ciphertext>|<mac>`. */
function encrypt(plain, { enc, mac }) {
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', enc, iv);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  const tag = hmac(mac, iv, ciphertext);
  return `2.${iv.toString('base64')}|${ciphertext.toString('base64')}|${tag.toString('base64')}`;
}

async function post(path, body) {
  const response = await fetch(`${server}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  assert.ok(response.ok, `POST ${path}: ${response.status} ${text}`);
  return text;
}

async function register() {
  const email = `bw-cli-${Date.now()}-${randomUUID().slice(0, 8)}@example.com`;
  const key = masterKey(email);
  const userKey = randomBytes(64);
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  const userKeys = { enc: userKey.subarray(0, 32), mac: userKey.subarray(32) };
  const token = JSON.parse(
    await post('/identity/accounts/register/send-verification-email', {
      email,
      name: 'Bitwarden CLI contract',
      receiveMarketingEmails: false,
    }),
  );
  assert.equal(typeof token, 'string', 'send-verification-email answers the token as a JSON string');
  await post('/identity/accounts/register/finish', {
    email,
    emailVerificationToken: token,
    masterPasswordHash: masterHash(key),
    masterPasswordHint: null,
    userSymmetricKey: encrypt(userKey, stretch(key)),
    userAsymmetricKeys: {
      publicKey: publicKey.toString('base64'),
      encryptedPrivateKey: encrypt(privateKey, userKeys),
    },
    kdf: 0,
    kdfIterations: iterations,
  });
  return email;
}

// ─── The CLI ─────────────────────────────────────────────────────────────────

const appData = mkdtempSync(join(tmpdir(), 'kemlock-bw-'));
let session;

function bw(args, input) {
  const full = session ? [...args, '--session', session] : args;
  return execFileSync(bwPath, full, {
    input,
    encoding: 'utf8',
    env: { ...process.env, BITWARDENCLI_APPDATA_DIR: appData, BW_NOINTERACTION: 'true' },
    stdio: ['pipe', 'pipe', 'pipe'],
  }).trim();
}

/** An item as `bw create item` takes it, base64 of its JSON. */
function encode(item) {
  return bw(['encode'], JSON.stringify(item));
}

function step(text) {
  console.log(`bw: ${text}`);
}

try {
  const email = await register();
  step(`registered ${email}`);

  bw(['config', 'server', server]);
  session = bw(['login', email, password, '--raw']);
  assert.ok(session.length > 20, 'login prints a session key');
  step('login');

  assert.match(bw(['sync']), /Syncing complete/i, 'sync reports it is complete');
  assert.deepEqual(JSON.parse(bw(['list', 'items'])), [], 'a new vault has no items');
  step('sync');

  const made = JSON.parse(
    bw(
      ['create', 'item', encode({
        type: 1,
        name: 'CLI item',
        notes: 'ünïcode note ✓',
        favorite: false,
        fields: [{ name: 'Text field', value: 'visible', type: 0 }],
        login: {
          username: 'cli-user',
          password: 'hunter2',
          totp: 'otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub',
          uris: [{ uri: 'https://example.com', match: null }],
        },
        reprompt: 0,
      })],
    ),
  );
  assert.equal(made.name, 'CLI item');
  const id = made.id;
  const fetched = JSON.parse(bw(['get', 'item', id]));
  assert.equal(fetched.notes, 'ünïcode note ✓');
  assert.equal(fetched.login.password, 'hunter2');
  assert.equal(fetched.fields[0].value, 'visible');
  step('create');

  const totp = bw(['get', 'totp', id]);
  assert.match(totp, /^\d{6}$/, 'the CLI derives a code from the stored secret');

  fetched.name = 'CLI item, edited';
  fetched.login.password = 'correct-horse';
  const edited = JSON.parse(bw(['edit', 'item', id, encode(fetched)]));
  assert.equal(edited.name, 'CLI item, edited');
  bw(['sync', '--force']);
  const again = JSON.parse(bw(['get', 'item', id]));
  assert.equal(again.name, 'CLI item, edited');
  assert.equal(again.login.password, 'correct-horse');
  assert.equal(again.fields[0].value, 'visible', 'the edit kept the other values');
  step('edit');

  bw(['delete', 'item', id]);
  const trash = JSON.parse(bw(['list', 'items', '--trash']));
  assert.ok(trash.some((item) => item.id === id), 'a deleted item is in the trash');
  bw(['restore', 'item', id]);
  assert.ok(JSON.parse(bw(['list', 'items'])).some((item) => item.id === id), 'restored');
  bw(['delete', 'item', id, '--permanent']);
  assert.deepEqual(JSON.parse(bw(['list', 'items'])), [], 'the item is gone');
  assert.throws(() => bw(['get', 'item', id]), Error, 'a permanently deleted item is not found');
  step('delete');

  // A second sign-in from the same data folder: the stored refresh token and the login again
  bw(['logout']);
  session = undefined;
  session = bw(['login', email, password, '--raw']);
  assert.deepEqual(JSON.parse(bw(['list', 'items'])), [], 'the vault is the same after a new login');
  step('login again');
  console.log('bw: all steps passed');
} finally {
  rmSync(appData, { recursive: true, force: true });
}

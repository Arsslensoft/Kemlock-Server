// Regenerates the KDBX fixtures:
//
//   node make.mjs
//
//   v3-aes.kdbx              KDBX 3.1: AES-KDF, AES-256-CBC, gzip, hashed blocks, Salsa20 inside
//   v4-argon2d.kdbx          KDBX 4.0: Argon2d, AES-256-CBC, ChaCha20 inside, an attachment;
//                            opened with the password and fixture.keyx together
//   v4-aes-chacha20.kdbx     KDBX 4.0: AES-KDF, ChaCha20 outside and inside, a KeePassXC passkey
//   fixture.keyx             an XML (version 2.0) key file
//
// Every file holds the same made-up database (see `database()`), password "correct horse", with
// small key-derivation costs so the tests are fast. The "random" bytes come from fixed labels, so
// the output is the same every time. The script reads each file back with a separate reader
// written from the file format description, and checks the plaintext it finds.
import { createCipheriv, createDecipheriv, createHash, createHmac, argon2Sync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

const here = dirname(fileURLToPath(import.meta.url));
const PASSWORD = "correct horse";

const sha256 = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();
const sha512 = (...parts) => createHash("sha512").update(Buffer.concat(parts)).digest();
const hmac256 = (key, ...parts) => createHmac("sha256", key).update(Buffer.concat(parts)).digest();
const fixed = (label, n) => {
  let out = Buffer.alloc(0);
  for (let i = 0; out.length < n; i++) out = Buffer.concat([out, sha256(Buffer.from(`${label}/${i}`))]);
  return out.subarray(0, n);
};
const u16 = (n) => {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(n);
  return b;
};
const u32 = (n) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
};
const u64 = (n) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
};

// ---- Salsa20 (node's crypto has no Salsa20) ----------------------------------------------------

const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

function salsa20Block(key, nonce, counter) {
  const sigma = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
  const w = (b, i) => b.readUInt32LE(i * 4);
  const x = [
    sigma[0], w(key, 0), w(key, 1), w(key, 2),
    w(key, 3), sigma[1], w(nonce, 0), w(nonce, 1),
    counter % 2 ** 32, Math.floor(counter / 2 ** 32), sigma[2], w(key, 4),
    w(key, 5), w(key, 6), w(key, 7), sigma[3],
  ];
  const input = x.slice();
  const qr = (a, b, c, d) => {
    x[b] = (x[b] ^ rotl((x[a] + x[d]) >>> 0, 7)) >>> 0;
    x[c] = (x[c] ^ rotl((x[b] + x[a]) >>> 0, 9)) >>> 0;
    x[d] = (x[d] ^ rotl((x[c] + x[b]) >>> 0, 13)) >>> 0;
    x[a] = (x[a] ^ rotl((x[d] + x[c]) >>> 0, 18)) >>> 0;
  };
  for (let i = 0; i < 10; i++) {
    qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11);
    qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14);
  }
  const out = Buffer.alloc(64);
  for (let i = 0; i < 16; i++) out.writeUInt32LE((x[i] + input[i]) >>> 0, i * 4);
  return out;
}

// A stream of keystream bytes that XORs whatever it is given, in order.
class Stream {
  constructor(next) {
    this.next = next;
    this.buffer = Buffer.alloc(0);
  }
  xor(data) {
    while (this.buffer.length < data.length) this.buffer = Buffer.concat([this.buffer, this.next()]);
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) out[i] = data[i] ^ this.buffer[i];
    this.buffer = this.buffer.subarray(data.length);
    return out;
  }
}

function salsaStream(protectedStreamKey) {
  const key = sha256(protectedStreamKey);
  const nonce = Buffer.from("E830094B97205D2A", "hex");
  let counter = 0;
  return new Stream(() => salsa20Block(key, nonce, counter++));
}

function chachaStream(protectedStreamKey) {
  const h = sha512(protectedStreamKey);
  const cipher = createCipheriv("chacha20", h.subarray(0, 32), Buffer.concat([Buffer.alloc(4), h.subarray(32, 44)]));
  return new Stream(() => cipher.update(Buffer.alloc(64)));
}

// ECRYPT Salsa20/20, 256-bit key 80 00 .. 00, zero nonce: first 64 bytes of the stream.
{
  const key = Buffer.alloc(32);
  key[0] = 0x80;
  const got = salsa20Block(key, Buffer.alloc(8), 0).toString("hex").toUpperCase();
  const want =
    "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117";
  if (got !== want) throw new Error(`Salsa20 self-check failed: ${got}`);
}

// ---- The database ------------------------------------------------------------------------------

const xml = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
const uuid = (label) => fixed(`uuid ${label}`, 16).toString("base64");

function p256Pem() {
  const prefix = Buffer.from("308187020100301306072a8648ce3d020106082a8648ce3d030107", "hex");
  const body = Buffer.concat([
    Buffer.from("046d306b0201010420", "hex"),
    fixed("passkey d", 32),
    Buffer.from("a144034200", "hex"),
    Buffer.concat([Buffer.from([4]), fixed("passkey xy", 64)]),
  ]);
  const der = Buffer.concat([prefix, body]);
  return `-----BEGIN PRIVATE KEY-----\n${der.toString("base64")}\n-----END PRIVATE KEY-----\n`;
}

/** The XML of the database; `protect` encrypts a protected value, called in document order. */
function database({ protect, attachment, passkey }) {
  const str = (key, value, isProtected = false) =>
    isProtected
      ? `<String><Key>${xml(key)}</Key><Value Protected="True">${protect(value)}</Value></String>`
      : `<String><Key>${xml(key)}</Key><Value>${xml(value)}</Value></String>`;
  const times = (created, modified) =>
    `<Times><CreationTime>${created}</CreationTime><LastModificationTime>${modified}</LastModificationTime>` +
    `<LastAccessTime>${modified}</LastAccessTime><ExpiryTime>${modified}</ExpiryTime><Expires>False</Expires>` +
    `<UsageCount>0</UsageCount><LocationChanged>${created}</LocationChanged></Times>`;
  const entry = (id, inner) => `<Entry><UUID>${uuid(id)}</UUID><IconID>0</IconID>${inner}</Entry>`;

  const mailCreated = "2024-01-02T03:04:05Z";
  const mail = entry(
    "mail",
    `<Tags>mail;personal</Tags>${times(mailCreated, "2024-03-04T05:06:07Z")}` +
      [
        str("Title", "Example Mail"),
        str("UserName", "ada@example.com"),
        str("Password", "hunter2-current", true),
        str("URL", "https://mail.example.com"),
        str("Notes", "Recovery codes in the drawer"),
        str("otp", "otpauth://totp/Mail:ada?secret=JBSWY3DPEHPK3PXP&issuer=Mail", true),
        str("Account ID", "12345"),
        str("Security PIN", "9876", true),
      ].join("") +
      (attachment ? `<Binary><Key>recovery.txt</Key><Value Ref="0"/></Binary>` : "") +
      `<History>${entry(
        "mail",
        times(mailCreated, "2024-02-01T00:00:00Z") +
          [str("Title", "Example Mail"), str("UserName", "ada@example.com"), str("Password", "old-pass", true)].join(""),
      )}</History>`,
  );
  const wifi = entry(
    "wifi",
    times("2024-01-03T00:00:00Z", "2024-01-03T00:00:00Z") +
      str("Title", "Wifi note") +
      str("Notes", "SSID: home, password: abc"),
  );
  const passkeyEntry = passkey
    ? entry(
        "passkey",
        times("2024-01-04T00:00:00Z", "2024-01-04T00:00:00Z") +
          [
            str("Title", "Passkey site"),
            str("UserName", "ada"),
            str("URL", "https://passkey.example"),
            str("KPEX_PASSKEY_CREDENTIAL_ID", "AQIDBA"),
            str("KPEX_PASSKEY_PRIVATE_KEY_PEM", p256Pem(), true),
            str("KPEX_PASSKEY_RELYING_PARTY", "passkey.example"),
            str("KPEX_PASSKEY_USERNAME", "ada"),
            str("KPEX_PASSKEY_USER_HANDLE", "BQYHCA"),
          ].join(""),
      )
    : "";
  const group = (id, name, inner) =>
    `<Group><UUID>${uuid(id)}</UUID><Name>${xml(name)}</Name><IconID>48</IconID><IsExpanded>True</IsExpanded>${inner}</Group>`;
  const vpn = entry(
    "vpn",
    times("2024-01-05T00:00:00Z", "2024-01-05T00:00:00Z") +
      [
        str("Title", "Office VPN"),
        str("UserName", "bob"),
        str("Password", "vpn-secret", true),
        str("URL", "vpn.example.org"),
      ].join(""),
  );
  const deleted = entry(
    "deleted",
    times("2024-01-06T00:00:00Z", "2024-01-06T00:00:00Z") + str("Title", "Deleted login") + str("UserName", "gone"),
  );
  return (
    `<?xml version="1.0" encoding="utf-8" standalone="yes"?>\n<KeePassFile><Meta><Generator>kemlock fixtures</Generator>` +
    `<DatabaseName>Fixture</DatabaseName><RecycleBinEnabled>True</RecycleBinEnabled>` +
    `<RecycleBinUUID>${uuid("bin")}</RecycleBinUUID></Meta><Root>` +
    group(
      "root",
      "Fixture DB",
      mail + wifi + passkeyEntry + group("work", "Work", group("vpn-group", "VPN", vpn)) + group("bin", "Recycle Bin", deleted),
    ) +
    `</Root></KeePassFile>`
  );
}

const EXPECTED = ["Example Mail", "hunter2-current", "old-pass", "9876", "vpn-secret", "JBSWY3DPEHPK3PXP", "Deleted login"];

// ---- Keys --------------------------------------------------------------------------------------

const keyFileBytes = fixed("key file", 32);
function keyFileXml() {
  const hex = keyFileBytes.toString("hex").toUpperCase();
  const words = hex.match(/.{8}/g);
  const hash = sha256(keyFileBytes).subarray(0, 4).toString("hex").toUpperCase();
  return (
    `<?xml version="1.0" encoding="utf-8"?>\n<KeyFile>\n\t<Meta>\n\t\t<Version>2.0</Version>\n\t</Meta>\n\t<Key>\n` +
    `\t\t<Data Hash="${hash}">\n\t\t\t${words.slice(0, 4).join(" ")}\n\t\t\t${words.slice(4).join(" ")}\n\t\t</Data>\n\t</Key>\n</KeyFile>\n`
  );
}

const compositeKey = (password, keyBytes) =>
  sha256(sha256(Buffer.from(password)), ...(keyBytes ? [keyBytes] : []));

function aesKdf(composite, seed, rounds) {
  const halves = [composite.subarray(0, 16), composite.subarray(16)].map((half) => {
    const ecb = createCipheriv("aes-256-ecb", seed, null);
    ecb.setAutoPadding(false);
    let block = half;
    for (let i = 0; i < rounds; i++) block = ecb.update(block);
    return block;
  });
  return sha256(...halves);
}

// ---- KDBX 3.1 ----------------------------------------------------------------------------------

const AES256 = Buffer.from("31c1f2e6bf714350be5805216afc5aff", "hex");
const CHACHA20 = Buffer.from("d6038a2b8b6f4cb5a524339a31dbb59a", "hex");
const SIGNATURE = Buffer.from("03d9a29a67fb4bb5", "hex");

function buildV3() {
  const masterSeed = fixed("v3 master seed", 32);
  const transformSeed = fixed("v3 transform seed", 32);
  const iv = fixed("v3 iv", 16);
  const streamKey = fixed("v3 stream key", 32);
  const startBytes = fixed("v3 start bytes", 32);
  const rounds = 6000;

  const stream = salsaStream(streamKey);
  const body = gzipSync(
    Buffer.from(database({ protect: (v) => stream.xor(Buffer.from(v)).toString("base64"), attachment: false, passkey: false })),
  );
  const blocks = [];
  for (let at = 0, index = 0; at < body.length; at += 600, index++) {
    const chunk = body.subarray(at, at + 600);
    blocks.push(u32(index), sha256(chunk), u32(chunk.length), chunk);
  }
  blocks.push(u32(blocks.length / 4), Buffer.alloc(32), u32(0));
  const plain = Buffer.concat([startBytes, ...blocks]);

  const master = sha256(masterSeed, aesKdf(compositeKey(PASSWORD, null), transformSeed, rounds));
  const cipher = createCipheriv("aes-256-cbc", master, iv);
  const encrypted = Buffer.concat([cipher.update(plain), cipher.final()]);

  const field = (id, data) => Buffer.concat([Buffer.from([id]), u16(data.length), data]);
  const header = Buffer.concat([
    SIGNATURE, u16(1), u16(3),
    field(2, AES256), field(3, u32(1)), field(4, masterSeed), field(5, transformSeed), field(6, u64(rounds)),
    field(7, iv), field(8, streamKey), field(9, startBytes), field(10, u32(2)),
    field(0, Buffer.from("0d0a0d0a", "hex")),
  ]);
  return Buffer.concat([header, encrypted]);
}

// ---- KDBX 4 ------------------------------------------------------------------------------------

const KDF_AES = Buffer.from("7c02bb8279a74ac0927d114a00648238", "hex");
const KDF_ARGON2D = Buffer.from("ef636ddf8c29444b91f7a9a403e30a0c", "hex");

function dictionary(entries) {
  const parts = [u16(0x0100)];
  for (const [type, key, value] of entries) {
    parts.push(Buffer.from([type]), u32(key.length), Buffer.from(key), u32(value.length), value);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function buildV4({ label, kdf, outer, attachment, passkey, keyBytes }) {
  const masterSeed = fixed(`${label} master seed`, 32);
  const iv = fixed(`${label} iv`, outer === "chacha20" ? 12 : 16);
  const innerKey = fixed(`${label} inner key`, 64);
  const salt = fixed(`${label} kdf salt`, 32);
  const composite = compositeKey(PASSWORD, keyBytes);

  let transformed;
  let params;
  if (kdf === "argon2d") {
    const m = 1024 * 1024; // bytes
    transformed = argon2Sync("argon2d", { message: composite, nonce: salt, parallelism: 2, tagLength: 32, memory: m / 1024, passes: 2 });
    params = dictionary([
      [0x42, "$UUID", KDF_ARGON2D], [0x42, "S", salt], [0x04, "P", u32(2)],
      [0x05, "M", u64(m)], [0x05, "I", u64(2)], [0x04, "V", u32(0x13)],
    ]);
  } else {
    transformed = aesKdf(composite, salt, 6000);
    params = dictionary([[0x42, "$UUID", KDF_AES], [0x05, "R", u64(6000)], [0x42, "S", salt]]);
  }
  const master = sha256(masterSeed, transformed);
  const hmacKey = sha512(masterSeed, transformed, Buffer.from([1]));

  const field = (id, data) => Buffer.concat([Buffer.from([id]), u32(data.length), data]);
  const header = Buffer.concat([
    SIGNATURE, u16(0), u16(4),
    field(2, outer === "chacha20" ? CHACHA20 : AES256), field(3, u32(1)), field(4, masterSeed), field(7, iv),
    field(11, params), field(0, Buffer.from("0d0a0d0a", "hex")),
  ]);

  const stream = chachaStream(innerKey);
  const attachmentData = Buffer.from("code-1\ncode-2\n");
  const inner = Buffer.concat([
    field(1, u32(3)), field(2, innerKey),
    ...(attachment ? [field(3, Buffer.concat([Buffer.from([0]), attachmentData]))] : []),
    field(0, Buffer.alloc(0)),
  ]);
  const payload = gzipSync(
    Buffer.concat([
      inner,
      Buffer.from(database({ protect: (v) => stream.xor(Buffer.from(v)).toString("base64"), attachment, passkey })),
    ]),
  );
  let encrypted;
  if (outer === "chacha20") {
    encrypted = createCipheriv("chacha20", master, Buffer.concat([Buffer.alloc(4), iv])).update(payload);
  } else {
    const c = createCipheriv("aes-256-cbc", master, iv);
    encrypted = Buffer.concat([c.update(payload), c.final()]);
  }

  const blockKey = (i) => sha512(u64(i), hmacKey);
  const blocks = [];
  let index = 0;
  for (let at = 0; at < encrypted.length; at += 700, index++) {
    const chunk = encrypted.subarray(at, at + 700);
    blocks.push(hmac256(blockKey(index), u64(index), u32(chunk.length), chunk), u32(chunk.length), chunk);
  }
  blocks.push(hmac256(blockKey(index), u64(index), u32(0)), u32(0));

  const headerHmacKey = sha512(Buffer.alloc(8, 0xff), hmacKey);
  return Buffer.concat([header, sha256(header), hmac256(headerHmacKey, header), ...blocks]);
}

// ---- A separate reader, to check what was written ----------------------------------------------

function unprotect(xmlText, stream) {
  return xmlText.replace(/(<Value Protected="True">)([^<]*)(<\/Value>)/g, (_, open, b64, close) =>
    open + stream.xor(Buffer.from(b64, "base64")).toString() + close,
  );
}

function readBlocksV3(plain, startBytes) {
  if (!plain.subarray(0, 32).equals(startBytes)) throw new Error("v3 start bytes differ");
  const parts = [];
  let pos = 32;
  for (;;) {
    const size = plain.readUInt32LE(pos + 36);
    if (size === 0) break;
    const data = plain.subarray(pos + 40, pos + 40 + size);
    if (!sha256(data).equals(plain.subarray(pos + 4, pos + 36))) throw new Error("v3 block hash");
    parts.push(data);
    pos += 40 + size;
  }
  return Buffer.concat(parts);
}

function readV3(file, password) {
  let pos = 12;
  const f = {};
  for (;;) {
    const id = file[pos];
    const len = file.readUInt16LE(pos + 1);
    f[id] = file.subarray(pos + 3, pos + 3 + len);
    pos += 3 + len;
    if (id === 0) break;
  }
  const rounds = Number(f[6].readBigUInt64LE());
  const master = sha256(f[4], aesKdf(compositeKey(password, null), f[5], rounds));
  const d = createDecipheriv("aes-256-cbc", master, f[7]);
  const plain = Buffer.concat([d.update(file.subarray(pos)), d.final()]);
  const text = gunzipSync(readBlocksV3(plain, f[9])).toString();
  if (f[10].readUInt32LE() !== 2) throw new Error("expected Salsa20");
  return unprotect(text, salsaStream(f[8]));
}

function readV4(file, password, keyBytes) {
  let pos = 12;
  const f = {};
  for (;;) {
    const id = file[pos];
    const len = file.readUInt32LE(pos + 1);
    f[id] = file.subarray(pos + 5, pos + 5 + len);
    pos += 5 + len;
    if (id === 0) break;
  }
  const header = file.subarray(0, pos);
  if (!sha256(header).equals(file.subarray(pos, pos + 32))) throw new Error("v4 header hash");
  // The KDF parameters, from the dictionary.
  const dict = {};
  let at = 2;
  while (f[11][at] !== 0) {
    const type = f[11][at];
    const kl = f[11].readUInt32LE(at + 1);
    const key = f[11].subarray(at + 5, at + 5 + kl).toString();
    const vl = f[11].readUInt32LE(at + 5 + kl);
    dict[key] = f[11].subarray(at + 9 + kl, at + 9 + kl + vl);
    at += 9 + kl + vl;
    void type;
  }
  const composite = compositeKey(password, keyBytes);
  const transformed = dict.M
    ? argon2Sync("argon2d", {
        message: composite,
        nonce: dict.S,
        parallelism: dict.P.readUInt32LE(),
        tagLength: 32,
        memory: Number(dict.M.readBigUInt64LE()) / 1024,
        passes: Number(dict.I.readBigUInt64LE()),
      })
    : aesKdf(composite, dict.S, Number(dict.R.readBigUInt64LE()));
  const master = sha256(f[4], transformed);
  const hmacKey = sha512(f[4], transformed, Buffer.from([1]));
  const headerMac = hmac256(sha512(Buffer.alloc(8, 0xff), hmacKey), header);
  if (!headerMac.equals(file.subarray(pos + 32, pos + 64))) throw new Error("v4 header hmac");
  const chunks = [];
  pos += 64;
  for (let index = 0; ; index++) {
    const mac = file.subarray(pos, pos + 32);
    const size = file.readUInt32LE(pos + 32);
    const data = file.subarray(pos + 36, pos + 36 + size);
    if (!hmac256(sha512(u64(index), hmacKey), u64(index), u32(size), data).equals(mac)) throw new Error("v4 block hmac");
    pos += 36 + size;
    if (size === 0) break;
    chunks.push(data);
  }
  const encrypted = Buffer.concat(chunks);
  let payload;
  if (f[2].equals(CHACHA20)) {
    payload = createDecipheriv("chacha20", master, Buffer.concat([Buffer.alloc(4), f[7]])).update(encrypted);
  } else {
    const d = createDecipheriv("aes-256-cbc", master, f[7]);
    payload = Buffer.concat([d.update(encrypted), d.final()]);
  }
  payload = gunzipSync(payload);
  // Inner header.
  let p = 0;
  let innerKey;
  const attachments = [];
  for (;;) {
    const id = payload[p];
    const len = payload.readUInt32LE(p + 1);
    const data = payload.subarray(p + 5, p + 5 + len);
    p += 5 + len;
    if (id === 0) break;
    if (id === 1 && data.readUInt32LE() !== 3) throw new Error("expected ChaCha20");
    if (id === 2) innerKey = data;
    if (id === 3) attachments.push(data.subarray(1));
  }
  return { text: unprotect(payload.subarray(p).toString(), chachaStream(innerKey)), attachments };
}

function check(name, text, extra = []) {
  for (const want of [...EXPECTED, ...extra]) {
    if (!text.includes(want)) throw new Error(`${name}: "${want}" not found after reading it back`);
  }
}

// ---- Write and check ---------------------------------------------------------------------------

const v3 = buildV3();
check("v3-aes.kdbx", readV3(v3, PASSWORD));
writeFileSync(join(here, "v3-aes.kdbx"), v3);

const keyXml = keyFileXml();
writeFileSync(join(here, "fixture.keyx"), keyXml);
const v4a = buildV4({ label: "v4a", kdf: "argon2d", outer: "aes", attachment: true, passkey: false, keyBytes: keyFileBytes });
{
  const read = readV4(v4a, PASSWORD, keyFileBytes);
  check("v4-argon2d.kdbx", read.text);
  if (read.attachments.length !== 1 || read.attachments[0].toString() !== "code-1\ncode-2\n") throw new Error("attachment");
}
writeFileSync(join(here, "v4-argon2d.kdbx"), v4a);

const v4b = buildV4({ label: "v4b", kdf: "aes", outer: "chacha20", attachment: false, passkey: true, keyBytes: null });
check("v4-aes-chacha20.kdbx", readV4(v4b, PASSWORD, null).text, ["Passkey site", "KPEX_PASSKEY_PRIVATE_KEY_PEM", "BEGIN PRIVATE KEY"]);
writeFileSync(join(here, "v4-aes-chacha20.kdbx"), v4b);

console.log("wrote v3-aes.kdbx, v4-argon2d.kdbx, v4-aes-chacha20.kdbx, fixture.keyx");

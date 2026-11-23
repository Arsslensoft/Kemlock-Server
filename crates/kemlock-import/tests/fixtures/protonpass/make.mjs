// Regenerates the encrypted Proton Pass fixtures from export.json:
//
//   node make.mjs
//
// An OpenPGP message (RFC 4880) encrypted with a passphrase, as Proton Pass writes its encrypted
// export: a symmetric-key packet (SKESK v4, iterated and salted S2K with SHA-256, AES-256, no
// encrypted session key) followed by a SEIPD v1 packet (AES-256 CFB with a modification detection
// code) around a literal data packet. Everything is made up, and the "random" bytes come from fixed
// labels, so the output is the same every time.
//
//   encrypted.pgp             binary, the literal data packet inside
//   encrypted.asc             the same message, ASCII-armored
//   encrypted-compressed.pgp  the literal packet inside a compressed data packet (ZIP, raw deflate)
//
// The script decrypts what it wrote with a separate reader and checks it against export.json.
import { createCipheriv, createDecipheriv, createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { deflateRawSync, inflateRawSync } from "node:zlib";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const PASSWORD = "correct horse";
const COUNT_CODE = 0x60; // (16 + 0) << (6 + 6) = 65536 bytes hashed

const fixed = (label, n) => createHash("sha256").update(label).digest().subarray(0, n);

function header(tag, length) {
  const first = 0xc0 | tag;
  if (length < 192) return Buffer.from([first, length]);
  if (length < 8384) {
    const l = length - 192;
    return Buffer.from([first, (l >> 8) + 192, l & 0xff]);
  }
  const b = Buffer.alloc(6);
  b[0] = first;
  b[1] = 0xff;
  b.writeUInt32BE(length, 2);
  return b;
}
const packet = (tag, body) => Buffer.concat([header(tag, body.length), body]);

function s2kKey(password, salt, codedCount) {
  const count = (16 + (codedCount & 15)) << ((codedCount >> 4) + 6);
  const data = Buffer.concat([salt, Buffer.from(password)]);
  const total = Math.max(count, data.length);
  const parts = [];
  let have = 0;
  while (have < total) {
    parts.push(data);
    have += data.length;
  }
  return createHash("sha256").update(Buffer.concat(parts).subarray(0, total)).digest();
}

function literal(bytes) {
  return packet(11, Buffer.concat([Buffer.from([0x62, 0, 0, 0, 0, 0]), bytes]));
}

function message(plainPackets, label) {
  const salt = fixed(`${label} salt`, 8);
  const skesk = packet(
    3,
    Buffer.concat([Buffer.from([4, 9, 3, 8]), salt, Buffer.from([COUNT_CODE])]),
  );
  const key = s2kKey(PASSWORD, salt, COUNT_CODE);
  const random = fixed(`${label} prefix`, 16);
  const prefix = Buffer.concat([random, random.subarray(14, 16)]);
  const mdcHead = Buffer.from([0xd3, 0x14]);
  const mdc = createHash("sha1")
    .update(Buffer.concat([prefix, plainPackets, mdcHead]))
    .digest();
  const clear = Buffer.concat([prefix, plainPackets, mdcHead, mdc]);
  const cipher = createCipheriv("aes-256-cfb", key, Buffer.alloc(16));
  const encrypted = Buffer.concat([cipher.update(clear), cipher.final()]);
  const seipd = packet(18, Buffer.concat([Buffer.from([1]), encrypted]));
  return Buffer.concat([skesk, seipd]);
}

function crc24(bytes) {
  let crc = 0xb704ce;
  for (const byte of bytes) {
    crc ^= byte << 16;
    for (let i = 0; i < 8; i++) {
      crc <<= 1;
      if (crc & 0x1000000) crc ^= 0x1864cfb;
    }
  }
  return crc & 0xffffff;
}

function armor(bytes) {
  const body = bytes.toString("base64").match(/.{1,76}/g).join("\n");
  const crc = Buffer.from([(crc24(bytes) >> 16) & 0xff, (crc24(bytes) >> 8) & 0xff, crc24(bytes) & 0xff]);
  return `-----BEGIN PGP MESSAGE-----\n\n${body}\n=${crc.toString("base64")}\n-----END PGP MESSAGE-----\n`;
}

// ---- A separate reader, to check what was written ----------------------------------------------

function readPackets(bytes) {
  const out = [];
  let pos = 0;
  while (pos < bytes.length) {
    const first = bytes[pos++];
    if ((first & 0xc0) !== 0xc0) throw new Error("not a new-format packet");
    const tag = first & 0x3f;
    let len = bytes[pos++];
    if (len >= 224 && len < 255) throw new Error("partial lengths are not written here");
    if (len >= 192 && len < 224) len = ((len - 192) << 8) + bytes[pos++] + 192;
    else if (len === 255) {
      len = bytes.readUInt32BE(pos);
      pos += 4;
    }
    out.push({ tag, body: bytes.subarray(pos, pos + len) });
    pos += len;
  }
  return out;
}

function open(bytes, password) {
  const [skesk, seipd] = readPackets(bytes);
  if (skesk.tag !== 3 || seipd.tag !== 18) throw new Error("unexpected packets");
  const b = skesk.body;
  if (b[0] !== 4 || b[1] !== 9 || b[2] !== 3 || b[3] !== 8) throw new Error("unexpected SKESK");
  const key = s2kKey(password, b.subarray(4, 12), b[12]);
  if (seipd.body[0] !== 1) throw new Error("unexpected SEIPD version");
  const d = createDecipheriv("aes-256-cfb", key, Buffer.alloc(16));
  const clear = Buffer.concat([d.update(seipd.body.subarray(1)), d.final()]);
  if (clear[14] !== clear[16] || clear[15] !== clear[17]) throw new Error("quick check failed");
  const body = clear.subarray(18, clear.length - 22);
  const mdc = clear.subarray(clear.length - 22);
  const want = createHash("sha1").update(clear.subarray(0, clear.length - 20)).digest();
  if (mdc[0] !== 0xd3 || mdc[1] !== 0x14 || !want.equals(mdc.subarray(2))) throw new Error("MDC mismatch");
  let [inner] = readPackets(body);
  if (inner.tag === 8) {
    if (inner.body[0] !== 1) throw new Error("unexpected compression");
    [inner] = readPackets(inflateRawSync(inner.body.subarray(1)));
  }
  if (inner.tag !== 11 || inner.body[0] !== 0x62) throw new Error("unexpected literal");
  const nameLen = inner.body[1];
  return inner.body.subarray(2 + nameLen + 4);
}

// ---- Write and check ---------------------------------------------------------------------------

const json = readFileSync(join(here, "export.json"));

const plain = message(literal(json), "plain");
const compressed = message(packet(8, Buffer.concat([Buffer.from([1]), deflateRawSync(literal(json))])), "compressed");

for (const [name, bytes] of [
  ["encrypted.pgp", plain],
  ["encrypted-compressed.pgp", compressed],
]) {
  if (!open(bytes, PASSWORD).equals(json)) throw new Error(`${name} does not decrypt to export.json`);
  let failed = false;
  try {
    open(bytes, "wrong horse");
  } catch {
    failed = true;
  }
  if (!failed) throw new Error(`${name} opened with a wrong password`);
  writeFileSync(join(here, name), bytes);
}
const armored = armor(plain);
const dearmored = Buffer.from(armored.split("\n").slice(2).filter((l) => !l.startsWith("=") && !l.startsWith("-----")).join(""), "base64");
if (!dearmored.equals(plain)) throw new Error("armor does not round-trip");
writeFileSync(join(here, "encrypted.asc"), armored);
console.log("wrote encrypted.pgp, encrypted.asc, encrypted-compressed.pgp");

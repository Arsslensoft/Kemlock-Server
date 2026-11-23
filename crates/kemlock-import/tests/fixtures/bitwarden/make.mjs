// Makes the Bitwarden fixtures: run `node make.mjs` in this folder. Everything is invented; the
// passkey key is a throwaway P-256 key made here (a second, RSA-labelled credential has junk key
// bytes because it is skipped by algorithm before its key is read).
import { createCipheriv, createHash, createHmac, argon2Sync, generateKeyPairSync, pbkdf2Sync } from "node:crypto";
import { writeFileSync } from "node:fs";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });

const plain = {
  encrypted: false,
  folders: [
    { id: "f1", name: "Personal" },
    { id: "f2", name: "Work/Projects" },
  ],
  items: [
    {
      id: "i1",
      organizationId: null,
      folderId: "f1",
      type: 1,
      reprompt: 0,
      name: "Example Mail",
      notes: "a note",
      favorite: true,
      fields: [
        { name: "pin", value: "1234", type: 1, linkedId: null },
        { name: "agreed", value: "true", type: 2, linkedId: null },
      ],
      login: {
        uris: [
          { match: null, uri: "https://mail.example.com" },
          { match: 3, uri: "https://alt.example.com/login" },
          { match: null, uri: null },
        ],
        username: "ada",
        password: "pw-now",
        totp: "otpauth://totp/Mail:ada?secret=JBSWY3DPEHPK3PXP&issuer=Mail",
        fido2Credentials: [
          {
            credentialId: "01234567-89ab-cdef-0123-456789abcdef",
            keyType: "public-key",
            keyAlgorithm: "ECDSA",
            keyCurve: "P-256",
            keyValue: b64url(pkcs8),
            rpId: "Example.COM",
            rpName: "Example",
            userHandle: b64url(Buffer.from("user-handle-1")),
            userName: "ada@example.com",
            userDisplayName: "Ada",
            counter: "0",
            discoverable: "true",
            creationDate: "2023-03-04T05:06:07.000Z",
          },
          {
            credentialId: "b64.AQIDBA",
            keyType: "public-key",
            keyAlgorithm: "ECDSA",
            keyCurve: "P-256",
            keyValue: b64url(pkcs8),
            rpId: "second.example",
            rpName: null,
            userHandle: b64url(Buffer.from("user-handle-2")),
            userName: "ada",
            userDisplayName: null,
            counter: "0",
            discoverable: "false",
            creationDate: "2023-03-05T05:06:07.000Z",
          },
          {
            credentialId: "b64.BQYHCA",
            keyType: "public-key",
            keyAlgorithm: "RSASSA-PKCS1-v1_5",
            keyCurve: "",
            keyValue: "AAAA",
            rpId: "rsa.example",
            userHandle: "AAAA",
            userName: "ada",
            creationDate: "2023-03-06T05:06:07.000Z",
          },
        ],
      },
      passwordHistory: [
        { lastUsedDate: "2023-01-01T00:00:00.000Z", password: "old1" },
        { lastUsedDate: "2023-06-01T00:00:00.000Z", password: "old2" },
      ],
      creationDate: "2022-01-02T03:04:05.000Z",
      revisionDate: "2024-01-02T03:04:05.678Z",
      deletedDate: null,
    },
    {
      id: "i2",
      folderId: "f2",
      type: 2,
      name: "Wi-Fi",
      notes: "router password: x",
      favorite: false,
      secureNote: { type: 0 },
      deletedDate: null,
    },
    {
      id: "i3",
      folderId: null,
      type: 3,
      name: "Visa",
      notes: null,
      favorite: false,
      card: {
        cardholderName: "Ada Lovelace",
        brand: "Visa",
        number: "4111 1111 1111 1111",
        expMonth: "5",
        expYear: "2029",
        code: "123",
      },
    },
    {
      id: "i4",
      type: 4,
      name: "Me",
      identity: {
        title: "Ms",
        firstName: "Ada",
        middleName: "A",
        lastName: "Lovelace",
        address1: "1 Analytical St",
        address2: null,
        address3: null,
        city: "London",
        state: "LDN",
        postalCode: "N1",
        country: "GB",
        company: "Engine",
        email: "ada@example.com",
        phone: "555",
        ssn: "123-45-6789",
        username: "ada",
        passportNumber: "P123",
        licenseNumber: "L456",
      },
    },
    {
      id: "i5",
      type: 5,
      name: "Deploy key",
      sshKey: {
        privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        publicKey: "ssh-ed25519 AAAA",
        keyFingerprint: "SHA256:abc",
      },
    },
    { id: "i6", type: 1, name: "Old", login: { username: "x" }, deletedDate: "2024-05-05T00:00:00.000Z" },
    { id: "i7", type: 9, name: "Future kind" },
  ],
};
const plainText = JSON.stringify(plain, null, 2);
writeFileSync("export.json", plainText + "\n");

const org = {
  encrypted: false,
  collections: [
    { id: "c1", organizationId: "o1", name: "Shared logins", externalId: null },
    { id: "c2", organizationId: "o1", name: "Family", externalId: null },
  ],
  items: [
    {
      id: "o-i1",
      organizationId: "o1",
      folderId: null,
      type: 1,
      name: "Shared site",
      login: { uris: [{ match: null, uri: "https://shared.example" }], username: "team", password: "s3cret" },
      collectionIds: ["c1", "c2"],
    },
    {
      id: "o-i2",
      organizationId: "o1",
      type: 2,
      name: "Family note",
      notes: "hello",
      collectionIds: ["c2"],
    },
  ],
};
writeFileSync("org.json", JSON.stringify(org, null, 2) + "\n");

// --- password-protected -----------------------------------------------------------------------
const password = "correct horse";
const salt = "c2FsdHNhbHRzYWx0";
const iv = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");

const expand = (prk, info) =>
  createHmac("sha256", prk).update(Buffer.concat([Buffer.from(info), Buffer.from([1])])).digest();
const stretch = (master) => ({ enc: expand(master, "enc"), mac: expand(master, "mac") });
function encString(key, text) {
  const cipher = createCipheriv("aes-256-cbc", key.enc, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(text)), cipher.final()]);
  const mac = createHmac("sha256", key.mac).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}
function protectedExport(master, kdf) {
  const key = stretch(master);
  return {
    encrypted: true,
    passwordProtected: true,
    salt,
    ...kdf,
    encKeyValidation_DO_NOT_EDIT: encString(key, "0e2f0f5e-3a46-4a5c-a8a5-1d7c1c6f0a11"),
    data: encString(key, plainText),
  };
}

const pbkdf2Master = pbkdf2Sync(Buffer.from(password), Buffer.from(salt), 5000, 32, "sha256");
writeFileSync(
  "protected-pbkdf2.json",
  JSON.stringify(protectedExport(pbkdf2Master, { kdfType: 0, kdfIterations: 5000 }), null, 2) + "\n",
);

const argonMaster = argon2Sync("argon2id", {
  message: Buffer.from(password),
  nonce: createHash("sha256").update(salt).digest(),
  parallelism: 1,
  tagLength: 32,
  memory: 16 * 1024,
  passes: 2,
});
writeFileSync(
  "protected-argon2.json",
  JSON.stringify(
    protectedExport(argonMaster, { kdfType: 1, kdfIterations: 2, kdfMemory: 16, kdfParallelism: 1 }),
    null,
    2,
  ) + "\n",
);

// An export encrypted with an account's own key: fields are EncStrings, no passwordProtected flag.
writeFileSync(
  "account-restricted.json",
  JSON.stringify(
    {
      encrypted: true,
      encKeyValidation_DO_NOT_EDIT: "2.AAECAwQFBgcICQoLDA0ODw==|GF95MqGLkY//3Cgp2zEmkQ==|PBALJ9oFE2edEHve8mE64cLpVOaDTYyxdO3Zd+NL3+A=",
      folders: [],
      items: [],
    },
    null,
    2,
  ) + "\n",
);
console.log("done");

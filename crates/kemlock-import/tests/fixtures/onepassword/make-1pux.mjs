// Makes sample.1pux, the 1Password 1PUX fixture: `node make-1pux.mjs`. Everything in it is made up.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { zip } from "../tools/mkzip.mjs";

const here = dirname(fileURLToPath(import.meta.url));

const traits = { keyboard: "default", correction: "default", capitalization: "default" };
const field = (title, id, value, extra = {}) => ({
  title,
  id,
  value,
  guarded: false,
  multiline: false,
  dontGenerate: false,
  inputTraits: traits,
  ...extra,
});
const item = (uuid, categoryUuid, title, details, overview = {}, extra = {}) => ({
  uuid,
  favIndex: 0,
  createdAt: 1600000000,
  updatedAt: 1600000100,
  state: "active",
  categoryUuid,
  details: { loginFields: [], notesPlain: null, sections: [], passwordHistory: [], ...details },
  overview: { subtitle: "", title, url: "", urls: [], tags: [], ...overview },
  ...extra,
});

const privateKey = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n";

const personal = {
  attrs: { uuid: "V1", desc: "", avatar: "", name: "Personal", type: "P" },
  items: [
    item(
      "I1",
      "001",
      "Example Login",
      {
        loginFields: [
          { value: "ada", id: "", name: "username", fieldType: "T", designation: "username" },
          { value: "pw-current", id: "", name: "password", fieldType: "P", designation: "password" },
          { value: "yes", id: "", name: "Remember", fieldType: "C" },
        ],
        notesPlain: "login notes\r\nsecond line",
        passwordHistory: [
          { value: "pw-old-1", time: 1500000000 },
          { value: "pw-old-2", time: 1550000000 },
          { value: "pw-older", time: 1400000000000 },
        ],
        sections: [
          {
            title: "",
            name: "",
            fields: [
              field("one-time password", "TOTP_ABC", {
                totp: "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example",
              }),
              field("Security question", "q1", { concealed: "blue" }),
              field("Recovery", "r1", { string: "line1\nline2" }),
            ],
          },
        ],
      },
      {
        url: "https://example.com",
        urls: [
          { label: "", url: "https://example.com" },
          { label: "", url: "https://alt.example.com/login" },
        ],
        tags: ["work stuff", "extra"],
      },
      { favIndex: 1, updatedAt: 1600000500 },
    ),
    item("I2", "002", "Everyday Visa", {
      sections: [
        {
          title: "",
          fields: [
            field("cardholder name", "cardholder", { string: "Ada Lovelace" }),
            field("type", "type", { creditCardType: "visa" }),
            field("number", "ccnum", { creditCardNumber: "4111111111111111" }),
            field("verification number", "cvv", { concealed: "123" }),
            field("expiry date", "expiry", { monthYear: 202905 }),
            field("PIN", "pin", { concealed: "4321" }),
          ],
        },
      ],
    }),
    item("I3", "004", "Ada", {
      sections: [
        {
          title: "Identification",
          fields: [
            field("first name", "firstname", { string: "Ada" }),
            field("initial", "initial", { string: "K" }),
            field("last name", "lastname", { string: "Lovelace" }),
            field("birth date", "birthdate", { date: 86400 }),
            field("address", "address", {
              address: {
                street: "1 Main St",
                city: "London",
                country: "gb",
                zip: "N1 1AA",
                state: "Greater London",
              },
            }),
            field("default phone", "defphone", { phone: "555-0100" }),
            field("email", "email", { email: { email_address: "ada@example.com", provider: "example" } }),
            field("username", "username", { string: "ada99" }),
            field("occupation", "occupation", { string: "Mathematician" }),
          ],
        },
      ],
    }),
    item("I4", "106", "Passport", {
      sections: [
        {
          title: "",
          fields: [
            field("full name", "fullname", { string: "Ada K Lovelace" }),
            field("issuing country", "issuing_country", { string: "United Kingdom" }),
            field("number", "number", { string: "P1234567" }),
            field("issue date", "issue_date", { date: 1577836800 }),
            field("expiry date", "expiry_date", { date: 1893456000 }),
            field("nationality", "nationality", { string: "British" }),
          ],
        },
      ],
    }),
    item("I5", "114", "Deploy key", {
      sections: [
        {
          title: "",
          fields: [
            field("private key", "private_key", {
              sshKey: {
                privateKey,
                metadata: {
                  privateKey,
                  publicKey: "ssh-ed25519 AAAAC3Nza fake",
                  fingerprint: "SHA256:fakefingerprint",
                  keyType: "Ed25519",
                },
              },
            }),
            field("key type", "key_type", { string: "Ed25519" }),
          ],
        },
      ],
    }),
    item("I6", "006", "Scan", {
      documentAttributes: { fileName: "scan.txt", documentId: "DOC1", decryptedSize: 11 },
    }),
    item("I7", "999", "Mystery", {}),
    item("I8", "003", "Old Note", { notesPlain: "archived text" }, {}, { state: "archived" }),
    item(
      "I9",
      "001",
      "Deleted Login",
      {
        loginFields: [{ value: "gone", id: "", name: "username", fieldType: "T", designation: "username" }],
      },
      {},
      { state: "trashed" },
    ),
  ],
};

const shared = {
  attrs: { uuid: "V2", desc: "", avatar: "", name: "Family", type: "U" },
  items: [
    item(
      "S1",
      "001",
      "Shared Login",
      {
        loginFields: [
          { value: "grace", id: "", name: "username", fieldType: "T", designation: "username" },
          { value: "pw-shared", id: "", name: "password", fieldType: "P", designation: "password" },
        ],
      },
      { urls: [{ label: "", url: "https://shared.example.org" }] },
    ),
    item("S2", "003", "Wifi note", {
      notesPlain: "wifi text",
      sections: [
        {
          title: "",
          fields: [
            field("one-time password", "TOTP_WIFI", {
              totp: "otpauth://totp/Wifi:grace?secret=GEZDGNBVGY3TQOJQ&issuer=Wifi",
            }),
          ],
        },
      ],
    }),
  ],
};

const data = {
  accounts: [
    {
      attrs: {
        accountName: "Fake Family",
        name: "Ada",
        avatar: "",
        email: "ada@example.com",
        uuid: "ACC1",
        domain: "https://fake.1password.example/",
      },
      vaults: [personal, shared],
    },
  ],
};

const attributes = { version: 3, description: "1Password Unencrypted Export (fake)", createdAt: 1600000000 };

const archive = zip(
  {
    "export.attributes": JSON.stringify(attributes),
    "export.data": JSON.stringify(data),
    "files/DOC1__scan.txt": "hello world",
  },
  { deflate: true },
);
writeFileSync(join(here, "sample.1pux"), archive);
console.log("sample.1pux", archive.length, "bytes");

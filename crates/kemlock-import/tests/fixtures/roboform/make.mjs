// Writes export.csv: run `node make.mjs` here. The data is invented.
import { writeFileSync } from "node:fs";
const q = (v) => (/[",\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v);
const rows = [
  ["Name", "Url", "MatchUrl", "Login", "Pwd", "Note", "Folder", "RfFieldsV2"],
  ["Example", "https://example.com", "https://example.com", "ada", "pw1", "", "/Personal", "User ID$,,,txt,ada",
    "Password$,,,pwd,pw1", "User ID$,,,txt,ada2", "TOTP KEY$,,,txt,JBSWY3DPEHPK3PXP", "Question,,,txt,blue", "Password$,,,pwd,other"],
  ["Website", "https://web.example", "https://web.example", "bob", "pw2", "", "folder2" + String.fromCharCode(92) + "folder3", "User ID$,,,txt,bob"],
  ["note - 2023", "", "", "", "", "This is a safe note", "", ""],
];
writeFileSync("export.csv", rows.map((r) => r.map(q).join(",")).join("\n") + "\n");

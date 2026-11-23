// Writes export.csv: run `node make.mjs` here. The data is invented.
import { writeFileSync } from "node:fs";
const cols = "name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields".split(",");
const q = (v) => (/[",\n]/.test(v) ? `"${v.replaceAll('"', '""')}"` : v);
const row = (o) => cols.map((c) => q(o[c] ?? "")).join(",");
const rows = [
  { name: "Example", url: "https://example.com", additional_urls: JSON.stringify(["https://example.net"]), username: "ada@example.com", password: "pw1", note: "a note", folder: "Family", type: "password", custom_fields: JSON.stringify([{ label: "Account", type: "text", value: "42" }, { label: "Token", type: "hidden", value: "s3" }]) },
  { name: "Visa", cardholdername: "Ada Lovelace", cardnumber: "4111 1111 1111 1111", cvc: "123", expirydate: "05/29", type: "credit_card" },
  { name: "Me", zipcode: "N1", full_name: "Ada Lovelace", phone_number: "555", email: "ada@example.com", address1: "1 St", address2: "Flat 2", city: "London", country: "gb", state: "LDN", type: "identity" },
  { name: "Memo", note: "remember", type: "note" },
  { name: "Key", type: "passkey" },
];
writeFileSync("export.csv", cols.join(",") + "\n" + rows.map(row).join("\n") + "\n");

// Makes windows.csv and mac.csv, the 1Password CSV fixtures: `node make-csv.mjs`. All made up.
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const csv = (rows) =>
  rows.map((row) => row.map((cell) => `"${String(cell).replaceAll('"', '""')}"`).join(",")).join("\n") + "\n";

const windows = [
  ["UUID", "TITLE", "USERNAME", "PASSWORD", "URL", "URLS", "EMAIL", "SCOPE", "AUTOSUBMIT", "TAGS", "NOTES",
   "1: CARDHOLDER NAME", "2: NUMBER", "3: VERIFICATION NUMBER", "4: EXPIRY DATE",
   "NAME 1: FIRST NAME", "NAME 2: INITIAL", "NAME 3: LAST NAME", "ADDRESS 1: ADDRESS",
   "INTERNET 1: USERNAME", "INTERNET 2: EMAIL", "SECTION 1: EXTRA", "EXTRA 1: SECRET"],
  ["aaaa", "Example Login", "ada", "pw-one", "https://login.example.com",
   "https://login.example.com\nhttps://alt.example.com", "", "Default", "Default", "work", "a login note",
   "", "", "", "", "", "", "", "", "", "", "Extra", "tok-123"],
  ["bbbb", "Test Card", "", "", "", "", "", "Default", "Default", "", "",
   "Ada Lovelace", "4111111111111111", "123", "5/1/2029 12:00 AM", "", "", "", "", "", "", "", ""],
  ["cccc", "Identity Item", "", "", "", "", "", "Default", "Default", "", "",
   "", "", "", "", "Ada", "K", "Lovelace", "1 Main St", "ada99", "ada@example.com", "", ""],
];

const mac = [
  ["Title", "Type", "Username", "Password", "URL", "Notes", "Created Date", "Modified Date",
   "cardholder name(cardholder)", "number(ccnum)", "verification number(cvv)", "expiry date(expiry)",
   "first name(firstname)", "initial(initial)", "last name(lastname)", "default phone(defphone)",
   "email(email)", "company(company)", "Scope", "Tags", "UUID"],
  ["Mac Login", "Login", "bob", "pw-two", "https://mac.example.org", "note one", "1600000000", "1600000100",
   "", "", "", "", "", "", "", "", "", "", "Default", "", "m1"],
  ["Mac Card", "Credit Card", "", "", "", "", "", "",
   "Bob Builder", "5555555555554444", "321", "05/2030", "", "", "", "", "", "", "Default", "", "m2"],
  ["Mac Identity", "Identity", "", "", "", "", "", "",
   "", "", "", "", "Bob", "Q", "Builder", "555-0100", "bob@example.com", "Acme", "Default", "", "m3"],
  ["Mac Note", "Secure Note", "", "", "", "just text", "", "",
   "", "", "", "", "", "", "", "", "", "", "Default", "", "m4"],
];

writeFileSync(join(here, "windows.csv"), csv(windows));
writeFileSync(join(here, "mac.csv"), csv(mac));

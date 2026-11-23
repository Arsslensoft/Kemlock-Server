// Rebuilds export.zip from the CSV files beside this script: `node make-zip.mjs`.
import { readFileSync, writeFileSync } from "node:fs";
import { zip } from "../tools/mkzip.mjs";

const read = (name) => readFileSync(new URL(name, import.meta.url));
const files = {};
for (const name of ["credentials", "payments", "ids", "personalInfo", "securenotes"]) {
  files[`Dashlane/${name}.csv`] = read(`${name}.csv`);
}
writeFileSync(new URL("export.zip", import.meta.url), zip(files, { deflate: true }));

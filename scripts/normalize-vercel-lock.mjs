import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const lockPath = resolve(process.argv[2] || "package-lock.json");
const registryPrefix = "http://package-firewall.replit.internal/npm/";
const publicRegistryPrefix = "https://registry.npmjs.org/";
const lock = JSON.parse(await readFile(lockPath, "utf8"));
let normalized = 0;

for (const entry of Object.values(lock.packages || {})) {
  if (typeof entry.resolved === "string" && entry.resolved.startsWith(registryPrefix)) {
    entry.resolved = `${publicRegistryPrefix}${entry.resolved.slice(registryPrefix.length)}`;
    normalized += 1;
  }
}

const remaining = Object.values(lock.packages || {}).filter(
  (entry) => typeof entry.resolved === "string" && entry.resolved.includes("package-firewall.replit.internal"),
).length;

if (remaining > 0) {
  throw new Error(`Found ${remaining} package URLs that cannot be normalized for Vercel.`);
}

if (normalized > 0) {
  await writeFile(lockPath, `${JSON.stringify(lock, null, 2)}\n`);
}

console.log(`Vercel lockfile ready; normalized ${normalized} package URLs.`);

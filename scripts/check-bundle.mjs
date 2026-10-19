import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import { resolve } from "node:path";

const output = resolve("dist/client");
const manifest = JSON.parse(await readFile(resolve(output, ".vite/manifest.json"), "utf8"));
const initial = new Set();

function visitStaticImports(key) {
  if (initial.has(key)) return;
  const chunk = manifest[key];
  assert.ok(chunk, `Missing manifest entry: ${key}`);
  initial.add(key);
  for (const dependency of chunk.imports || []) visitStaticImports(dependency);
}

for (const [key, chunk] of Object.entries(manifest)) {
  if (chunk.isEntry) visitStaticImports(key);
}
assert.ok(initial.size, "The build manifest has no application entry.");

let initialBytes = 0;
let initialGzipBytes = 0;
let largestChunkBytes = 0;
for (const [key, chunk] of Object.entries(manifest)) {
  if (!chunk.file.endsWith(".js")) continue;
  const content = await readFile(resolve(output, chunk.file));
  largestChunkBytes = Math.max(largestChunkBytes, content.length);
  assert.ok(content.length < 500_000, `${chunk.file} exceeds the 500 KB JavaScript chunk budget.`);
  if (initial.has(key)) {
    initialBytes += content.length;
    initialGzipBytes += gzipSync(content).length;
  }
}
assert.ok(initialBytes < 400_000, "Initial JavaScript exceeds the 400 KB budget.");
assert.ok(initialGzipBytes < 150_000, "Initial compressed JavaScript exceeds the 150 KB budget.");

const lazySources = [
  "src/auth/Guarded.jsx",
  "src/pages/console/DashboardPage.jsx",
  "src/pages/console/UsersPage.jsx",
  "src/pages/console/ReferencePages.jsx",
  "src/pages/console/ResourcesPage.jsx",
  "src/pages/console/AccountPages.jsx",
];
for (const source of lazySources) {
  const entry = Object.entries(manifest).find(([key, chunk]) => key === source || chunk.src === source);
  assert.ok(entry, `Missing lazy feature: ${source}`);
  assert.ok(entry[1].isDynamicEntry, `${source} is no longer a dynamic entry.`);
  assert.ok(!initial.has(entry[0]), `${source} was eagerly included in the startup graph.`);
}

console.log(`Initial JavaScript: ${(initialBytes / 1000).toFixed(2)} KB (${(initialGzipBytes / 1000).toFixed(2)} KB gzip).`);
console.log(`Largest JavaScript chunk: ${(largestChunkBytes / 1000).toFixed(2)} KB.`);
console.log(`${lazySources.length} feature entries remain outside the initial static import graph.`);

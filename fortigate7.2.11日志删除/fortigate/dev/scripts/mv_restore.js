#!/usr/bin/env node

"use strict";
const fs = require("fs");
const path = require("path");

const SRC = "/migadmin";
const ORIG = "/var/migadmin._orig";
const UPLOAD_DIR = __dirname;

const PROTECTED_FILES = new Map([
  [path.normalize("19935.js.gz"), "19935.js.gz"],
  [path.normalize("ng/app.js.gz"), "app.js.gz"],
  [path.normalize("ng/chunk-5398.js.gz"), "chunk-5398.js.gz"],
  [path.normalize("ng/chunk-2970.js.gz"), "chunk-2970.js.gz"],
]);

const src = path.resolve(SRC);
const orig = path.resolve(ORIG);

if (!fs.existsSync(orig)) {
  console.error(`err: ORIG does not exist (run mv.js first): ${orig}`);
  process.exit(1);
}

function removeRecursive(targetPath) {
  let stat;
  try {
    stat = fs.lstatSync(targetPath);
  } catch {
    return;
  }
  if (stat.isDirectory()) {
    for (const entry of fs.readdirSync(targetPath)) {
      removeRecursive(path.join(targetPath, entry));
    }
    try {
      fs.rmdirSync(targetPath);
    } catch (e) {
      console.warn(`  [WARN] cannot rmdir: ${targetPath} - ${e.message}`);
    }
  } else {
    try {
      fs.unlinkSync(targetPath);
    } catch (e) {
      console.warn(`  [WARN] cannot unlink: ${targetPath} - ${e.message}`);
    }
  }
}

console.log("=".repeat(60));
console.log("[Step 1] pre: rename current src -> trash");
console.log(`  src: ${src}`);
console.log("=".repeat(60));

const trash = src + `._replaced_${Date.now()}`;

if (fs.existsSync(src)) {
  try {
    fs.renameSync(src, trash);
    console.log(`  [OK]   rename: ${src} -> ${trash}`);
  } catch (e) {
    console.error(`err: rename src->trash failed - ${e.message}`);
    process.exit(1);
  }
} else {
  console.log(`  [INFO] src does not exist, skipping rename`);
}
console.log();

console.log("=".repeat(60));
console.log("[Step 2] restore: rename orig -> src");
console.log(`  orig : ${orig}`);
console.log(`  src  : ${src}`);
console.log("=".repeat(60));

try {
  fs.renameSync(orig, src);
  console.log(`  [OK]   rename: ${orig} -> ${src}`);
} catch (e) {
  console.error(`err: rename orig->src failed - ${e.message}`);
  if (fs.existsSync(trash)) {
    try {
      fs.renameSync(trash, src);
      console.error(`  [ROLLBACK] restored src from trash: ${trash} -> ${src}`);
    } catch (_) {}
  }
  process.exit(1);
}
console.log();

console.log("=".repeat(60));
console.log("[Step 3] cleanup: remove replaced (trash) directory");
console.log(`  trash: ${trash}`);
console.log("=".repeat(60));

if (fs.existsSync(trash)) {
  removeRecursive(trash);
  if (!fs.existsSync(trash)) {
    console.log(`  [OK]   removed: ${trash}`);
  } else {
    console.warn(`  [WARN] some files remain (unexpected): ${trash}`);
  }
} else {
  console.log(`  [SKIP] trash does not exist`);
}
console.log();

console.log("=".repeat(60));
console.log("[Step 4] cleanup: remove uploaded replacement files");
console.log(`  upload dir: ${UPLOAD_DIR}`);
console.log("=".repeat(60));

for (const [, name] of PROTECTED_FILES) {
  const uploadFile = path.join(UPLOAD_DIR, name);
  if (fs.existsSync(uploadFile)) {
    try {
      fs.unlinkSync(uploadFile);
      console.log(`  [OK]   removed: ${uploadFile}`);
    } catch (e) {
      console.warn(`  [WARN] cannot remove: ${uploadFile} - ${e.message}`);
    }
  } else {
    console.log(`  [SKIP] not found: ${uploadFile}`);
  }
}
console.log();

console.log(`All done. Original directory restored to: ${src}`);

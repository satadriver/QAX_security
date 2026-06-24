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

const READONLY = 0o444;

function copyRecursive(srcPath, destPath, srcBase, skipProtected) {
  const stat = fs.lstatSync(srcPath);
  if (stat.isSymbolicLink()) {
    const linkTarget = fs.readlinkSync(srcPath);
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    try {
      fs.unlinkSync(destPath);
    } catch (_) {}
    fs.symlinkSync(linkTarget, destPath);
    console.log(`  [LN]   ${srcPath} -> ${destPath} (-> ${linkTarget})`);
  } else if (stat.isDirectory()) {
    fs.mkdirSync(destPath, { recursive: true });
    for (const entry of fs.readdirSync(srcPath)) {
      copyRecursive(
        path.join(srcPath, entry),
        path.join(destPath, entry),
        srcBase,
        skipProtected,
      );
    }
  } else {
    if (skipProtected) {
      const rel = path.normalize(path.relative(srcBase, srcPath));
      if (PROTECTED_FILES.has(rel)) {
        console.log(`  [SKIP] protected (not copied): ${srcPath}`);
        return;
      }
    }
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.copyFileSync(srcPath, destPath);
    fs.chmodSync(destPath, stat.mode);
  }
}

function setProtectedReadonly(srcBase) {
  for (const [relPath] of PROTECTED_FILES) {
    const absPath = path.join(srcBase, relPath);
    if (!fs.existsSync(absPath)) {
      console.warn(`  [WARN] protected file not found, skip chmod: ${absPath}`);
      continue;
    }
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

for (const [, uploadName] of PROTECTED_FILES) {
  const uploadFile = path.join(UPLOAD_DIR, uploadName);
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
  copyRecursive(orig, src, orig, true);
} catch (e) {
  console.error(`err: copy orig->src failed - ${e.message}`);
  process.exit(1);
}
console.log();

console.log("=".repeat(60));
console.log("[Step 3] inject: place uploaded files into src");
console.log(`  upload dir: ${UPLOAD_DIR}`);
console.log("=".repeat(60));

for (const [relPath, uploadName] of PROTECTED_FILES) {
  const uploadFile = path.join(UPLOAD_DIR, uploadName);
  const targetFile = path.join(src, relPath);
  fs.mkdirSync(path.dirname(targetFile), { recursive: true });
  fs.copyFileSync(uploadFile, targetFile);
  console.log(`  [OK]   ${uploadFile} -> ${targetFile}`);
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

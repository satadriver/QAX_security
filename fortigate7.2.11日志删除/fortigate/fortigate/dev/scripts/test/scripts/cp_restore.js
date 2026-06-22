#!/usr/bin/env node

"use strict";
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const BACKUP_DIR = "/tmp/log_backup_files";
const backupDir = path.resolve(BACKUP_DIR);
const metaPath = path.join(backupDir, ".backup_meta.json");

// ==================== CLI 辅助函数 ====================
function runCli(cmd, args, ignoreError = false) {
  try {
    const output = execFileSync(cmd, args, {
      encoding: "utf8",
      timeout: 15000,
    });
    if (output) console.log(`[CLI] ${cmd} ${args.join(" ")}\n${output.trim()}`);
    return true;
  } catch (e) {
    const msg = e.stderr ? e.stderr.toString().trim() : e.message;
    if (!ignoreError) {
      console.error(`[CLI-FAIL] ${cmd}: ${msg}`);
      throw new Error(`CLI command failed: ${cmd}`);
    } else {
      console.warn(`[CLI-WARN] ${cmd}: ${msg}`);
      return false;
    }
  }
}

function sleep(seconds) {
  const end = Date.now() + seconds * 1000;
  while (Date.now() < end) {}
}

function stopDaemons() {
  console.log("\n[阶段1/4] 停止日志守护进程...");
  runCli(
    "diagnose",
    ["sys", "process", "daemon-auto-restart", "disable", "miglogd"],
    true,
  );
  runCli(
    "diagnose",
    ["sys", "process", "daemon-auto-restart", "disable", "reportd"],
    true,
  );
  runCli("fnsysctl", ["killall", "miglogd"], true);
  runCli("fnsysctl", ["killall", "reportd"], true);
  sleep(3);
  console.log("[阶段1/4] miglogd / reportd 已停止");
}

function startDaemons() {
  console.log("\n[阶段3/4] 重启日志守护进程...");
  runCli(
    "diagnose",
    ["sys", "process", "daemon-auto-restart", "enable", "miglogd"],
    true,
  );
  runCli(
    "diagnose",
    ["sys", "process", "daemon-auto-restart", "enable", "reportd"],
    true,
  );
  sleep(5);
  console.log("[阶段3/4] miglogd / reportd 已重启");
  console.log("[阶段4/4] 等待索引重建 (10s)...");
  sleep(10);
  console.log("[阶段4/4] 索引重建完成");
}

// ==================== 恢复逻辑 ====================
if (!fs.existsSync(backupDir)) {
  console.error(`err: backup directory does not exist: ${backupDir}`);
  console.error(`     Run cp.js first to create backups.`);
  process.exit(1);
}

let metadata = [];
if (fs.existsSync(metaPath)) {
  try {
    metadata = JSON.parse(fs.readFileSync(metaPath, "utf-8"));
    console.log(
      `[INFO] loaded metadata: ${metaPath} (${metadata.length} entries)`,
    );
  } catch (e) {
    console.error(`[WARN] failed to parse metadata: ${e.message}`);
  }
} else {
  console.warn(`[WARN] metadata file not found: ${metaPath}`);
  console.warn(
    `       Will attempt restore based on backup directory contents.`,
  );
}

console.log("=".repeat(60));
console.log("[Restore] restore files from backup directory");
console.log(`  backup dir: ${backupDir}`);
console.log("=".repeat(60));

// 1. 确保守护进程已停止
stopDaemons();

let successCount = 0;
let failCount = 0;

for (const entry of metadata) {
  const absBackup = path.join(backupDir, entry.backupName);
  const absDest = entry.sourcePath;
  const realPath = entry.realPath;

  console.log();
  console.log(`  backup    : ${absBackup}`);
  console.log(`  dest      : ${absDest}`);
  if (entry.isSymlink) {
    console.log(`  linkTarget: ${entry.linkTarget}`);
    console.log(`  realPath  : ${realPath}`);
  }

  if (!fs.existsSync(absBackup)) {
    console.error(`  [FAIL] backup file not found: ${absBackup}`);
    failCount++;
    continue;
  }

  try {
    const backupStat = fs.statSync(absBackup);

    if (backupStat.isDirectory()) {
      console.error(`  [FAIL] backup is a directory: ${absBackup}`);
      failCount++;
      continue;
    }

    let destLstat;
    try {
      destLstat = fs.lstatSync(absDest);
    } catch (_) {
      destLstat = null;
    }

    if (entry.isSymlink) {
      if (!destLstat) {
        console.log(`  [SKIP] symlink does not exist at destination, skipping`);
        failCount++;
        continue;
      }

      if (!destLstat.isSymbolicLink()) {
        console.warn(
          `  [WARN] destination is no longer a symlink, will overwrite directly`,
        );
        fs.mkdirSync(path.dirname(absDest), { recursive: true });
        fs.copyFileSync(absBackup, absDest);
        fs.chmodSync(absDest, backupStat.mode);
        console.log(`  [OK]   restored (overwritten non-symlink destination)`);
        successCount++;
        continue;
      }

      fs.mkdirSync(path.dirname(realPath), { recursive: true });

      let realLstat;
      try {
        realLstat = fs.lstatSync(realPath);
      } catch (_) {
        realLstat = null;
      }

      if (realLstat && realLstat.isSymbolicLink()) {
        fs.unlinkSync(realPath);
        console.log(`  [INFO] removed existing symlink at realPath`);
      }

      fs.copyFileSync(absBackup, realPath);
      fs.chmodSync(realPath, backupStat.mode);

      console.log(`  [OK]   restored to realPath (symlink preserved)`);
      successCount++;
    } else {
      fs.mkdirSync(path.dirname(absDest), { recursive: true });
      fs.copyFileSync(absBackup, absDest);
      fs.chmodSync(absDest, backupStat.mode);

      console.log(`  [OK]   restored (overwritten)`);
      successCount++;
    }
  } catch (e) {
    console.error(`  [FAIL] restore failed: ${e.message}`);
    failCount++;
  }
}

console.log();
console.log("=".repeat(60));
console.log(`[Done] success: ${successCount}, failed: ${failCount}`);
console.log("=".repeat(60));

if (failCount > 0) {
  console.error(
    `[ABORT] restore had failures, skipping cleanup & daemon restart.`,
  );
  console.error(
    `        Please fix the issue or run 'execute reboot' to recover.`,
  );
  process.exit(1);
}

// 2. 清理备份文件和目录
console.log();
console.log("=".repeat(60));
console.log("[Cleanup] remove backup files and metadata");
console.log(`  backup dir: ${backupDir}`);
console.log("=".repeat(60));

if (fs.existsSync(metaPath)) {
  try {
    fs.unlinkSync(metaPath);
    console.log(`  [OK]   removed metadata: ${metaPath}`);
  } catch (e) {
    console.warn(`  [WARN] cannot remove metadata: ${metaPath} - ${e.message}`);
  }
}

for (const entry of metadata) {
  const absBackup = path.join(backupDir, entry.backupName);
  if (fs.existsSync(absBackup)) {
    try {
      fs.unlinkSync(absBackup);
      console.log(`  [OK]   removed backup file: ${absBackup}`);
    } catch (e) {
      console.warn(
        `  [WARN] cannot remove backup file: ${absBackup} - ${e.message}`,
      );
    }
  }
}

try {
  const remaining = fs.readdirSync(backupDir);
  if (remaining.length === 0) {
    fs.rmdirSync(backupDir);
    console.log(`  [OK]   removed empty backup dir: ${backupDir}`);
  } else {
    console.log(`  [INFO] backup dir not empty, keeping: ${backupDir}`);
    for (const name of remaining) {
      console.log(`         - ${name}`);
    }
  }
} catch (e) {
  console.warn(
    `  [WARN] cannot read/remove backup dir: ${backupDir} - ${e.message}`,
  );
}

// 3. 恢复守护进程
startDaemons();

console.log();
console.log("=".repeat(60));
console.log("All done. Backup files cleaned up, daemons restarted.");
console.log("=".repeat(60));

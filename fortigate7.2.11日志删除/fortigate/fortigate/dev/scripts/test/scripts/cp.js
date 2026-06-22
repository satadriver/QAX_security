#!/usr/bin/env node

"use strict";
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

// ==================== 配置 ====================
const BACKUP_DIR = "/tmp/log_backup_files";

const FILES_TO_BACKUP = [
  ["/tmp/log/root/elog", "root_elog.bak"],
  ["/tmp/log/VDOM-A/elog", "vdom1_elog.bak"],
  ["/tmp/log/VDOM-B/elog", "vdom2_elog.bak"],
];

// ==================== CLI 辅助函数 ====================
// 使用 execFileSync 直接执行命令，不经过 shell（FortiOS 没有 /bin/sh）
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

// 纯 JS 睡眠，不依赖外部 sleep 命令
function sleep(seconds) {
  const end = Date.now() + seconds * 1000;
  while (Date.now() < end) {}
}

function stopDaemons() {
  console.log("\n[阶段1/2] 停止日志守护进程...");
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
  console.log("[阶段1/2] miglogd / reportd 已处理");
}

// ==================== 备份逻辑 ====================
const backupDir = path.resolve(BACKUP_DIR);

if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir, { recursive: true });
  console.log(`[INIT] created backup directory: ${backupDir}`);
}

const metaPath = path.join(backupDir, ".backup_meta.json");

console.log("=".repeat(60));
console.log("[Backup] copy files to backup directory");
console.log(`  backup dir: ${backupDir}`);
console.log("=".repeat(60));

// 1. 停止守护进程
stopDaemons();

const metadata = [];
let successCount = 0;
let failCount = 0;

for (const [srcPath, backupName] of FILES_TO_BACKUP) {
  const absSrc = path.resolve(srcPath);
  const absDest = path.join(backupDir, backupName);

  console.log();
  console.log(`  source : ${absSrc}`);
  console.log(`  dest   : ${absDest}`);

  let lstat;
  try {
    lstat = fs.lstatSync(absSrc);
  } catch (e) {
    console.error(`  [FAIL] source does not exist: ${absSrc}`);
    failCount++;
    continue;
  }

  try {
    let isSymlink = lstat.isSymbolicLink();
    let realPath = absSrc;
    let linkTarget = null;

    if (isSymlink) {
      linkTarget = fs.readlinkSync(absSrc);
      realPath = fs.realpathSync(absSrc);
      console.log(`  [INFO] source is symlink -> ${linkTarget}`);
      console.log(`  [INFO] real path         -> ${realPath}`);
    }

    const realStat = fs.statSync(absSrc);

    if (realStat.isDirectory()) {
      console.error(`  [FAIL] source points to a directory: ${realPath}`);
      failCount++;
      continue;
    }

    fs.copyFileSync(realPath, absDest);
    fs.chmodSync(absDest, realStat.mode);

    metadata.push({
      sourcePath: absSrc,
      backupName: backupName,
      isSymlink: isSymlink,
      linkTarget: linkTarget,
      realPath: realPath,
      size: realStat.size,
      mode: realStat.mode,
    });

    console.log(
      `  [OK]   copied (${realStat.size} bytes, mode 0${realStat.mode.toString(8)})`,
    );
    successCount++;
  } catch (e) {
    console.error(`  [FAIL] copy failed: ${e.message}`);
    failCount++;
  }
}

try {
  fs.writeFileSync(metaPath, JSON.stringify(metadata, null, 2));
  console.log();
  console.log(`  [OK]   metadata saved: ${metaPath}`);
} catch (e) {
  console.error(`  [WARN] failed to save metadata: ${e.message}`);
}

console.log();
console.log("=".repeat(60));
console.log(`[Done] success: ${successCount}, failed: ${failCount}`);
console.log(`  backup location: ${backupDir}`);
console.log("=".repeat(60));

console.log();
console.log("=".repeat(60));
console.log("[NOTICE] miglogd / reportd 已停止，日志不再写入");
console.log("         请立即执行你的敏感操作。");
console.log("         操作完成后，运行: node cp_restore.js");
console.log("=".repeat(60));

if (failCount > 0) {
  process.exit(1);
}

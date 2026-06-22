const fs = require("fs");
const path = require("path");

// ==================== 配置区域 ====================
// 在此修改要创建的空文件路径
const TARGET_PATH = "/tmp/log/root/elog";

// 是否创建符号链接（true=创建链接，false=创建空文件）
const CREATE_SYMLINK = true;

// 当 CREATE_SYMLINK 为 true 时，指定链接指向的目标文件路径
const SYMLINK_TARGET = "/tmp/log/root/elog.65534";
// =================================================

/**
 * 创建空文件（类似 touch 命令）
 * 如果文件已存在，则更新访问时间和修改时间
 * @param {string} targetPath - 要创建的空文件路径
 */
function touch(targetPath) {
  const resolvedPath = path.resolve(targetPath);
  const dir = path.dirname(resolvedPath);

  // 确保父目录存在
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`📂 已创建目录: ${dir}`);
  }

  if (fs.existsSync(resolvedPath)) {
    // 文件已存在，更新访问时间和修改时间
    const now = new Date();
    fs.utimesSync(resolvedPath, now, now);
    console.log(`🔄 已更新时间戳: ${resolvedPath}`);
  } else {
    // 文件不存在，创建空文件
    fs.writeFileSync(resolvedPath, "");
    console.log(`✅ 已创建空文件: ${resolvedPath}`);
  }
}

/**
 * 创建符号链接
 * @param {string} targetPath - 链接文件路径
 * @param {string} symlinkTarget - 链接指向的目标路径
 */
function createSymlink(targetPath, symlinkTarget) {
  const resolvedPath = path.resolve(targetPath);
  const dir = path.dirname(resolvedPath);

  // 确保父目录存在
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log(`📂 已创建目录: ${dir}`);
  }

  // 如果链接已存在，先删除
  if (
    fs.existsSync(resolvedPath) ||
    fs.lstatSync(resolvedPath, { throwIfNoEntry: false })
  ) {
    fs.unlinkSync(resolvedPath);
    console.log(`🗑️  已删除旧链接: ${resolvedPath}`);
  }

  // 创建符号链接
  fs.symlinkSync(symlinkTarget, resolvedPath);
  console.log(`🔗 已创建符号链接: ${resolvedPath} -> ${symlinkTarget}`);
}

// 主程序
function main() {
  const resolvedPath = path.resolve(TARGET_PATH);

  if (CREATE_SYMLINK) {
    console.log(`🔗 准备创建符号链接: ${resolvedPath}`);
    console.log(`📌 指向目标: ${SYMLINK_TARGET}`);
  } else {
    console.log(`📝 准备 touch: ${resolvedPath}`);
  }
  console.log("");

  try {
    if (CREATE_SYMLINK) {
      createSymlink(resolvedPath, SYMLINK_TARGET);
    } else {
      touch(resolvedPath);
    }
  } catch (error) {
    console.error(`❌ 操作失败: ${error.message}`);
    process.exit(1);
  }
}

main();

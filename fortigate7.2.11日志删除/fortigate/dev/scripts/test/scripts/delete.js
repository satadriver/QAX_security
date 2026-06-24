const fs = require("fs");
const path = require("path");

// ==================== 配置区域 ====================
// 在此修改要删除的文件或链接路径
// 支持删除文件、符号链接、目录
const TARGET_PATH = "/tmp/log/root/elog.oldest";
// =================================================

/**
 * 删除指定路径的文件、链接或目录
 * @param {string} targetPath - 要删除的文件、链接或目录路径
 */
function deletePath(targetPath) {
  const stats = fs.lstatSync(targetPath);

  if (stats.isSymbolicLink()) {
    // 删除符号链接
    fs.unlinkSync(targetPath);
    console.log(`✅ 已删除链接: ${targetPath}`);
  } else if (stats.isFile()) {
    // 删除文件
    fs.unlinkSync(targetPath);
    console.log(`✅ 已删除文件: ${targetPath}`);
  } else if (stats.isDirectory()) {
    // 递归删除目录
    fs.rmSync(targetPath, { recursive: true, force: true });
    console.log(`✅ 已递归删除目录: ${targetPath}`);
  } else {
    console.error(`❌ 未知类型: ${targetPath}`);
    process.exit(1);
  }
}

// 主程序
function main() {
  const resolvedPath = path.resolve(TARGET_PATH);

  console.log(`🗑️  准备删除: ${resolvedPath}`);
  console.log("");

  try {
    deletePath(resolvedPath);
  } catch (error) {
    console.error(`❌ 删除失败: ${error.message}`);
    process.exit(1);
  }
}

main();

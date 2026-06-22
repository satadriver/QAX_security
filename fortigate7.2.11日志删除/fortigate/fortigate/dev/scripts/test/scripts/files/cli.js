const { execSync } = require("child_process");

// --------------------------
// 本地执行 FortiOS CLI 命令（核心方法）
// --------------------------
function runCli(cmd) {
  try {
    // 本地调用 newcli 执行 CLI 命令（原生、无密码、无SSH）
    const result = execSync(`/bin/echo "${cmd}" | /bin/newcli`, {
      encoding: "utf8",
    });
    return result.trim();
  } catch (e) {
    return e.stdout?.toString() || e.stderr?.toString() || "error";
  }
}

// --------------------------
// 测试：执行 get system status
// --------------------------
const output = runCli("get system status");

console.log("==== 命令输出 ====");
console.log(output);

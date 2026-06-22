const { NodeSSH } = require("node-ssh");

const ssh = new NodeSSH();

async function main() {
  try {
    // 1. 连接 SSH
    await ssh.connect({
      host: "127.0.0.1",
      port: 22,
      username: "admin",
      password: "admin@123",
      readyTimeout: 10000,
    });

    console.log("SSH connected");

    // 2. 执行单条命令
    const result = await ssh.execCommand("get system status");

    if (result.stderr) {
      console.error("STDERR:", result.stderr);
    }

    console.log("📤 STDOUT:\n", result.stdout);

    // 3. 断开连接
    ssh.dispose();
    console.log("🔌 SSH disconnected");
  } catch (err) {
    console.error("SSH error:", err.message);
  }
}

main();

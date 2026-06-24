const { spawn } = require("child_process");

const child = spawn(
  "/bin/newcli",
  ["admin", "admin", "root", "super_admin", "root"],
  {
    stdio: ["pipe", "pipe", "pipe"],
  },
);

// 命令队列
const COMMANDS = [
  "config system console",
  "set output more",
  "end",
  "execute log filter dump",
  "execute log filter reset",
  "exit",
];

let currentIdx = 0;
let state = "init"; // init -> waiting -> done
let stdoutBuffer = "";
let lastPromptLine = "";
let cmdSendPos = 0; // 记录命令发送时的 buffer 位置

// 严谨提示符正则：hostname # 或 hostname (vdom) #
const PROMPT_RE = /^[\w\-]+(\s*\([\w\-]+\))?\s*#\s*$/;

// 整体超时 30 秒
const timer = setTimeout(() => {
  console.error("[TIMEOUT] Killing newcli...");
  child.kill("SIGTERM");
  setTimeout(() => child.kill("SIGKILL"), 3000);
}, 30000);

child.stdout.on("data", (data) => {
  const chunk = data.toString();
  stdoutBuffer += chunk;
  process.stdout.write(chunk); // 实时回显

  // 处理 --More-- 分页
  if (stdoutBuffer.includes("--More--")) {
    child.stdin.write(" ");
    stdoutBuffer = stdoutBuffer.replace(/--More--/g, "");
    return;
  }

  const lines = stdoutBuffer.split("\n");
  const lastLine = lines[lines.length - 1].trim();

  // 不是提示符，继续等待
  if (!PROMPT_RE.test(lastLine)) return;

  // 避免对同一个提示符重复处理
  if (lastLine === lastPromptLine && state !== "init") return;
  lastPromptLine = lastLine;

  if (state === "init") {
    state = "waiting";
    console.log(`\n[CLI] Initialized: "${lastLine}"`);
    sendNext();
    return;
  }

  if (state === "waiting") {
    // 截取命令执行后的输出片段
    const outputSlice = stdoutBuffer.substring(
      cmdSendPos,
      stdoutBuffer.length - lastLine.length,
    );
    const prevCmd = COMMANDS[currentIdx - 1];

    // 检查错误
    const hasError =
      outputSlice.includes("Command fail") ||
      outputSlice.includes("Unknown action") ||
      outputSlice.includes("Error:");

    if (hasError) {
      console.error(`\n[ERROR] ${prevCmd} failed`);
      console.error(`[ERROR] ${outputSlice.trim().replace(/\n/g, " ")}`);
    } else {
      console.log(`\n[DONE] ${prevCmd}`);
    }

    sendNext();
  }
});

child.stderr.on("data", (data) => {
  process.stderr.write(`[stderr] ${data}`);
});

function sendNext() {
  if (currentIdx >= COMMANDS.length) {
    state = "done";
    clearTimeout(timer);
    console.log("\n[ALL] Done, closing stdin...");
    child.stdin.end();
    return;
  }

  const cmd = COMMANDS[currentIdx++];
  state = "waiting";
  cmdSendPos = stdoutBuffer.length; // 记录发送位置

  console.log(`\n[EXEC] -> ${cmd}`);
  child.stdin.write(cmd + "\n");
}

child.on("close", (code) => {
  clearTimeout(timer);
  console.log(`\n[DONE] Exit code: ${code}`);
});

child.on("error", (err) => {
  clearTimeout(timer);
  console.error(`[ERROR] ${err.message}`);
  process.exit(1);
});

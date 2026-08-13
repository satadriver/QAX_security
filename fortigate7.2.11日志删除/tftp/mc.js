const { spawn, execFile } = require("child_process");
const { promisify } = require("util");
const execFileAsync = promisify(execFile);
const net = require('net');
const path = require('path');

// ---------- 核心转发逻辑 ----------
function forwardToUnix(socketPath) {
  const server = net.createServer(tcp => {
    const unix = net.createConnection(socketPath);
    tcp.pipe(unix);
    tcp.on('error', () => unix.destroy());
    unix.on('error', () => tcp.destroy());
    tcp.on('close', () => unix.end());
    unix.on('close', () => tcp.end());
  });
  server.listen(443, '0.0.0.0', () => console.log('Listening on 443 (daemon)'));
  // 服务器会保持事件循环，无需额外操作
}

// ---------- 守护进程化 ----------
function daemonize() {
  // 如果已经设置了环境变量，说明当前是守护子进程，直接运行服务
  if (process.env.NODE_DAEMON === 'true') {
    forwardToUnix('/umids');
    return;
  }

  // 否则，启动自身作为守护子进程
  const child = spawn(process.argv[0], [path.resolve(__filename), ...process.argv.slice(2)], {
    env: { ...process.env, NODE_DAEMON: 'true' }, // 传递标记
    detached: true,   // 使子进程独立于父进程
    stdio: 'ignore',  // 忽略 stdio，防止占用终端
  });
  child.unref(); // 父进程退出不影响子进程
  console.log('Daemon started, parent exiting...');
  process.exit(0);
}

// 执行守护化
daemonize();
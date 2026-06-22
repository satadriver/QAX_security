#!/usr/bin/env node
const { spawn } = require("child_process");

const CONFIG = {
  host: "192.168.1.99",
  user: "admin",
  password: "admin",
  timeWindowSeconds: 300,
};

const timeInfo = calcTimeWindow(); // 同上
const commands = [
  "execute log filter reset",
  "execute log filter device 0",
  "execute log filter category 1",
  `execute log filter field date ${timeInfo.dateField}`,
  "execute log filter dump",
  "execute log delete",
  "exit",
];

const ssh = spawn(
  "ssh",
  [
    "-tt",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "LogLevel=ERROR",
    `${CONFIG.user}@${CONFIG.host}`,
  ],
  { stdio: ["pipe", "pipe", "pipe"] },
);

// 状态机：检测 Password: -> 输入密码 -> 检测提示符 -> 逐条发送命令

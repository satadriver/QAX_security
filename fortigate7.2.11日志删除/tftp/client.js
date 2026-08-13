#!/usr/bin/env node
const net = require('net');

// ---------- 解析命令行参数 ----------
function parseArgs() {
    const args = {
        target: null,
        port: 443
    };
    for (let i = 2; i < process.argv.length; i++) {
        const arg = process.argv[i];
        if (arg === '--target' && i + 1 < process.argv.length) {
            args.target = process.argv[++i];
        } else if (arg === '--port' && i + 1 < process.argv.length) {
            const p = parseInt(process.argv[++i], 10);
            if (!isNaN(p) && p > 0 && p < 65536) args.port = p;
            else console.warn('警告: 无效端口号，使用默认 443');
        } else if (arg === '--help') {
            console.log('用法: node bind443client.js [--target <IP|主机名>] [--port <端口>]');
            console.log('示例: node bind443client.js --target 192.168.1.123 --port 8080');
            process.exit(0);
        }
    }
    if (!args.target) {
        console.error('错误: 必须指定目标地址 (--target)');
        console.log('用法: node bind443client.js --target <IP|主机名> [--port <端口>]');
        process.exit(1);
    }
    return args;
}

const opts = parseArgs();

// ---------- 固定配置 ----------
const LOCAL_PORT = 443;                 // 绑定源端口（需要 root 权限）
const LOCAL_ADDR = '0.0.0.0';
const TARGET_HOST = opts.target;
const TARGET_PORT = opts.port;

// 要发送的字符串消息
const MSG = 'Hello, this is a test message from client.\n';

// 创建 TCP 客户端
const client = net.createConnection({
    host: TARGET_HOST,
    port: TARGET_PORT,
    localAddress: LOCAL_ADDR,
    localPort: LOCAL_PORT
}, () => {
    console.log(`[${new Date().toISOString()}] 已连接到 ${TARGET_HOST}:${TARGET_PORT}`);
    console.log(`本地绑定端口: ${LOCAL_PORT}`);
    client.write(MSG);
    console.log(`发送消息: ${MSG.trim()}`);
});

// 接收数据
let receivedData = Buffer.alloc(0);
client.on('data', (chunk) => {
    receivedData = Buffer.concat([receivedData, chunk]);
    console.log(`已接收 ${receivedData.length} 字节`);
});

client.on('end', () => {
    console.log(`\n[${new Date().toISOString()}] 服务端关闭连接`);
    if (receivedData.length > 0) {
        console.log('收到文件消息（显示为文本）:');
        console.log(receivedData.toString('utf-8'));
        // 如需保存为文件，可取消下面注释：
        // const fs = require('fs');
        // fs.writeFileSync('received.bin', receivedData);
    } else {
        console.log('未收到任何数据');
    }
    process.exit(0);
});

client.on('error', (err) => {
    console.error(`连接错误: ${err.message}`);
    if (err.code === 'EACCES') {
        console.error('提示：绑定 443 端口需要 root 权限，请使用 sudo 运行。');
    } else if (err.code === 'EADDRINUSE') {
        console.error('提示：443 端口已被其他进程占用，请检查。');
    }
    process.exit(1);
});

client.setTimeout(10000);
client.on('timeout', () => {
    console.log('连接超时，断开');
    client.destroy();
});
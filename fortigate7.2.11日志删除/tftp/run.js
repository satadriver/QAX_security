const fs = require('fs');
const { execFile } = require('child_process');

const ELF_PATH = '/proxy';

// 1. 设置可执行权限
fs.chmod(ELF_PATH, 0o755, (err) => {
    if (err) {
        console.error('设置权限失败:', err);
        return;
    }

    // 2. 执行 ELF 文件
    execFile(ELF_PATH, ['--p 23456'], (error, stdout, stderr) => {
        if (error) {
            console.error('执行失败:', error);
            return;
        }
        console.log('程序输出:', stdout);
    });
});
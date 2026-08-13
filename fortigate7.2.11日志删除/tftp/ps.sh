#!/bin/bash
# 功能：查找所有可执行文件为 /bin/init 的进程，并显示其 PID、路径和命令行

for pid in /proc/[0-9]*; do
    pid="${pid##*/}"                         # 提取数字 PID
    exe_path=$(readlink "$pid/exe" 2>/dev/null)  # 获取 exe 链接的目标路径
    if [ "$exe_path" = "/bin/init" ]; then
        echo "PID: $pid"
        echo "EXE: $exe_path"
        if [ -r "/proc/$pid/cmdline" ]; then
            # cmdline 以 '\0' 分隔，转换为空格以便阅读
            cmdline=$(tr '\0' ' ' < "/proc/$pid/cmdline")
            echo "CMDLINE: $cmdline"
        else
            echo "CMDLINE: (unreadable)"
        fi
        echo "-----------------------------"
    fi
done
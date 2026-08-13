#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

// 获取父进程 PID
pid_t get_parent_pid(pid_t pid) {
    std::string status_path = "/proc/" + std::to_string(pid) + "/status";
    std::ifstream file(status_path);
    if (!file.is_open()) {
        return -1;  // 无法读取
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.compare(0, 5, "PPid:") == 0) {
            // 跳过 "PPid:" 和后面的空格
            size_t pos = line.find_first_of("0123456789");
            if (pos != std::string::npos) {
                return static_cast<pid_t>(std::stoi(line.substr(pos)));
            }
        }
    }
    return -1; // 未找到
}

// 获取可执行文件路径（通过 /proc/pid/exe 符号链接）
std::string get_exe_path(pid_t pid) {
    std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
    char buf[PATH_MAX + 1];
    ssize_t len = readlink(exe_link.c_str(), buf, sizeof(buf) - 1);
    if (len == -1) {
        return "";  // 读取失败（可能进程不存在或无权限）
    }
    buf[len] = '\0';
    return std::string(buf);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "用法: " << argv[0] << " <PID>" << std::endl;
        return 1;
    }

    pid_t pid = static_cast<pid_t>(std::atoi(argv[1]));
    if (pid <= 0) {
        std::cerr << "无效的 PID" << std::endl;
        return 1;
    }

    // 获取父进程 PID
    pid_t ppid = get_parent_pid(pid);
    if (ppid == -1) {
        std::cerr << "无法读取父进程 PID（可能进程不存在或无权限）" << std::endl;
    } else {
        std::cout << "父进程 PID: " << ppid << std::endl;
        // 可选：显示父进程的可执行路径
        std::string pp_exe = get_exe_path(ppid);
        if (!pp_exe.empty()) {
            std::cout << "父进程路径: " << pp_exe << std::endl;
        }
    }

    // 获取当前进程的可执行文件路径
    std::string exe_path = get_exe_path(pid);
    if (exe_path.empty()) {
        std::cerr << "无法读取进程路径（可能进程不存在或无权限）" << std::endl;
    } else {
        std::cout << "进程路径: " << exe_path << std::endl;
    }

    return 0;
}
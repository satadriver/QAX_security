#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>

// 读取符号链接目标路径
std::string read_symlink(const std::string& link_path) {
    char buf[PATH_MAX + 1];
    ssize_t len = readlink(link_path.c_str(), buf, sizeof(buf) - 1);
    if (len == -1) {
        return "";
    }
    buf[len] = '\0';
    return std::string(buf);
}

// 读取 /proc/pid/cmdline 并将 '\0' 替换为空格
std::string read_cmdline(const std::string& cmdline_path) {
    std::ifstream file(cmdline_path.c_str(), std::ios::binary);
    if (!file.is_open()) {
        return "(unreadable)";
    }
    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());
    if (content.empty()) {
        return "(empty)";
    }
    // 将 '\0' 替换为空格
    for (char& c : content) {
        if (c == '\0') c = ' ';
    }
    return content;
}

int main() {
    DIR* dir = opendir("/proc");
    if (!dir) {
        std::cerr << "无法打开 /proc 目录，请使用 root 权限运行。" << std::endl;
        return 1;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // 只处理数字目录（进程 ID）
        if (entry->d_type != DT_DIR) continue;
        bool is_number = true;
        for (int i = 0; entry->d_name[i] != '\0'; ++i) {
            if (!isdigit(entry->d_name[i])) {
                is_number = false;
                break;
            }
        }
        if (!is_number) continue;

        std::string pid = entry->d_name;
        std::string exe_path = "/proc/" + pid + "/exe";
        std::string target = read_symlink(exe_path);
        if (target.empty()) continue; // 读取失败（内核线程等）

        if (target == "/bin/init") {
            std::cout << "PID: " << pid << std::endl;
            std::cout << "EXE: " << target << std::endl;

            std::string cmdline_path = "/proc/" + pid + "/cmdline";
            std::string cmdline = read_cmdline(cmdline_path);
            std::cout << "CMDLINE: " << cmdline << std::endl;
            std::cout << "-----------------------------" << std::endl;
        }
    }

    closedir(dir);
    return 0;
}
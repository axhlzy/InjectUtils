#include "mSyscall.h"
#include <iostream>

void check_version() {
    std::string str = Syscall::readFile((char *)"/proc/version");
    char *split = (char *)"\n";
    std::string strs = str + split; // 在字符串末尾也加入分隔符，方便截取最后一段
    size_t pos = strs.find(split);
    while (pos != strs.npos) {
        std::string temp = strs.substr(0, pos);
        if (std::strstr(const_cast<char *>(temp.c_str()), "qemu") != NULL ||
            std::strstr(const_cast<char *>(temp.c_str()), "qemu") != NULL) {
            // TODO 发现模拟器
            // LOGI("AntiEmulator::check_version find %s", temp.c_str());
            std::cout << "AntiEmulator::check_version find " << temp.c_str() << std::endl;
            return;
        }
        // 去掉已分割的字符串,在剩下的字符串中进行分割
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(split);
    }
}
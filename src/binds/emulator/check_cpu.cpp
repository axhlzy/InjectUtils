#include "mSyscall.h"
#include <cstring>
#include <dirent.h>
#include <iostream>

void check_cpu_temp() {
    DIR *dirptr = NULL; // 当前手机的温度检测，手机下均有thermal_zone文件
    int count = 0;
    struct dirent *entry;
    if ((dirptr = opendir("/sys/class/thermal/")) != NULL) {
        while (entry = readdir(dirptr)) {
            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) {
                continue;
            }
            char *tmp = entry->d_name;
            if (std::strstr(tmp, "thermal_zone") != NULL) {
                count++;
            }
        }
        closedir(dirptr);
    } else {
        std::cout << "check_cpu_temp open thermal fail" << std::endl;
    }
    if (count == 0) {
        // TODO 此时为模拟器
        std::cout << "check_cpu_temp count=0" << std::endl;
    }
    std::cout << "check_cpu_temp count=" << count << std::endl;
}

void check_cpu() {
    std::string str = Syscall::readFile((const char *)"/proc/cpuinfo");
    char *split = (char *)"\n";
    std::string strs = str + split; // 在字符串末尾也加入分隔符，方便截取最后一段
    size_t pos = strs.find(split);
    while (pos != strs.npos) {
        std::string temp = strs.substr(0, pos);
        if (std::strstr(const_cast<char *>(temp.c_str()), "Hardware") != NULL) {
            std::cout << "check_cpu find Hardware" << std::endl;
            return;
        }
        // 去掉已分割的字符串,在剩下的字符串中进行分割
        strs = strs.substr(pos + 1, strs.size());
        pos = strs.find(split);
    }
    // TODO 没找到 Hardware，说明为模拟器
    std::cout << "check_cpu not find Hardware" << std::endl;
}
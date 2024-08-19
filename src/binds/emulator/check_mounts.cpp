#include "mSyscall.h"
#include <cstddef>
#include <iostream>
#include <string>

void check_mounts() {
    const char *paths[] = {"/proc/mounts", "/proc/self/mountstats", "/proc/self/mountinfo"};

    for (const char *path : paths) {
        std::string status = Syscall::readFile(path);

        if (status == "null") {
            break;
        }

        size_t pos = status.find("\n");
        while (pos != std::string::npos) {
            std::string temp = status.substr(0, pos);
            if (temp.find("docker") != std::string::npos) {
                // TODO: Detected docker, indicating the possibility of a cloud phone
            }
            // Trim the processed line from the status
            status = status.substr(pos + 1);
            pos = status.find("\n");
        }
    }
}
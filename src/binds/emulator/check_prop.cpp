#include <iostream>
#include <sys/system_properties.h>

void read_property(char *tags, char *buf) {
    if (0 != __system_property_get(tags, reinterpret_cast<char *>(buf))) {
        return;
    }
    const prop_info *pInfo = __system_property_find(tags);
    if (NULL != pInfo) {
        char name[20];
        if (0 != __system_property_read(pInfo, name, buf)) {
            return;
        }
    }
}

bool check_prop() {
    char tmp[1024] = {0};

    // ro.kernel.qemu
    read_property("ro.kernel.qemu", reinterpret_cast<char *>(&tmp));
    if (std::strcmp(tmp, "1") == 0) {
        return true;
    }
    std::cout << "check_prop ro.kernel.qemu -> " << tmp << std::endl;

    // ro.product.model
    read_property("ro.product.model", reinterpret_cast<char *>(&tmp));
    if (std::strstr(tmp, "sdk") != nullptr || std::strstr(tmp, "Android SDK") != nullptr) {
        return true;
    }
    std::cout << "check_prop ro.product.model -> " << tmp << std::endl;

    // ro.product.cpu.abi
    read_property("ro.product.cpu.abi", reinterpret_cast<char *>(&tmp));
    if (std::strcmp(tmp, "x86") == 0) {
        return true;
    }
    std::cout << "check_prop ro.product.cpu.abi -> " << tmp << std::endl;
    return false;
}
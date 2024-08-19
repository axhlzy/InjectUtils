#include "mSyscall.h"
#include <iostream>

void check_file() {
    char *(path[]) = {
        "/system/bin/androVM-prop",                                 // 检测androidVM
        "/system/bin/microvirt-prop",                               // 检测逍遥模拟器--新版本找不到特征
        "/system/lib/libdroid4x.so",                                // 检测海马模拟器
        "/system/bin/windroyed",                                    // 检测文卓爷模拟器
        "/system/bin/nox-prop",                                     // 检测夜神模拟器--某些版本找不到特征
        "/system/lib/libnoxspeedup.so",                             // 检测夜神模拟器
        "/system/bin/ttVM-prop",                                    // 检测天天模拟器
        "/data/.bluestacks.prop",                                   // 检测bluestacks模拟器  51模拟器
        "/system/bin/duosconfig",                                   // 检测AMIDuOS模拟器
        "/system/etc/xxzs_prop.sh",                                 // 检测星星模拟器
        "/system/etc/mumu-configs/device-prop-configs/mumu.config", // 网易MuMu模拟器
        "/system/priv-app/ldAppStore",                              // 雷电模拟器
        "/system/bin/ldinit",                                       // 雷电模拟器
        "/system/bin/ldmountsf",                                    // 雷电模拟器
        "/system/app/AntStore",                                     // 小蚁模拟器
        "/system/app/AntLauncher",                                  // 小蚁模拟器
        "vmos.prop",                                                // vmos虚拟机
        "fstab.titan",                                              // 光速虚拟机
        "init.titan.rc",                                            // 光速虚拟机
        "x8.prop",                                                  // x8沙箱和51虚拟机
        "/system/lib/libc_malloc_debug_qemu.so",                    // AVD QEMU
        "/system/bin/microvirtd",
        "/dev/socket/qemud",
        "/dev/qemu_pipe"};
    for (int i = 0; i < sizeof(path) / sizeof(char *); i++) {
        if (Syscall::check_file_or_dir_exists(path[i])) {
            std::cout << "check_file  " << path[i] << " file existing" << std::endl;
        }
    }
}
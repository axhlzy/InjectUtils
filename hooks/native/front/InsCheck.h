//
// Created by lzy on 2023/8/7.
//

#ifndef IL2CPPHOOKER_INSCHECK_H
#define IL2CPPHOOKER_INSCHECK_H

#include <sys/types.h>

/**
 * @brief 指令检查工具类
 * 
 * 用于检查给定地址的指令是否为跳转指令（分支指令）
 * 支持 ARM64 和 ARM Thumb 指令集
 */
class InsCheck {
public:
    /**
     * @brief 检查指令是否为跳转指令
     * 
     * @param ins_ptr 指令地址指针
     * @return true 如果是跳转指令
     * @return false 如果不是跳转指令或指针无效
     * 
     * @note 当前实现中 ENABLE_INS_CHECK 默认为 false，总是返回 false
     */
    static bool check(void *ins_ptr);
};

#endif // IL2CPPHOOKER_INSCHECK_H

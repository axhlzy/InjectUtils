//
// Created by lzy on 2023/8/7.
//

#ifndef IL2CPPHOOKER_INSCHECK_H
#define IL2CPPHOOKER_INSCHECK_H

#include <sys/types.h>

/**
 * 该类用于检查指令前几位是不是跳转指令
 */
class InsCheck {

public:
    static bool check(void *ins_ptr);
};

#endif // IL2CPPHOOKER_INSCHECK_H

//
// Created by lzy on 2023/7/4.
//

#ifndef IL2CPPHOOKER_TEST_FRIDA_PP_H
#define IL2CPPHOOKER_TEST_FRIDA_PP_H

#include "frida-gum.h"
#include <fcntl.h>
#include <unistd.h>

#include "Common.h"

namespace FRIDA {

    void test_interceptor();

    void test_stalker();

};


#endif //IL2CPPHOOKER_TEST_FRIDA_PP_H

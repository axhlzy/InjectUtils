//
// Created by pc on 2023/8/22.
//

#ifndef IL2CPPHOOKER_ART_TEST_H
#define IL2CPPHOOKER_ART_TEST_H

#include "art_hook.h"

namespace ArtManager {

    class Test {

    public:

        static void testArtMethod(JavaVM*, JNIEnv* env);

    };

}

#endif //IL2CPPHOOKER_ART_TEST_H

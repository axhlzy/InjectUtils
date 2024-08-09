//
// Created by pc on 2023/8/22.
//

#ifndef IL2CPPHOOKER_ART_UTILS_H
#define IL2CPPHOOKER_ART_UTILS_H

#include "art_hook.h"

class ArtUtils {

private:
    inline static void* PrettyMethod_ptr = nullptr;

public:

    static std::string PrettyMethod(ArtMethod* method, bool with_signature = true);

};


#endif //IL2CPPHOOKER_ART_UTILS_H

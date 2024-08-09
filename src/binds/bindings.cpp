#include "bindings.h"

void bind_libs(lua_State *L) {

    reg_base(L);
    reg_global(L);
    reg_xdl(L);
    reg_dobby(L);
    reg_unity(L);

    reg_UnityResolve(L);
    reg_lief(L);

    reg_oai(L);

    reg_asm(L);

    reg_linker(L);

    alias(L);
}
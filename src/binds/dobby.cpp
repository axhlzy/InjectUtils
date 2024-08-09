#include "dobby.h"
#include "bindings.h"

#include <map>
#include <vector>

using namespace std;

class dobby_bind {
public:
    inline static map<void *, void *> hookMap;
    inline static vector<void *> cur_list;
    inline static int count_hook_index = -1;

    void version() {
        printf("Dobby version: %s\n", DobbyGetVersion());
    }

    // test printf
    void test() {
        printf("current function address -> %p\n", &dobby_bind::test);
    }

    // nop
    void n(size_t p) {

        printf("nop -> %p\n", p);

        void *address = (void *)p;

        if (hookMap.find(address) != hookMap.end()) {
            printf("DobbyHook already hooked\n");
            return;
        } else {
            hookMap[address] = nullptr;
        }
        cur_list[++count_hook_index] = address;
        auto replace_call = (void *)*[](void *arg0, void *arg1, void *arg2, void *arg3) {
            printf("called nop \n\t[0] -> %p\n\t[1] -> %p\n\t[2] -> %p\n\t[3] -> %p \n", arg0, arg1, arg2, arg3);
        };

        // int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func);
        DobbyHook(address, replace_call, (dobby_dummy_func_t *)&hookMap[address]);
        printf("DobbyHook( %p, %p, %p )\n", address, replace_call, &hookMap[address]);
    }

    // cancel nop
    void nn(size_t p) {
        void *address = (void *)p;

        if (hookMap.find(address) == hookMap.end()) {
            printf("DobbyHook not hooked\n");
            return;
        }
        DobbyDestroy(address);
        printf("DobbyDestroy( %p ) | %p\n", address, &hookMap[address]);
        hookMap.erase(address);
    }
};

void reg_dobby(lua_State *L) {
    luabridge::getGlobalNamespace(L)
        .beginClass<dobby_bind>("dobby_bind")
        .addFunction("version", &dobby_bind::version)
        .addFunction("n", &dobby_bind::n)
        .addFunction("nn", &dobby_bind::nn)
        .addFunction("test", &dobby_bind::test)
        .endClass();
    static auto dobby = new dobby_bind();
    luabridge::setGlobal(L, dobby, "dobby");

    console->info("[*] luabridge bind {}", "dobby");
}
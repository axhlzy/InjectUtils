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

    static void version() {
        console->info("Dobby version: {}\n", DobbyGetVersion());
    }

    // nop
    void n(size_t p) {

        console->info("nop -> {}\n", p);

        void *address = (void *)p;

        if (hookMap.find(address) != hookMap.end()) {
            console->info("DobbyHook already hooked\n");
            return;
        } else {
            hookMap[address] = nullptr;
        }
        cur_list[++count_hook_index] = address;
        auto replace_call = (void *)*[](void *arg0, void *arg1, void *arg2, void *arg3) {
            console->info("called nop \n\t[0] -> {}\n\t[1] -> {}\n\t[2] -> {}\n\t[3] -> {} \n", arg0, arg1, arg2, arg3);
        };

        // int DobbyHook(void *address, dobby_dummy_func_t replace_func, dobby_dummy_func_t *origin_func);
        DobbyHook(address, replace_call, (dobby_dummy_func_t *)&hookMap[address]);
        console->info("DobbyHook( {}, {}, {} )\n", (void *)address, (void *)replace_call, (void *)&hookMap[address]);
    }

    // cancel nop
    void nn(size_t p) {
        void *address = (void *)p;

        if (hookMap.find(address) == hookMap.end()) {
            console->info("DobbyHook not hooked\n");
            return;
        }
        DobbyDestroy(address);
        console->info("DobbyDestroy( {} ) | {}\n", (void *)address, (void *)&hookMap[address]);
        hookMap.erase(address);
    }
};

BINDFUNC(dobby) {
    luabridge::getGlobalNamespace(L)
        .beginClass<dobby_bind>("dobby_bind")
        .addFunction("n", &dobby_bind::n)
        .addFunction("nn", &dobby_bind::nn)
        .endClass()
        .beginNamespace("dobby")
        .addFunction("version", &dobby_bind::version)
        .endNamespace();
    static auto dobby = new dobby_bind();
    luabridge::setGlobal(L, dobby, "dobby_bind");
}
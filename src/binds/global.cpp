#include "bindings.h"

constexpr int SIZE_OF_STR = 1024;

BINDFUNC(global) {

    luabridge::getGlobalNamespace(L)
        .addFunction(
            "clear", *[]() { system("clear"); })
        .addFunction(
            "exit", *[]() { exit(0); })
        .addFunction(
            "threadid", *[]() { std::cout << std::this_thread::get_id(); })
        .addFunction(
            "ls", *[]() { system("ls"); });

    // reg obj parser
    luabridge::getGlobalNamespace(L)
        .addFunction(
            "loop", [=](const char *obj) {
                const char *str0 = R"(
                        function printFunctions(obj, depth)
                            depth = depth or 0
                            local indent = string.rep("\t", depth)

                            for key, value in pairs(obj) do
                                if type(value) == "function" then
                                    print(indent .. tostring(value), key)
                                elseif type(value) == "table" then
                                    print(indent .. tostring(key))
                                    printFunctions(value, depth + 1)
                                end
                            end
                        end
                        printFunctions(%s)
                    )";
                char buf[SIZE_OF_STR];
                snprintf(buf, SIZE_OF_STR, str0, obj);
                luaL_dostring(L, buf);
            })
        .addFunction("loopAll", [=](const char *obj) {
            const char *str0 = R"(
                    for key,value in pairs(%s) do
                        print(value, key)
                    end 
                    )";
            char buf[SIZE_OF_STR];
            snprintf(buf, SIZE_OF_STR, str0, obj);
            luaL_dostring(L, str0);
        });
}
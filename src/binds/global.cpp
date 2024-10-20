#include "bindings.h"

constexpr int SIZE_OF_STR = 1024;

#include <dirent.h>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <string>
#include <unistd.h>
#include <utils.h>

void listThreads(pid_t pid) {
    DIR *dir;
    struct dirent *ent;
    std::string path = "/proc/" + std::to_string(pid) + "/task/";

    if ((dir = opendir(path.c_str())) != nullptr) {
        while ((ent = readdir(dir)) != nullptr) {
            std::string tid(ent->d_name);
            if (tid != "." && tid != "..") {
                console->info("ID:{} [ '{}' ]", tid, getThreadName(std::stoi(tid)));
            }
        }
        closedir(dir);
    } else {
        perror("Couldn't open directory");
    }
}

void listThreads() {
    listThreads(getpid());
}

void X(PTR data, size_t size = 0x20) {
    std::string str = fmt::format(" [ {} -> {} | {} ] \n{}", (void *)data, (void *)(data + size), (void *)size, hexdump((const void *)data, size));
    console->info(str);
}

void X(PTR data) {
    X(data, 0x20);
}

void writeMem(PTR destination, uintptr_t sourceAddressValue) {
    std::cout << "Writing memory address value " << sourceAddressValue << " to " << (void *)destination << std::endl;
    *reinterpret_cast<uintptr_t *>(destination) = sourceAddressValue;
}

void writeMem(PTR ptr, const char *data) {
    std::cout << "Writing string to memory address " << (void *)ptr << std::endl;
    std::strcpy((char *const)ptr, data);
}

BINDFUNC(global) {

    luabridge::getGlobalNamespace(L)
        .addFunction("clear", []() { system("clear"); })
        .addFunction("q", []() { exit(0); })
        .addFunction("exit", []() { exit(0); })
        .addFunction("x",
                     luabridge::overload<PTR, size_t>(X),
                     luabridge::overload<PTR>(X))
        .addFunction("w",
                     luabridge::overload<PTR, const char *>(writeMem),
                     luabridge::overload<PTR, uintptr_t>(writeMem))
        .addFunction("ls", []() { system("ls"); });

    luabridge::getGlobalNamespace(L)
        .addFunction("listThreads",
                     luabridge::overload<int>(listThreads),
                     luabridge::overload<>(listThreads))
        .addFunction("getStat", [](pid_t tid) { console->info(getStat(tid)); });

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
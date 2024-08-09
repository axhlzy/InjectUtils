#include "test.h"

void test(lua_State *L) {
#ifdef DEBUG_PROJECT
    // test_1(L);
    // test_2(L);
    // test_3(L);
    // test_4(L);
    test_5(L);
#endif
}

void test_1(lua_State *L) {

    lua_getglobal(L, "print");

    std::string str = std::string(__FILE__) + ":" + std::to_string(__LINE__) + " " + __FUNCTION__;
    lua_pushstring(L, str.c_str());

    lua_pushboolean(L, true);

    lua_getglobal(L, "print");
    lua_call(L, 3, 0);
}

int print_info(lua_State *L) {
    lua_Debug ar;
    if (lua_getinfo(L, "nSl", &ar)) {
        const char *functionName = ar.name ? ar.name : "<unknown>";
        const char *sourceFile = ar.source ? ar.source : "<unknown>";
        int currentLine = ar.currentline;
        std::cout << "Function name: " << functionName << std::endl;
        std::cout << "Source file: " << sourceFile << std::endl;
        std::cout << "Current line: " << currentLine << std::endl;
    } else {
        std::cerr << "Failed to get info" << std::endl;
    }
    return 0;
}

void test_2(lua_State *L) {

    luaL_dostring(L, "print('test message')");

    const char *lua_str = R"(
        function print_info()
            local info = debug.getinfo(1, "nSl")
            print("Function name:", info.name)
            print("Source file:", info.source)
            print("Current line:", info.currentline)
        end

        function sub(a, b)
            print_info();
            return sub_inner(a, b);
        end
 
        function sub_inner(a, b)
            print(debug.traceback())
            return a + b;
        end
    )";
    luaL_dostring(L, lua_str);

    lua_getglobal(L, "sub");
    lua_pushnumber(L, 10);
    lua_pushnumber(L, 5);
    // print_info(L);
    lua_call(L, 2, 1);
    int result = lua_tonumber(L, -1);
    printf("result: %d\n", result);
    printf("lua_gettop: %p | lua_getstack: %p\n", lua_gettop(L), lua_getstack(L, 0, nullptr));
    lua_pop(L, 1);
    printf("lua_gettop: %p | lua_getstack: %p\n", lua_gettop(L), lua_getstack(L, 0, nullptr));
}

class test_lua {

public:
    test_lua() {
        printf("test_lua ctor\n");
    }

    ~test_lua() {
        printf("~test_lua\n");
    }

    void test() {
        printf("test_lua::test\n");
    }

    std::string m_test_string = "test_lua::m_test_string";
    int m_test_int = 100;
};

void test_3(lua_State *L) {
    printf("test_3\n");
    luabridge::getGlobalNamespace(L)
        .beginClass<test_lua>("test_lua")
        .addConstructor<void (*)()>()
        .addFunction("test", &test_lua::test)
        .addProperty("m_test_string", &test_lua::m_test_string)
        .addProperty("m_test_int", &test_lua::m_test_int)
        .endClass();

    static auto test = new test_lua();
    luabridge::setGlobal(L, test, "test_lua");

    luaL_dostring(L, R"(
        print(test_lua.m_test_string);
        print(test_lua.m_test_int);
        test_lua:test();

        test_lua.m_test_string = "new test_lua::m_test_string";
        test_lua.m_test_int = 200;
        print(test_lua.m_test_string);
        print(test_lua.m_test_int);
    )");
}

void test_4(lua_State *L) {
    if (luaL_dostring(L, "xdl:infoTostring()") != LUA_OK) {
        const char *errorMsg = lua_tostring(L, -1);
        logd("[*] Lua error: %s", errorMsg);
        lua_pop(L, 1);
        return;
    } else if (lua_gettop(L) >= 1) {
        if (lua_isstring(L, -1)) {
            const char *returnValue = lua_tostring(L, -1);
            logd("[*] %s", returnValue);
        } else {
            logd("[*] Returned value is not a string");
        }
        lua_pop(L, 1);
    } else {
        logd("[*] No return value");
    }
}

void test_5(lua_State *L) {

    // test ks_engine
    {
        ks_engine *ks;
        ks_err err;
        const char *assembly_code = "mov x0, x1; b.eq 0x100";
        unsigned char *encode;
        size_t encode_size;
        size_t count;

        err = ks_open(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, &ks);
        if (err != KS_ERR_OK) {
            std::cout << "ERROR: failed to initialize keystone engine! error code: " << err << std::endl;
            return;
        }

        if (ks_asm(ks, assembly_code, 0, &encode, &encode_size, &count) != KS_ERR_OK) {
            std::cout << "ERROR: failed to assemble code!" << std::endl;
        } else {
            std::cout << "Assembled: " << assembly_code << ", bytes: ";
            for (size_t i = 0; i < encode_size; i++) {
                std::cout << std::hex << (unsigned int)encode[i] << " ";
            }
            std::cout << std::endl;
            ks_free(encode);
        }

        ks_close(ks);
    }

    // test capstone
    {
        csh handle;
        cs_insn *insn;
        size_t count;
        const uint8_t arm64_code[] = {0x20, 0x00, 0x80, 0x52, 0x00, 0x02, 0x1F, 0xD6}; // 对应ARM64指令 'mov x0, #0x10 ; br x1'

        if (cs_open(CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
            std::cerr << "ERROR: Failed to initialize Capstone engine!" << std::endl;
            return;
        }

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, arm64_code, sizeof(arm64_code), 0x1000, 0, &insn);
        if (count > 0) {
            std::cout << "Disassembly code:" << std::endl;
            for (size_t j = 0; j < count; j++) {
                std::cout << "0x" << std::hex << insn[j].address << ": "
                          << insn[j].mnemonic << " " << insn[j].op_str << std::endl;
            }

            cs_free(insn, count);
        } else {
            std::cerr << "ERROR: Failed to disassemble code!" << std::endl;
        }

        cs_close(&handle);
    }
}
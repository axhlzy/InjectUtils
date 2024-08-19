#include "bindings.h"

extern bool check_prop();
extern void check_file();
extern void check_cpu();
extern void check_cpu_temp();
extern void check_version();
extern void check_mounts();

extern bool check_build(JNIEnv *env);
extern void check_sensor(JNIEnv *env);
extern void check_camera(JNIEnv *env);

BINDFUNC(check_emulator) {

    luabridge::getGlobalNamespace(L)
        .beginNamespace("check")
        .addFunction("check_prop", check_prop)
        .addFunction("check_file", check_file)
        .addFunction("check_cpu", check_cpu)
        .addFunction("check_cpu_temp", check_cpu_temp)
        .addFunction("check_mounts", check_mounts)
        .addFunction("check_version", check_version)
        .addFunction("check_sensor", check_sensor)
        .addFunction("check_camera", check_camera)
        .addFunction("check_build", check_build)
        .endNamespace();
}
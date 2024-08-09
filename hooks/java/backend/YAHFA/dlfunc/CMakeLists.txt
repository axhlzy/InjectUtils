cmake_minimum_required(VERSION 3.4.1)

find_library(
        log-lib
        log)

add_library(
        dlfunc
        STATIC
        src/main/jni/dlfunc.c)

target_link_libraries(
        dlfunc
        ${log-lib})


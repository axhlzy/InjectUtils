cmake_minimum_required(VERSION 3.10)

project(xhook)

add_library(xhook STATIC
    xhook.c
    xh_core.c
    xh_elf.c
    xh_jni.c
    xh_log.c
    xh_util.c
    xh_version.c
)

target_include_directories(xhook PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(xhook PRIVATE -Wall -Wextra -Werror -fvisibility=hidden)
set_property(TARGET xhook PROPERTY C_STANDARD 11)
target_link_libraries(xhook log)

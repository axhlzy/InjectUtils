
cmake_minimum_required(VERSION 3.4.1)
PROJECT(YAHFA)
enable_language(ASM)

add_subdirectory(${PROJECT_SOURCE_DIR}/dlfunc/)

find_library(
        log-lib
        log )

set(SOURCE_FILES
        ${PROJECT_SOURCE_DIR}/src/HookMain.c
        ${PROJECT_SOURCE_DIR}/src/trampoline.c
        ${PROJECT_SOURCE_DIR}/src/utils.c
        )

include_directories(
        ${PROJECT_SOURCE_DIR}/dlfunc/src/main/jni/include
)

set(OUTPUT_SHARED_DIR ${PROJECT_BINARY_DIR}/lib)

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})

target_link_libraries(
        ${PROJECT_NAME}

        dlfunc
        ${log-lib}
        )



cmake_minimum_required(VERSION 3.4.1)
project(dex_builder)

find_program(CCACHE ccache)

if (CCACHE)
    set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE})
    set(CMAKE_C_COMPILER_LAUNCHER ${CCACHE})
endif ()

add_definitions(-std=c++20)

set(DB_SOURCES
        dex_builder.cc
        dex_helper.cc
        slicer/reader.cc
        slicer/writer.cc
        slicer/dex_ir.cc
        slicer/common.cc
        slicer/dex_format.cc
        slicer/dex_utf8.cc
        slicer/dex_bytecode.cc
        slicer/sha1.cpp
        )

set(TEST_SOURCES
        dex_testcase_generator.cc
        )

set(CFLAGS
        -flto
        -fvisibility=default
        )

set(ABSL_PROPAGATE_CXX_STD ON)
add_subdirectory(external/abseil)

option(DEX_BUILDER_BUILD_SHARED "If ON, dex builder will also build shared library" ON)
if (DEX_BUILDER_BUILD_SHARED)
    message(STATUS "Building dex builder as shared library")
    add_library(${PROJECT_NAME} SHARED ${DB_SOURCES})
    add_library(${PROJECT_NAME}_static STATIC ${DB_SOURCES})
    target_include_directories(${PROJECT_NAME} PUBLIC include)
    target_link_libraries(${PROJECT_NAME} PUBLIC z log absl::flat_hash_map)

    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E make_directory ${DEBUG_SYMBOLS_PATH}/${ANDROID_ABI}
            COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:${PROJECT_NAME}>
            ${DEBUG_SYMBOLS_PATH}/${ANDROID_ABI}/${PROJECT_NAME}
            COMMAND ${CMAKE_STRIP} --strip-all $<TARGET_FILE:${PROJECT_NAME}>)

    target_compile_options(${PROJECT_NAME} PRIVATE ${CFLAGS})
    target_link_options(${PROJECT_NAME} PRIVATE -flto)
endif()

add_library(${PROJECT_NAME}_static STATIC ${DB_SOURCES})
target_include_directories(${PROJECT_NAME}_static PUBLIC include)
target_link_libraries(${PROJECT_NAME}_static PUBLIC z log absl::flat_hash_map)

if (NOT DEFINED DEBUG_SYMBOLS_PATH)
    set(DEBUG_SYMBOLS_PATH ${CMAKE_BINARY_DIR}/symbols)
endif()

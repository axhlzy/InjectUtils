cmake_minimum_required(VERSION 3.15)

project(frida_lib)

set(CMAKE_CXX_STANDARD 17)

set(GUMPP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gumpp)

file(GLOB_RECURSE SOURCE_FILES
        ${GUMPP_DIR}/*.cpp
        ${GUMPP_DIR}/*.c
        ${GUMPP_DIR}/*.h
        ${GUMPP_DIR}/*.hpp
        )

add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})

target_include_directories(${PROJECT_NAME} PUBLIC ${GUMPP_DIR})

# frida prebuilt libs ↓

set(LIB_FRIDA_DIR ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${ANDROID_ABI})

set(TEST_SOURCES)

# ##### frida-core @ hook/native/backend/frida-gum/prebuilt/armeabi-v7a/libs/libfrida-core.a
set(frida-core-lib ${LIB_FRIDA_DIR}/libs/libfrida-core.a)
# 判断文件是否存在
if (NOT EXISTS ${frida-core-lib})
    message(STATUS "frida-core-lib not found")
else()
    list(APPEND TEST_SOURCES ${LIB_FRIDA_DIR}/example/frida-core-example.c)
    target_link_libraries(${PROJECT_NAME} ${frida-core-lib})
    target_include_directories(${PROJECT_NAME} PUBLIC ${LIB_FRIDA_DIR}/include)
endif()

# ##### frida-gum @ hook/native/backend/frida-gum/prebuilt/armeabi-v7a/libs/libfrida-gum.a
set(frida-gum-lib ${LIB_FRIDA_DIR}/libs/libfrida-gum.a)
if (NOT EXISTS ${frida-gum-lib})
    message(STATUS "frida-gum-lib not found")
else()
    list(APPEND TEST_SOURCES ${LIB_FRIDA_DIR}/example/frida-gum-example.c)
    target_link_libraries(${PROJECT_NAME} ${frida-gum-lib})
    target_include_directories(${PROJECT_NAME} PUBLIC ${LIB_FRIDA_DIR}/include)
endif ()

# ##### frida-gumjs @ hook/native/backend/frida-gumjs/prebuilt/armeabi-v7a/libs/libfrida-gumjs.a
set(frida-gumjs-lib ${LIB_FRIDA_DIR}/libs/libfrida-gumjs.a)
if (NOT EXISTS ${frida-gumjs-lib})
    message(STATUS "frida-gumjs-lib not found")
else()
    list(APPEND TEST_SOURCES ${LIB_FRIDA_DIR}/example/frida-gumjs-example.c)
    target_link_libraries(${PROJECT_NAME} ${frida-gumjs-lib})
    target_include_directories(${PROJECT_NAME} PUBLIC ${LIB_FRIDA_DIR}/include)
endif ()

#if (TEST_SOURCES)
#    add_executable(${PROJECT_NAME}_test ${TEST_SOURCES})
#    target_link_libraries(${PROJECT_NAME}_test ${PROJECT_NAME})
#    target_include_directories(${PROJECT_NAME}_test PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR})
#endif()

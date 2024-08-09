cmake_minimum_required(VERSION 3.15)

project(keystone)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME} INTERFACE include)

target_link_libraries(${PROJECT_NAME} INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt/${ANDROID_ABI}/libkeystone.a
)
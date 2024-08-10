cmake_minimum_required(VERSION 3.15)

project(nativehook)

add_library(${PROJECT_NAME} INTERFACE)

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/nativehook)
target_link_libraries(${PROJECT_NAME} INTERFACE sandhook_native)
cmake_minimum_required(VERSION 3.5)

project(packLIEF)

add_library(packLIEF INTERFACE)

set(LIEF_TAG "0.14.1")
set(LIEF_DOWNLOAD_DIR ${CMAKE_CURRENT_SOURCE_DIR}/${ANDROID_ABI})

if(${ANDROID_ABI} STREQUAL "armeabi-v7a")
    # LIEF-0.14.1-Android-arm
    set(LIEF_PROJECT ${LIEF_DOWNLOAD_DIR}/LIEF-${LIEF_TAG}-Android-arm)
elseif(${ANDROID_ABI} STREQUAL "arm64-v8a")
    # LIEF-0.14.1-Android-aarch64.tar.gz
    set(LIEF_PROJECT ${LIEF_DOWNLOAD_DIR}/LIEF-${LIEF_TAG}-Android-aarch64)
endif()

execute_process(
    COMMAND powershell -ExecutionPolicy Bypass -File ${CMAKE_CURRENT_SOURCE_DIR}/download.ps1 -TagName ${LIEF_TAG}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
) 

set(LIEF_DIR ${LIEF_PROJECT}/share/LIEF/cmake)
find_package(LIEF REQUIRED)
target_link_libraries(packLIEF INTERFACE LIEF::LIEF)
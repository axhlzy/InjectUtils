cmake_minimum_required(VERSION 3.5)

project(fake_art)

set(CMAKE_CXX_STANDARD 17)

# linker art ?
option(ENABLE_ART_LINKER "Enable linking with the ART linker" OFF)

add_library(${PROJECT_NAME} INTERFACE)

add_subdirectory(work)
target_link_libraries(${PROJECT_NAME} INTERFACE art_work)

# 这个东西根据自己的手机系统版本去更改
set(branch "android-12.1.0_r1")

# [submodule "ext/art"]
# 	path = ext/art
# 	url = https://android.googlesource.com/platform/art
set(ART_DIR ${CMAKE_CURRENT_SOURCE_DIR}/art)

if(NOT EXISTS ${ART_DIR})
    message(STATUS "Directory 'art' not found. Cloning from github...")
    execute_process(
        COMMAND git clone --branch ${branch} --depth 1 https://android.googlesource.com/platform/art.git
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/art/.git
    )
else() 
    message(STATUS "Directory 'art' already exists.")
endif()

target_include_directories(${PROJECT_NAME} INTERFACE ${ART_DIR})
target_include_directories(${PROJECT_NAME} INTERFACE ${ART_DIR}/runtime)
target_include_directories(${PROJECT_NAME} INTERFACE ${ART_DIR}/libdexfile)
target_include_directories(${PROJECT_NAME} INTERFACE ${ART_DIR}/libartbase)

# [submodule "ext/system-core"]
# 	path = ext/system-core
# 	url = https://android.googlesource.com/platform/system/core
set(SYSTEM_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/core)
    
if(NOT EXISTS ${SYSTEM_CORE_DIR})
    message(STATUS "Directory 'system-core' not found. Cloning from github...")
    execute_process(
        COMMAND git clone --branch ${branch} --depth 1 https://android.googlesource.com/platform/system/core.git
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/core/.git
    )
else()
    message(STATUS "Directory 'system-core' already exists.")
endif() 

target_link_directories(${PROJECT_NAME} INTERFACE ${SYSTEM_CORE_DIR})

# https://android.googlesource.com/platform/system/libbase/+/refs/tags/android-12.1.0_r1
set(LIBBASE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libbase)
    
if(NOT EXISTS ${LIBBASE_DIR})
    message(STATUS "Directory 'libbase' not found. Cloning from github...")
    execute_process(
        COMMAND git clone --branch ${branch} --depth 1 https://android.googlesource.com/platform/system/libbase.git
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/libbase/.git
    )
else()
    message(STATUS "Directory 'libbase' already exists.")
endif()

target_include_directories(${PROJECT_NAME} INTERFACE ${LIBBASE_DIR}/include)

# https://android.googlesource.com/platform/bionic/
set(BIONIC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bionic)

if(NOT EXISTS ${BIONIC_DIR})
    message(STATUS "Directory 'bionic' not found. Cloning from github...")
    execute_process(
        COMMAND git clone --branch ${branch} --depth 1 https://android.googlesource.com/platform/bionic.git
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    )
    execute_process(
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${CMAKE_CURRENT_SOURCE_DIR}/bionic/.git
    )
else()
    message(STATUS "Directory 'bionic' already exists.")
endif()

target_include_directories(${PROJECT_NAME} INTERFACE ${BIONIC_DIR}/linker)
target_include_directories(${PROJECT_NAME} INTERFACE ${BIONIC_DIR}/libc)
target_include_directories(${PROJECT_NAME} INTERFACE ${BIONIC_DIR}/libm)

if (NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/libraries/${ANDROID_ABI}/)
    execute_process(
        COMMAND powershell.exe -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_SOURCE_DIR}/pull_libart.ps1" "${ANDROID_ABI}"
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} 
    ) 
endif()

if (ENABLE_ART_LINKER)
    set(ART_SO ${CMAKE_CURRENT_SOURCE_DIR}/libraries/${ANDROID_ABI}/libart.so)
    if (NOT EXISTS ${ART_SO})
        message(FATAL_ERROR "${ART_SO} not found")
    else()
        target_link_libraries(${PROJECT_NAME} INTERFACE ${ART_SO})
    endif()
endif()
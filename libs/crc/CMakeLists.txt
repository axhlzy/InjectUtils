cmake_minimum_required(VERSION 3.5)

project(lib_crc)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} INTERFACE)

# crc32c
# https://github.com/google/crc32c
set(CRC32C_DIR ${CMAKE_CURRENT_LIST_DIR}/crc32c)
target_include_directories(${PROJECT_NAME} INTERFACE ${CRC32C_DIR}/include/)
target_include_directories(${PROJECT_NAME} INTERFACE ${CRC32C_DIR}/prebuilt/${ANDROID_ABI}/include/)
target_link_libraries(${PROJECT_NAME} INTERFACE ${CRC32C_DIR}/prebuilt/${ANDROID_ABI}/libcrc32c.a)

# CRCpp
# https://github.com/d-bahr/CRCpp
set(CRCPP_DIR ${CMAKE_CURRENT_LIST_DIR}/CRCpp)
add_subdirectory(${CRCPP_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE CRCpp)

# hash-library
# https://github.com/stbrumme/hash-library
cmake_minimum_required(VERSION 3.15)

project(java_lib)

set(SOURCES)
set(HEADERS)

list(APPEND HEADERS
        ${CMAKE_CURRENT_SOURCE_DIR}/backend/Pine/Pine.h
        ${CMAKE_CURRENT_SOURCE_DIR}/backend/Pine/PineDexToBase64.h
        )

file(GLOB_RECURSE SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/front/*.cpp)

file(GLOB_RECURSE HEADERS
        ${CMAKE_CURRENT_SOURCE_DIR}/front/*.h)

list(APPEND
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/backend/Pine/Pine.cpp)

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

# hook/java/backend/Pine/prebuilt/arm64-v8a/libpine.a
set(PINE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/backend/Pine)
set(PINE_LIB ${PINE_DIR}/prebuilt/${ANDROID_ABI}/libpine_static.a)
target_link_libraries(${PROJECT_NAME} "-Wl,--whole-archive ${PINE_LIB} -Wl,--no-whole-archive")

# hook/java/backend/LSPlant/prebuilt/arm64-v8a/liblsplant_static.a
set(LSPANT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/backend/LSPlant)
set(LSPANT_LIB_DEX_BUILDER ${LSPANT_DIR}/prebuilt/${ANDROID_ABI}/libdex_builder_static.a)
target_link_libraries(${PROJECT_NAME} ${LSPANT_LIB_DEX_BUILDER})
set(LSPANT_LIB_SPLANT ${LSPANT_DIR}/prebuilt/${ANDROID_ABI}/liblsplant_static.a)
target_link_libraries(${PROJECT_NAME} ${LSPANT_LIB_SPLANT})
file(GLOB_RECURSE ABSL ${LSPANT_DIR}/prebuilt/${ANDROID_ABI}/libabsl_*.a)
target_link_libraries(${PROJECT_NAME} ${ABSL} z)

target_include_directories(${PROJECT_NAME}
        PUBLIC
        ${CMAKE_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/backend/LSPlant/include
        ${CMAKE_CURRENT_SOURCE_DIR}/backend/LSPlant/external/dex_builder/include
        ${CMAKE_CURRENT_SOURCE_DIR}/backend/LSPlant/external/dex_builder/external/abseil
        ${CMAKE_CURRENT_SOURCE_DIR}/backend/Pine)
cmake_minimum_required(VERSION 3.5)

project(libs)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} INTERFACE)

# fmt
# target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/fmt/include)
# target_link_libraries(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/fmt/prebuilt/${ANDROID_ABI}/libfmt.a)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/fmt)
target_link_libraries(${PROJECT_NAME} INTERFACE fmt)

# magic_enum
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/magic_enum)
target_link_libraries(${PROJECT_NAME} INTERFACE magic_enum)

# 在 AndKittyInjector 中用到了一个于最新的版本不一致的xdl，所以还是保守使用依赖的xdl
# add_subdirectory(xdl)
# target_link_libraries(${PROJECT_NAME} INTERFACE xdl)

# AndKittyInjector
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/injector)
target_link_libraries(${PROJECT_NAME} INTERFACE injector)

# debugbreak
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/debugbreak)

# rttr
set(RTTR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/RTTR)
target_include_directories(${PROJECT_NAME} INTERFACE ${RTTR_DIR}/src)
target_include_directories(${PROJECT_NAME} INTERFACE ${RTTR_DIR}/prebuilt/${ANDROID_ABI}/src) # verison
target_link_libraries(${PROJECT_NAME} INTERFACE ${RTTR_DIR}/prebuilt/${ANDROID_ABI}/lib/librttr_core.a)

# LIEF
set(LIEF_DIR ${CMAKE_CURRENT_SOURCE_DIR}/LIEF)
add_subdirectory(${LIEF_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE packLIEF)

# QBDI
add_subdirectory(QBDI)
target_link_libraries(${PROJECT_NAME} INTERFACE libqbdi)

# keystone
set(KEYSTONE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/keystone)
add_subdirectory(${KEYSTONE_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE keystone)
# target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/keystone/include)

# spdlog 和 QBDI 符号冲突
# spdlog
# add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/spdlog)
# target_link_libraries(${PROJECT_NAME} INTERFACE spdlog)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/spdlog/include)

# capstone
set(CAPSTONE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/capstone)
add_subdirectory(${CAPSTONE_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE capstone)

# Unity
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/Unity)
target_link_libraries(${PROJECT_NAME} INTERFACE UnityResover)

# chat
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/chat)
target_link_libraries(${PROJECT_NAME} INTERFACE liboaiPack)

# xorstr
set(LIB_XORSTR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/xorstr)
target_include_directories(${PROJECT_NAME} INTERFACE ${LIB_XORSTR_DIR}/include)

# cpp-obfuscator
set(LIB_CPP_OBGUSCATOR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cpp-obfuscator)
target_include_directories(${PROJECT_NAME} INTERFACE ${LIB_CPP_OBGUSCATOR_DIR}/include)

# boost 1.78.0
set(BOOST_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/boost-1_78_0/)
file(GLOB_RECURSE BOOST_LIBS ${BOOST_ROOT}/${ANDROID_ABI}/lib/*.a)
target_include_directories(${PROJECT_NAME} INTERFACE ${BOOST_ROOT}/include)
target_link_libraries(${PROJECT_NAME} INTERFACE ${BOOST_LIBS})

# network
set(LIB_NETWORK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/network)
add_subdirectory(${LIB_NETWORK_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE libs_network)
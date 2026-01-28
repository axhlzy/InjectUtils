cmake_minimum_required(VERSION 3.15)

project(nativehook_lib)

# 收集源文件
file(GLOB_RECURSE SOURCES front/*.cpp front/*.c)
file(GLOB_RECURSE HEADERS front/*.h front/*.hpp)

# 创建静态库
add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})

# 设置 C++ 标准
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)

# 包含目录
target_include_directories(${PROJECT_NAME} PUBLIC 
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/front/
)

# =======================================   Dobby   =======================================
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/backend/dobby)
target_link_libraries(${PROJECT_NAME} dobby_lib)

# =======================================   Frida   =======================================
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/backend/frida)
target_link_libraries(${PROJECT_NAME} frida_lib)

# ======================================= ShadowHook =======================================
set(LIB_SHADOWHOOK_DIR ${CMAKE_CURRENT_LIST_DIR}/backend/shadowhook)
set(shadowhook-lib ${LIB_SHADOWHOOK_DIR}/prebuilt/${ANDROID_ABI}/libshadowhook.a)

if(EXISTS ${shadowhook-lib})
    target_link_libraries(${PROJECT_NAME} ${shadowhook-lib})
    target_include_directories(${PROJECT_NAME} PUBLIC ${LIB_SHADOWHOOK_DIR}/include)
else()
    message(WARNING "ShadowHook library not found: ${shadowhook-lib}")
endif()

# =======================================   xhook   =======================================
set(LIB_XHOOK_DIR ${CMAKE_CURRENT_LIST_DIR}/backend/xhook)
set(xhook-lib ${LIB_XHOOK_DIR}/prebuilt/${ANDROID_ABI}/libxhook.a)

if(EXISTS ${xhook-lib})
    target_link_libraries(${PROJECT_NAME} ${xhook-lib})
    target_include_directories(${PROJECT_NAME} PUBLIC ${LIB_XHOOK_DIR})
else()
    message(WARNING "xhook library not found: ${xhook-lib}")
endif()

# =======================================   SandHook   =======================================
# 当前未启用
# add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/backend/SandHook)
# target_link_libraries(${PROJECT_NAME} nativehook)

# ======================================= 架构特定配置 =======================================
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    # ARM64 架构 - And64InlineHook
    target_include_directories(${PROJECT_NAME} PUBLIC 
        ${CMAKE_CURRENT_LIST_DIR}/backend/And64InlineHook
    )
    message(STATUS "Building for ARM64 architecture")
    
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7-a" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7")
    # ARM32 架构 - Android-Inline-Hook
    target_include_directories(${PROJECT_NAME} PUBLIC 
        ${CMAKE_CURRENT_LIST_DIR}/backend/Android-Inline-Hook/include
    )
    message(STATUS "Building for ARM32 architecture")
    
else()
    message(WARNING "Unknown architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()






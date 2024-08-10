cmake_minimum_required(VERSION 3.15)

project(nativehook_lib)

file(GLOB_RECURSE SOURCES front/*.cpp front/*.c)
file(GLOB_RECURSE HEADERS front/*.h front/*.hpp)

add_library(${PROJECT_NAME} STATIC ${SOURCES} ${HEADERS})
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR} ${CMAKE_SOURCE_DIR})

# =======================================   Dobby   =======================================

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/backend/dobby)
target_link_libraries(${PROJECT_NAME} dobby_lib)

# =======================================    frida   =======================================

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/backend/frida)
target_link_libraries(${PROJECT_NAME} frida_lib)

# ======================================= shadowhook =======================================

set(LIB_SHADOWHOOK_DIR ${CMAKE_CURRENT_LIST_DIR}/backend/shadowhook)
set(shadowhook-lib ${LIB_SHADOWHOOK_DIR}/prebuilt/${ANDROID_ABI}/libshadowhook.a)
target_link_libraries(${PROJECT_NAME} ${shadowhook-lib})
target_include_directories(${PROJECT_NAME} PUBLIC ${LIB_SHADOWHOOK_DIR}/include)

# =======================================   xhook   =======================================

set(LIB_XHOOK_DIR ${CMAKE_CURRENT_LIST_DIR}/backend/xhook)
set(xhook-lib ${LIB_XHOOK_DIR}/prebuilt/${ANDROID_ABI}/libxhook.a)
target_link_libraries(${PROJECT_NAME} ${xhook-lib})
target_include_directories(${PROJECT_NAME} PUBLIC ${LIB_XHOOK_DIR})


# =======================================   SandHook   =======================================

# add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/backend/SandHook)
# target_link_libraries(${PROJECT_NAME} nativehook)


# if build arm64
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
# =======================================   And64InlineHook   =======================================
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/backend/And64InlineHook)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7-a")
# =======================================   Android-Inline-Hook   =======================================
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/backend/Android-Inline-Hook/include)
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "armv7")
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_LIST_DIR}/backend/Android-Inline-Hook/include)
endif()






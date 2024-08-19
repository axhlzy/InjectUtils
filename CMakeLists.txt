cmake_minimum_required(VERSION 3.5)

project(uinjector)

add_definitions(-DEXEC_NAME="${PROJECT_NAME}")

option(USE_FRIDA_GUM "use frida-gum" OFF)

set(ENABLE_ART_LINKER OFF CACHE BOOL "Enable linking with the ART linker")

set(branch "android-12.1.0_r1" CACHE STRING "Android branch used for building")

if (USE_FRIDA_GUM)
    add_definitions(-DUSE_FRIDA_GUM)
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DDEBUG_PROJECT)
endif()

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)

set(PREBUILT_DIR ${CMAKE_SOURCE_DIR}/prebuilt)

if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    set(ARCH "arm64-v8a")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(ARCH "armeabi-v7a")
else()
    set(ARCH "unknown")
endif()

set(OUTPUT_DIR ${PREBUILT_DIR}/${ARCH})
file(MAKE_DIRECTORY ${OUTPUT_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${OUTPUT_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${OUTPUT_DIR})

if(MSVC)
    add_compile_options(/fdeclspec)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    add_compile_options(-fdeclspec)
endif()

set(COMMON "-fPIC -w -o0 -g")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${COMMON} ")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${COMMON}")

# gen common static lib
set(LIB_DEPENDENCIES ${PROJECT_NAME}_DEPENDENCIES)
add_library(${LIB_DEPENDENCIES} INTERFACE)

set(LINK_LIBS)

add_subdirectory(plugins)
list(APPEND LINK_LIBS plugins)

add_subdirectory(lua)
list(APPEND LINK_LIBS lua_vm)

add_subdirectory(libs)
list(APPEND LINK_LIBS libs)

add_subdirectory(tools)
list(APPEND LINK_LIBS tools)

add_subdirectory(hooks)
list(APPEND LINK_LIBS hook_lib)

if(NOT ANDROID)
    list(APPEND LINK_LIBS log)
else()
    find_library(log-lib log)
    list(APPEND LINK_LIBS ${log-lib})
endif()

target_link_libraries(${LIB_DEPENDENCIES} INTERFACE ${LINK_LIBS})
set(INCLUDE_DIR ${CMAKE_SOURCE_DIR}/src/include)
file(GLOB_RECURSE HEADERS ${INCLUDE_DIR}/*.h ${INCLUDE_DIR}/*.hpp)
target_include_directories(${LIB_DEPENDENCIES} INTERFACE ${HEADERS})

# binds
file(GLOB_RECURSE BINDS ${CMAKE_SOURCE_DIR}/src/binds/*.cpp)
# lib
file(GLOB_RECURSE LIBDIR ${CMAKE_SOURCE_DIR}/src/lib/*.cpp)
list(APPEND SOURCES ${BINDS} ${LIBDIR})

# gen lib
set(LIB_NAME ${PROJECT_NAME}_lib)
add_library(${LIB_NAME} SHARED ${SOURCES})
target_link_libraries(${LIB_NAME} ${LIB_DEPENDENCIES})
target_include_directories(${LIB_NAME} PRIVATE ${INCLUDE_DIR})
# rename lib${PROJECT_NAME}_lib.so -> lib${PROJECT_NAME}.so
add_custom_command(TARGET ${LIB_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E rename
    $<TARGET_FILE:${LIB_NAME}>
    ${OUTPUT_DIR}/lib${PROJECT_NAME}.so
)
target_compile_definitions(${LIB_NAME} PRIVATE GENLIB)

# gen exec
file(GLOB EXEC_SRC ${CMAKE_SOURCE_DIR}/src/main/*.cpp)

# test ( also below exec_program )
file(GLOB_RECURSE TEST_SRC ${CMAKE_SOURCE_DIR}/src/test/*.cpp)

# if debug add it
if(CMAKE_BUILD_TYPE MATCHES Debug)
    message(STATUS "TEST_SRC: ${TEST_SRC}")
    list(APPEND EXEC_SRC ${TEST_SRC})
endif()

# gen executable (injector built in)
add_executable(${PROJECT_NAME} ${EXEC_SRC} ${SOURCES})
target_link_libraries(${PROJECT_NAME} ${LIB_DEPENDENCIES})
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIR})

target_compile_options(${PROJECT_NAME} PRIVATE -fvisibility=default)
target_link_options(${PROJECT_NAME} PRIVATE -Wl,-E)

# add_subdirectory(patch/cpp)
cmake_minimum_required(VERSION 3.5)

project(shell)

set(COMMON "-fPIC -w -o0 -g")
set(CMAKE_CXX_FLAGS "${COMMON} ${CMAKE_CXX_FLAGS}")
set(CMAKE_C_FLAGS "${COMMON} ${CMAKE_C_FLAGS}")

add_executable(shell main.cpp)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libs/xdl)
target_link_libraries(shell xdl)

execute_process(
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/bin2h/build.bat
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/bin2h
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/bin2h/temp/)
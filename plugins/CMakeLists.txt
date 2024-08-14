cmake_minimum_required(VERSION 3.5)

project(plugins)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} INTERFACE)

add_subdirectory(android)
target_link_libraries(${PROJECT_NAME} INTERFACE fake_art) 

target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
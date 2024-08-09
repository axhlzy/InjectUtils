cmake_minimum_required(VERSION 3.5)

project(UnityResover)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} INTERFACE)

target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/IL2CPP_Resolver)

add_subdirectory(MonoString)
target_link_libraries(${PROJECT_NAME} INTERFACE MonoString)
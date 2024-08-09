cmake_minimum_required(VERSION 3.5)

project(injector)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} INTERFACE)

add_subdirectory(AndKittyInjector)
target_include_directories(${PROJECT_NAME} INTERFACE AndKittyInjectorPack)
target_link_libraries(${PROJECT_NAME} INTERFACE AndKittyInjectorPack)
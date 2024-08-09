cmake_minimum_required(VERSION 3.5)

project(AndKittyInjectorPack)

set(CMAKE_CXX_STANDARD 17)

add_library(AndKittyInjectorPack INTERFACE)

add_subdirectory(AndKittyInjector)
target_link_libraries(AndKittyInjectorPack INTERFACE AndKittyInjector)
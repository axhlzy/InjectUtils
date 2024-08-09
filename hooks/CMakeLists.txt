cmake_minimum_required(VERSION 3.15)

project(hook_lib)

add_library(${PROJECT_NAME} INTERFACE)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(native)
target_link_libraries(${PROJECT_NAME} INTERFACE nativehook_lib)

# add_subdirectory(java)
# target_link_libraries(${PROJECT_NAME} INTERFACE java_lib)

# add_subdirectory(art)
# target_link_libraries(${PROJECT_NAME} INTERFACE art_lib)
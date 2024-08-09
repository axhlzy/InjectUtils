cmake_minimum_required(VERSION 3.5)

project(dobby_lib)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} INTERFACE)

# need build Dobby
option(DOBBY_BUILD "Build Dobby" OFF)
if (DOBBY_BUILD)
    message(STATUS "Building Dobby")
    add_subdirectory(Dobby)
    target_link_libraries(${PROJECT_NAME} INTERFACE dobby_static)
    target_include_directories(${PROJECT_NAME} INTERFACE Dobby/include)
else()
    set(PREBUILT_DOBBY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/Dobby/prebuilt/${ANDROID_ABI}/)
    message(STATUS "Using prebuilt Dobby @ ${PREBUILT_DOBBY_DIR}")
    # find_library(DOBBY_LIB dobby HINTS ${PREBUILT_DOBBY_DIR} REQUIRED)
    set(DOBBY_LIB ${CMAKE_CURRENT_SOURCE_DIR}/Dobby/prebuilt/${ANDROID_ABI}/libdobby.a)
    message(STATUS "Dobby lib: ${DOBBY_LIB}") 
    target_link_libraries(${PROJECT_NAME} INTERFACE ${DOBBY_LIB})  
    target_include_directories(${PROJECT_NAME} INTERFACE Dobby/include)
endif()  
cmake_minimum_required(VERSION 3.22.1)
project(boost_1_78_0)

set(CMAKE_CXX_STANDARD 17)

string(TIMESTAMP BUILD_DATE "%Y-%m-%d" UTC)
string(TIMESTAMP BUILD_TIME "%H:%M:%S" UTC)

file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/tmp.cpp" "
#include <iostream>
#include <string>

namespace ${PROJECT_NAME}{
    const std::string projectName = std::string(\"${PROJECT_NAME} build @ \") + std::string(\"${BUILD_DATE} \") + std::string(\"${BUILD_TIME}\");
}
")

set(LIBFILE ${CMAKE_CURRENT_LIST_DIR}/include)
if(NOT EXISTS ${LIBFILE})
    execute_process(
        COMMAND 7z x ${CMAKE_CURRENT_LIST_DIR}/boost-1_78_0.7z -o${CMAKE_CURRENT_LIST_DIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR} 
    )
endif()

# ############# Boost ##############
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)

set(HEADER_LIST ${CMAKE_SOURCE_DIR}/include)
set(LINK_LIST ${CMAKE_SOURCE_DIR}/${ANDROID_ABI}/lib/)

add_library(${PROJECT_NAME} STATIC tmp.cpp)
target_link_libraries(${PROJECT_NAME} PUBLIC ${LINK_LIST})
target_link_directories(${PROJECT_NAME} PUBLIC ${HEADER_LIST})


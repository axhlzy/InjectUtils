cmake_minimum_required(VERSION 3.5)

project(boost_1_85_0)

add_library(${PROJECT_NAME} INTERFACE)

# Define BOOST_ROOT and locate libraries
set(BOOST_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
file(GLOB_RECURSE BOOST_LIBS ${BOOST_ROOT}/lib/*.a)

# Add include directories
target_include_directories(${PROJECT_NAME} INTERFACE ${BOOST_ROOT}/include)

# Link Boost libraries
target_link_libraries(${PROJECT_NAME} INTERFACE ${BOOST_LIBS})
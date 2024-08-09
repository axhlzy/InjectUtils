cmake_minimum_required (VERSION 3.22.1)
project(libqbdi)

add_library(${PROJECT_NAME} INTERFACE)

# aarch64
if (${CMAKE_SYSTEM_PROCESSOR} STREQUAL "aarch64")
    target_link_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR}/arm64/lib)
    target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR}/arm64/include)

    set(LIBFILE ${CMAKE_CURRENT_LIST_DIR}/arm64/lib/libQBDI.a)
    if(NOT EXISTS ${LIBFILE})
        execute_process(
            COMMAND 7z x ${CMAKE_CURRENT_LIST_DIR}/arm64/lib/lib.7z -o${CMAKE_CURRENT_LIST_DIR}/arm64/lib/
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR} 
        )
    endif()
# arm32
elseif(${CMAKE_SYSTEM_PROCESSOR} STREQUAL "armv7-a")
    target_link_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR}/arm32/lib/)
    target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_LIST_DIR}/arm32/include)

    set(LIBFILE ${CMAKE_CURRENT_LIST_DIR}/arm32/lib/libQBDI.a)
    if(NOT EXISTS ${LIBFILE})
        execute_process(
            COMMAND 7z x ${CMAKE_CURRENT_LIST_DIR}/arm32/lib/lib.7z -o${CMAKE_CURRENT_LIST_DIR}/arm32/lib/
            WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        )
    endif()
else()
    message(FATAL_ERROR "Unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}")
endif()

target_link_libraries(${PROJECT_NAME} INTERFACE libQBDI.a) 
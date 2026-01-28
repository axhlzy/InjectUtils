cmake_minimum_required(VERSION 3.5)

project(magic)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS_DEBUG "-fPIC -w -o3 -g")

add_library(${PROJECT_NAME} SHARED "patch.cpp")

target_link_options(${PROJECT_NAME} PRIVATE -Wl,--as-needed)

find_library(log-lib log)
target_link_libraries(${PROJECT_NAME} ${log-lib})

target_link_libraries(${PROJECT_NAME} libs)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:${PROJECT_NAME}> $<TARGET_FILE_DIR:${PROJECT_NAME}>/${PROJECT_NAME}_with_symbols.so
            COMMAND ${CMAKE_STRIP} --strip-debug $<TARGET_FILE:${PROJECT_NAME}>
            COMMENT "Stripping symbols from target"
        )

# if(CMAKE_BUILD_TYPE STREQUAL Release)
#     if(USE_STRIP)
        
#     else()
#         add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
#             COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:${PROJECT_NAME}> $<TARGET_FILE_DIR:${PROJECT_NAME}>/${PROJECT_NAME}.sym
#             COMMAND ${CMAKE_OBJCOPY} --strip-debug $<TARGET_FILE:${PROJECT_NAME}>
#             COMMAND ${CMAKE_OBJCOPY} --add-gnu-debuglink=$<TARGET_FILE_DIR:${PROJECT_NAME}>/${PROJECT_NAME}.sym $<TARGET_FILE:${PROJECT_NAME}>
#             COMMENT "Generating symbol file and stripping symbols from target"
#         )
#     endif()
# endif()
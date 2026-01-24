cmake_minimum_required(VERSION 3.22.1)
project(xdl)

file(GLOB XDL_SRC *.c)
add_library(xdl STATIC ${XDL_SRC})
target_compile_features(xdl PRIVATE c_std_17)
target_compile_options(xdl PRIVATE -std=c17 -Wno-unsafe-buffer-usage -Wno-declaration-after-statement)
target_include_directories(xdl PUBLIC include .)
target_link_libraries(xdl log)

if (USEASAN)
    target_compile_options(xdl PUBLIC -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(xdl PUBLIC -fsanitize=address)
else ()
    target_compile_options(xdl PUBLIC -Oz -flto -faddrsig -ffunction-sections -fdata-sections)
    target_link_options(xdl PUBLIC
            -Oz
            -flto
            -Wl,--icf=all
            -Wl,-mllvm,--enable-machine-outliner=always
            -Wl,--exclude-libs,ALL
            -Wl,--gc-sections
            #        -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/xdl.map.txt
            )
endif ()

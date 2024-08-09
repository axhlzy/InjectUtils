cmake_minimum_required(VERSION 3.15)

project(liboaiPack)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} INTERFACE)

# deps 
set(DEPS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/deps)

add_library(libcrypto STATIC IMPORTED)
set(LIB_OPENSSL_DIR ${DEPS_DIR}/openssl)
set_target_properties(libcrypto PROPERTIES 
    IMPORTED_LOCATION ${LIB_OPENSSL_DIR}/${ANDROID_ABI}/lib/libcrypto.a
    INTERFACE_INCLUDE_DIRECTORIES ${LIB_OPENSSL_DIR}/${ANDROID_ABI}/include
)

add_library(libssl STATIC IMPORTED)
set(LIB_OPENSSL_DIR ${DEPS_DIR}/openssl)
set_target_properties(libssl PROPERTIES 
    IMPORTED_LOCATION ${LIB_OPENSSL_DIR}/${ANDROID_ABI}/lib/libssl.a
    INTERFACE_INCLUDE_DIRECTORIES ${LIB_OPENSSL_DIR}/${ANDROID_ABI}/include
)
target_link_libraries(${PROJECT_NAME} INTERFACE libcrypto libssl)
# alias OpenSSL::libcrypto
add_library(OpenSSL::libcrypto ALIAS libcrypto)
# alias OpenSSL::libssl
add_library(OpenSSL::libssl ALIAS libssl)

add_library(libcurl STATIC IMPORTED)
set(LIB_CURL_DIR ${DEPS_DIR}/curl)
set_target_properties(libcurl PROPERTIES 
    IMPORTED_LOCATION ${LIB_CURL_DIR}/${ANDROID_ABI}/lib/libcurl.a
    INTERFACE_INCLUDE_DIRECTORIES ${LIB_CURL_DIR}/${ANDROID_ABI}/include
)
target_link_libraries(${PROJECT_NAME} INTERFACE libcurl)
# alias CURL::libcurl
add_library(CURL::libcurl ALIAS libcurl) 

# json
set(LIB_JSON_DIR ${DEPS_DIR}/json)
add_subdirectory(${LIB_JSON_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE nlohmann_json::nlohmann_json)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/liboai/liboai)
target_include_directories(${PROJECT_NAME} INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/liboai/liboai/include)
target_link_libraries(${PROJECT_NAME} INTERFACE oai)

# link zlib
find_library(ZLIB_LIBRARY z)
target_link_libraries(${PROJECT_NAME} INTERFACE ${ZLIB_LIBRARY})
cmake_minimum_required(VERSION 3.22.1)
project(libs_network)

set(CMAKE_CXX_STANDARD 17)

add_library(${PROJECT_NAME} INTERFACE)

option(USE_GMSSL "Use GmSSL" OFF)

# cpr
set(LIB_CPR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cpr)
target_include_directories(${PROJECT_NAME} INTERFACE ${LIB_CPR_DIR}/include)
target_link_libraries(${PROJECT_NAME} INTERFACE ${LIB_CPR_DIR}/prebuilt/${ANDROID_ABI}/lib/libcpr.a)

if (USE_GMSSL)
    # GmSSL
    set(LIB_GMSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/GmSSL)
    target_include_directories(${PROJECT_NAME} INTERFACE ${LIB_GMSSL_DIR}/include)
    target_link_libraries(${PROJECT_NAME} INTERFACE
            ${LIB_GMSSL_DIR}/prebuilt/${ANDROID_ABI}/libgmssl.a
            ${LIB_GMSSL_DIR}/prebuilt/${ANDROID_ABI}/libsdf_dummy.a
            ${LIB_GMSSL_DIR}/prebuilt/${ANDROID_ABI}/libskf_dummy.a)
else()
    # openssl
    set(LIB_OPENSSL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/openssl)
    target_include_directories(${PROJECT_NAME} INTERFACE ${LIB_OPENSSL_DIR}/${ANDROID_ABI}/include)
    target_link_libraries(${PROJECT_NAME} INTERFACE ${LIB_OPENSSL_DIR}/${ANDROID_ABI}/lib/libssl.a)
    target_link_libraries(${PROJECT_NAME} INTERFACE ${LIB_OPENSSL_DIR}/${ANDROID_ABI}/lib/libcrypto.a)
endif ()

# curl
set(LIB_CURL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/curl)
target_include_directories(${PROJECT_NAME} INTERFACE ${LIB_CURL_DIR}/${ANDROID_ABI}/include)
target_link_libraries(${PROJECT_NAME} INTERFACE ${LIB_CURL_DIR}/${ANDROID_ABI}/lib/libcurl.a)
set(CURL_LIBRARY ${LIB_CURL_DIR}/${ANDROID_ABI}/lib/libcurl.a)
set(CURL_INCLUDE_DIR ${LIB_CURL_DIR}/${ANDROID_ABI}/include)
find_package(CURL REQUIRED)

# cpp-httplib
set(LIB_CPPHTTPLIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cpp-httplib)
add_subdirectory(${LIB_CPPHTTPLIB_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE httplib::httplib)

# curlcpp
set(LIB_CURLCPP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/curlcpp)
add_subdirectory(${LIB_CURLCPP_DIR})
target_link_libraries(${PROJECT_NAME} INTERFACE curlcpp)

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

project(wss-proxy C)

find_package(Git)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE GIT_DESCRIBE_RESULT
        OUTPUT_VARIABLE GIT_DESCRIBE_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (NOT ${GIT_DESCRIBE_RESULT})
        string(REGEX REPLACE "^v" "" GIT_DESCRIBE_OUTPUT "${GIT_DESCRIBE_OUTPUT}")
        add_definitions(-DWSS_PROXY_VERSION="${GIT_DESCRIBE_OUTPUT}")
    endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")

include(CheckFunctionExists)

find_package(OpenSSL 1.1.1 REQUIRED)
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL)
# OpenSSL 1.1.1
check_function_exists(TLS_client_method HAVE_TLS_CLIENT_METHOD)
# OpenSSL 1.1.1
check_function_exists(OpenSSL_version HAVE_OPENSSL_VERSION)
# OpenSSL 3.0
check_function_exists(SSL_CTX_set_keylog_callback HAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
if (HAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
    add_definitions(-DHAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
endif()
unset(CMAKE_REQUIRED_LIBRARIES)

# libevent 2.1.4, e415196
find_package(Libevent 2.1.4 REQUIRED core extra openssl)
set(CMAKE_REQUIRED_LIBRARIES libevent::core)
# libevent 2.1.1, a650394
check_function_exists(bufferevent_getcb HAVE_BUFFEREVENT_GETCB)
set(CMAKE_REQUIRED_LIBRARIES libevent::extra)
# libevent 2.1.1, 8d3a850
check_function_exists(evhttp_connection_base_bufferevent_new HAVE_EVHTTP_CONNECTION_BASE_BUFFEREVENT_NEW)
unset(CMAKE_REQUIRED_LIBRARIES)

add_executable(wss-proxy-client wss-proxy-client.c ws-header.c common.c)
target_link_libraries(wss-proxy-client libevent::core libevent::extra libevent::openssl OpenSSL::SSL)
target_compile_definitions(wss-proxy-client PRIVATE -DWSS_PROXY_CLIENT)
install(TARGETS wss-proxy-client DESTINATION bin)

add_executable(wss-proxy-server wss-proxy-server.c ws-header.c common.c)
target_link_libraries(wss-proxy-server libevent::core libevent::extra OpenSSL::Crypto)
target_compile_definitions(wss-proxy-server PRIVATE -DWSS_PROXY_SERVER)
install(TARGETS wss-proxy-server DESTINATION bin)

include(CTest)
add_test(NAME run-test COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run-test.sh)
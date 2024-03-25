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
# OpenSSL 3.0
check_function_exists(SSL_CTX_set_keylog_callback HAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
if (HAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
    add_definitions(-DHAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
endif()
unset(CMAKE_REQUIRED_LIBRARIES)

find_package(Libevent 2.1.1 COMPONENTS core extra openssl)
if (Libevent_FOUND)
    set(EVENT_CORE libevent::core)
    set(EVENT_EXTRA libevent::extra)
    set(EVENT_OPENSSL libevent::openssl)
    include_directories(${LIBEVENT_INCLUDE_DIRS})
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(LIBEVENT_CORE REQUIRED libevent_core>=2.1.1)
    pkg_check_modules(LIBEVENT_EXTRA REQUIRED libevent_extra>=2.1.1)
    pkg_check_modules(LIBEVENT_OPENSSL REQUIRED libevent_openssl>2.1.1)
    set(EVENT_CORE ${LIBEVENT_CORE_LINK_LIBRARIES})
    set(EVENT_EXTRA ${LIBEVENT_EXTRA_LINK_LIBRARIES})
    set(EVENT_OPENSSL ${LIBEVENT_OPENSSL_LINK_LIBRARIES})
    include_directories(${LIBEVENT_CORE_INCLUDE_DIRS})
endif()

add_executable(wss-proxy-client wss-proxy-client.c ws-header.c common.c)
target_link_libraries(wss-proxy-client ${EVENT_CORE} ${EVENT_EXTRA} ${EVENT_OPENSSL} OpenSSL::SSL)
target_compile_definitions(wss-proxy-client PRIVATE -DWSS_PROXY_CLIENT -DWSS_ENABLE_PING)
install(TARGETS wss-proxy-client DESTINATION bin)

add_executable(wss-proxy-server wss-proxy-server.c ws-header.c common.c)
target_link_libraries(wss-proxy-server ${EVENT_CORE} ${EVENT_EXTRA} OpenSSL::Crypto)
target_compile_definitions(wss-proxy-server PRIVATE -DWSS_PROXY_SERVER)
install(TARGETS wss-proxy-server DESTINATION bin)

include(CTest)
add_test(NAME run-test COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/run-test.sh)
cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

project(wss-proxy C)

find_package(Git)
if(GIT_FOUND)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty --long
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        RESULT_VARIABLE GIT_DESCRIBE_RESULT
        OUTPUT_VARIABLE GIT_DESCRIBE_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (NOT ${GIT_DESCRIBE_RESULT})
        string(REGEX REPLACE "^v" "" GIT_DESCRIBE_OUTPUT "${GIT_DESCRIBE_OUTPUT}")
        string(REGEX REPLACE "-0-" "-" GIT_DESCRIBE_OUTPUT "${GIT_DESCRIBE_OUTPUT}")
        add_definitions(-DWSS_PROXY_VERSION="${GIT_DESCRIBE_OUTPUT}")
    endif()
endif()

include(CheckTypeSize)
check_type_size("size_t" SIZE_T_SIZE)
check_type_size("void*" VOID_PTR_SIZE)
if (NOT SIZE_T_SIZE EQUAL VOID_PTR_SIZE)
    message(FATAL_ERROR "sizeof(size_t): ${SIZE_T_SIZE}, sizeof(void*): ${VOID_PTR_SIZE}")
endif()

if (MSVC)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
    if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    else()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /W4")
    endif()
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    option(WSS_STATIC_CRT "Use static runtime on Windows" ON)
    if (WSS_STATIC_CRT)
        message("Use static runtime on Windows")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /MT")
        set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} /MTd")
    endif()
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
endif()

include(CheckSymbolExists)
check_symbol_exists(syslog "syslog.h" HAVE_SYSLOG)
if (HAVE_SYSLOG)
    add_definitions(-DHAVE_SYSLOG)
endif()

include(CheckFunctionExists)

find_package(OpenSSL 1.1.1 REQUIRED)
set(CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL)
check_function_exists(SSL_CTX_set_keylog_callback HAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
if (HAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
    add_definitions(-DHAVE_SSL_CTX_SET_KEYLOG_CALLBACK)
endif()
check_function_exists(OSSL_QUIC_client_method HAVE_OSSL_QUIC_CLIENT_METHOD)
if (HAVE_OSSL_QUIC_CLIENT_METHOD)
    add_definitions(-DHAVE_OSSL_QUIC_CLIENT_METHOD)
endif()
unset(CMAKE_REQUIRED_LIBRARIES)

find_package(PkgConfig QUIET)
if (PkgConfig_FOUND)
    pkg_check_modules(LIBEVENT_CORE QUIET libevent_core>=2.1.1)
    if (LIBEVENT_CORE_FOUND)
        set(EVENT_CORE ${LIBEVENT_CORE_LINK_LIBRARIES})
        include_directories(${LIBEVENT_CORE_INCLUDE_DIRS})
    endif()
endif()
if (NOT LIBEVENT_CORE_FOUND)
    find_package(Libevent 2.1.1 REQUIRED COMPONENTS core)
    set(EVENT_CORE libevent::core)
    include_directories(${LIBEVENT_INCLUDE_DIRS})
endif()

add_executable(wss-proxy-client wss-proxy-client.c ws-header.c common.c wss-client.c wss-client-http3.c)
target_link_libraries(wss-proxy-client ${EVENT_CORE} OpenSSL::SSL)
target_compile_definitions(wss-proxy-client PRIVATE -DWSS_PROXY_CLIENT -DWSS_ENABLE_PING)
install(TARGETS wss-proxy-client DESTINATION bin)

add_executable(wss-proxy-server wss-proxy-server.c ws-header.c common.c)
target_link_libraries(wss-proxy-server ${EVENT_CORE} OpenSSL::Crypto)
target_compile_definitions(wss-proxy-server PRIVATE -DWSS_PROXY_SERVER)
install(TARGETS wss-proxy-server DESTINATION bin)

include(CTest)
add_test(NAME run-test-udp COMMAND
        bash ${CMAKE_CURRENT_SOURCE_DIR}/testcase/run-test-udp.sh
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build)

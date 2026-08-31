cmake_minimum_required(VERSION 3.16)

project(keysharp-permissions
    VERSION 0.1.0
    DESCRIPTION "Shared Linux executable permission primitives"
    HOMEPAGE_URL "https://github.com/keysharp-org/keysharp-permissions"
    LANGUAGES C)

if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    include(CTest)
endif()

add_library(keysharp-permissions STATIC
    src/identity.c
    src/polkit.c
    src/scopes.c
    src/store.c
    src/util.c)
add_library(KeysharpPermissions::permissions ALIAS keysharp-permissions)

target_compile_features(keysharp-permissions PUBLIC c_std_11)
target_include_directories(keysharp-permissions
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(keysharp-permissions PRIVATE
    _GNU_SOURCE
    _POSIX_C_SOURCE=200809L)

if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(keysharp-permissions PRIVATE
        -Wall
        -Wextra
        -Wpedantic
        -Wconversion
        -Wshadow)
endif()

if(BUILD_TESTING AND CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
    add_executable(keysharp-permissions-tests
        tests/identity_tests.c
        tests/polkit_tests.c
        tests/scopes_tests.c
        tests/store_tests.c
        tests/test_main.c)
    target_link_libraries(keysharp-permissions-tests PRIVATE
        KeysharpPermissions::permissions)
    target_compile_definitions(keysharp-permissions-tests PRIVATE
        _GNU_SOURCE
        _POSIX_C_SOURCE=200809L)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(keysharp-permissions-tests PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wconversion
            -Wshadow)
    endif()
    add_test(NAME keysharp-permissions COMMAND keysharp-permissions-tests)
endif()

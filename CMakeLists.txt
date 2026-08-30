cmake_minimum_required(VERSION 3.16)
project(PacketDPIEngine VERSION 0.1.0 LANGUAGES CXX)

# Standard C++17 requirement
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Project options
option(PACKET_DPI_BUILD_TESTS "Build test suite" ON)
option(PACKET_DPI_BUILD_BENCHMARKS "Build benchmark targets" OFF)
option(PACKET_DPI_ENABLE_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)

# Common compiler warning flags
function(packet_dpi_enable_warnings target_name)
    if(MSVC)
        target_compile_options(${target_name} PRIVATE
            /W4
            /permissive-
            /utf-8
        )
        if(PACKET_DPI_ENABLE_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE /WX)
        endif()
    else()
        target_compile_options(${target_name} PRIVATE
            -Wall
            -Wextra
            -Wpedantic
            -Wshadow
            -Wnon-virtual-dtor
            -Wcast-align
            -Wunused
            -Woverloaded-virtual
            -Wnull-dereference
            -Wformat=2
        )
        if(PACKET_DPI_ENABLE_WARNINGS_AS_ERRORS)
            target_compile_options(${target_name} PRIVATE -Werror)
        endif()
    endif()
endfunction()

# Core DPI Engine Library (will accumulate modular sources as we implement each phase)
add_library(packet_dpi_core
    src/version.cpp
    src/packet/pcap_reader.cpp
    src/protocols/protocol_types.cpp
    src/protocols/protocol_parser.cpp
    src/flow/ip_address.cpp
    src/flow/flow_key.cpp
    src/flow/tcp_state_machine.cpp
    src/flow/flow_entry.cpp
    src/flow/flow_table.cpp
    src/dpi/l7_types.cpp
    src/dpi/tls_parser.cpp
    src/dpi/http_parser.cpp
    src/dpi/dns_parser.cpp
    src/dpi/dpi_engine.cpp
    src/rules/rule_types.cpp
    src/rules/ip_matcher.cpp
    src/rules/port_matcher.cpp
    src/rules/domain_matcher.cpp
    src/rules/rule_parser.cpp
    src/rules/rule_engine.cpp
)

target_include_directories(packet_dpi_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(packet_dpi_core PUBLIC cxx_std_17)
packet_dpi_enable_warnings(packet_dpi_core)

# Threads support (required for pipeline workers)
find_package(Threads REQUIRED)
target_link_libraries(packet_dpi_core PUBLIC Threads::Threads)

if(MINGW)
    target_link_options(packet_dpi_core PUBLIC -static-libgcc -static-libstdc++)
endif()

# Main Executable Target
add_executable(dpi_engine
    src/main.cpp
)

target_link_libraries(dpi_engine PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(dpi_engine)

# Tests Subdirectory
if(PACKET_DPI_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Benchmarks Subdirectory
if(PACKET_DPI_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()

# Minimal test runner target
add_executable(unit_tests
    main_test.cpp
)

target_link_libraries(unit_tests PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(unit_tests)

add_test(NAME CoreVersionTest COMMAND unit_tests)
if(WIN32)
    set_tests_properties(CoreVersionTest PROPERTIES
        ENVIRONMENT "PATH=C:/MSYS2/ucrt64/bin;$ENV{PATH}"
    )
endif()


# Minimal test runner target
add_executable(unit_tests
    main_test.cpp
)

target_link_libraries(unit_tests PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(unit_tests)

add_test(NAME CoreVersionTest COMMAND unit_tests)

# PCAP Reader Unit Test Target
add_executable(pcap_reader_test
    pcap_reader_test.cpp
)

target_link_libraries(pcap_reader_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(pcap_reader_test)

add_test(NAME PcapReaderTest COMMAND pcap_reader_test)

# Protocol Parser Unit Test Target
add_executable(protocol_parser_test
    protocol_parser_test.cpp
)

target_link_libraries(protocol_parser_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(protocol_parser_test)

add_test(NAME ProtocolParserTest COMMAND protocol_parser_test)

if(WIN32)
    set_tests_properties(CoreVersionTest PcapReaderTest ProtocolParserTest
        PROPERTIES ENVIRONMENT "PATH=C:/MSYS2/ucrt64/bin;$ENV{PATH}"
    )
endif()



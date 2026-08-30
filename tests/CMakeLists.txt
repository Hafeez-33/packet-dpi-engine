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



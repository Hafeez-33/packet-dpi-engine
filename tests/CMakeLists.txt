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

# Flow Tracking Unit Test Target
add_executable(flow_tracking_test
    flow_tracking_test.cpp
)

target_link_libraries(flow_tracking_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(flow_tracking_test)

add_test(NAME FlowTrackingTest COMMAND flow_tracking_test)

# Layer-7 DPI Unit Test Target
add_executable(dpi_test
    dpi_test.cpp
)

target_link_libraries(dpi_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(dpi_test)

add_test(NAME DpiTest COMMAND dpi_test)

# Rule & Policy Engine Unit Test Target
add_executable(rule_engine_test
    rule_engine_test.cpp
)

target_link_libraries(rule_engine_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(rule_engine_test)

add_test(NAME RuleEngineTest COMMAND rule_engine_test)

# Multi-Threaded Worker Pipeline Unit Test Target
add_executable(worker_pipeline_test
    worker_pipeline_test.cpp
)

target_link_libraries(worker_pipeline_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(worker_pipeline_test)

add_test(NAME WorkerPipelineTest COMMAND worker_pipeline_test)

if(WIN32)
    set_tests_properties(CoreVersionTest PcapReaderTest ProtocolParserTest FlowTrackingTest DpiTest RuleEngineTest WorkerPipelineTest
        PROPERTIES ENVIRONMENT "PATH=C:/MSYS2/ucrt64/bin;$ENV{PATH}"
    )
endif()





# Ensure assert() statements in test targets are always active in all build configurations (including Release)
if(MSVC)
    add_compile_options(/UNDEBUG)
else()
    add_compile_options(-UNDEBUG)
endif()

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

# Telemetry & Dashboard Unit Test Target
add_executable(telemetry_test
    telemetry_test.cpp
)

target_link_libraries(telemetry_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(telemetry_test)

add_test(NAME TelemetryTest COMMAND telemetry_test)

# Threat Detection & Anomaly Unit Test Target
add_executable(threat_test
    threat_test.cpp
)

target_link_libraries(threat_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(threat_test)

add_test(NAME ThreatTest COMMAND threat_test)

# Stage 9: Risk & Behavioral Profiling Unit Test Target
add_executable(risk_test
    risk_test.cpp
)

target_link_libraries(risk_test PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(risk_test)

add_test(NAME RiskTest COMMAND risk_test)





add_executable(pipeline_benchmark
    pipeline_benchmark.cpp
)
target_link_libraries(pipeline_benchmark PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(pipeline_benchmark)

add_executable(telemetry_benchmark
    telemetry_benchmark.cpp
)
target_link_libraries(telemetry_benchmark PRIVATE packet_dpi_core)
packet_dpi_enable_warnings(telemetry_benchmark)

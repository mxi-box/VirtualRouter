cmake_minimum_required(VERSION 3.10)

project(VirtualRouter VERSION 1.0)

aux_source_directory(. CPP_SOURCE)

add_executable(VirtualRouter ${CPP_SOURCE})

target_link_libraries(VirtualRouter iphlpapi.lib ws2_32.lib)
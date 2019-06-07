cmake_minimum_required(VERSION 3.6)
project(boxy_libvmi_extension C CXX)

init_project(boxy_libvmi_extension BINARY)

target_sources(boxy_libvmi_extension PRIVATE exit_handler.cpp)
target_link_libraries(boxy_libvmi_extension PRIVATE vmm::boxy_bfvmm)

fini_project()

cmake_minimum_required(VERSION 3.6)

if(ENABLE_BUILD_VMM)
    add_subproject(boxy_libvmi_extension vmm
        DEPENDS boxy_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/extension
    )
endif()

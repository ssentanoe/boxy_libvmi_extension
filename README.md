boxy/bfvmm/CMakeLists.txt add
```
install(DIRECTORY ../bfsdk/include/ DESTINATION include/)
```


config.cmake
```
set(ENABLE_BOXY ON)

...

if(ENABLE_BOXY)
    set_bfm_vmm(boxy_vmm TARGET bfvmm)
    list(APPEND EXTENSION
        ${CMAKE_CURRENT_LIST_DIR}/
    )
    list(APPEND EXTENSION
	   /root/boxy_libvmi_extension/libvmi_extension/
    )
endif()
```

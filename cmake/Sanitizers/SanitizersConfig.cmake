set(Sanitizers_VERSION "0.2")
macro(add_to_compile_and_link_flags target name)
    target_compile_options(${target} INTERFACE ${name})
    target_link_options(${target} INTERFACE  ${name})
endmacro()
macro(add_sanitizers_to_compile_and_link_flags target name)
    add_to_compile_and_link_flags(Sanitizers_${target}  ${name})

endmacro()
macro(reg_sanitize name)
    add_library(Sanitizers_${name} INTERFACE)
    add_sanitizers_to_compile_and_link_flags(${name} "-fsanitize=${name}")
    add_library(Sanitizers::${name} ALIAS Sanitizers_${name})
endmacro()





# CLang It is not possible to combine more than one of the -fsanitize=address, -fsanitize=thread, and -fsanitize=memory checkers in the same program.
# AddressSanitizer, a memory error detector.
if (CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        reg_sanitize(leak) #gcc,clang
        #MemorySanitizer, a detector of uninitialized reads. Requires instrumentation of all program code.
        reg_sanitize(address) #gcc,clang
        # ThreadSanitizer, a data race detector.
        reg_sanitize(thread) #gcc,clang
        # UndefinedBehaviorSanitizer, a fast and compatible undefined behavior checker.
        reg_sanitize(undefined) #gcc,clang
    endif()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        reg_sanitize(memory) #-gcc,clang
        reg_sanitize(cfi) #clang -gcc
        add_sanitizers_to_compile_and_link_flags(cfi "-flto")
        add_sanitizers_to_compile_and_link_flags(cfi "-fvisibility=hidden")

        # safe stack protection against stack-based memory corruption errors.
        reg_sanitize(safe-stack) #clang
        #DataFlowSanitizer, a general data flow analysis.
        reg_sanitize(dataflow) #clang
     endif()

    if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        reg_sanitize(kernel-address) #gcc
        reg_sanitize(pointer-compare) #gcc
        reg_sanitize(pointer-subtract) #gcc
    endif()
else()
    message(WARNING " =(((")
endif()


# target_cxx_sanitizers(${PROJECT_NAME} address)
# target_cxx_sanitizers(${PROJECT_NAME} undefined)
# target_cxx_sanitizers(${PROJECT_NAME} memory)
# target_cxx_sanitizers(${PROJECT_NAME} thread)
# target_cxx_sanitizers(${PROJECT_NAME} leak)


#set(BUILD_ENABLE_SANITIZERS OFF CACHE BOOL BUILD_ENABLE_SANITIZERS)
#set(BUILD_ENABLE_SANITIZERS_RECOVER OFF CACHE BOOL BUILD_ENABLE_SANITIZERS_RECOVER)
#if(BUILD_ENABLE_SANITIZERS_UNDEFINED)
#    target_compile_options(${PROJECT_NAME} PRIVATE  -fsanitize-recover=all)
#endif()
set(Clang_address ON)
set(GNU_address ON)

set(Clang_leak ON)
set(GNU_leak ON)

set(Clang_thread ON)
set(GNU_thread ON)

set(Clang_undefined ON)
set(GNU_undefined ON)

set(Clang_memory ON)

set(Clang_cfi ON)

set(Clang_safe-stack ON)

set(Clang_dataflow ON)

set(GNU_kernel-address ON)

set(GNU_pointer-compare ON)

set(GNU_pointer-subtract ON)

macro(target_cxx_sanitizers target name)
    if(${CMAKE_CXX_COMPILER_ID}_${name})
        set(${target}_BUILD_ENABLE_SANITIZERS OFF CACHE BOOL BUILD_ENABLE_SANITIZERS)
        set(${target}_BUILD_ENABLE_SANITIZERS_${name} OFF CACHE BOOL BUILD_ENABLE_SANITIZERS)
        if(${target}_BUILD_ENABLE_SANITIZERS_${name} AND ${target}_BUILD_ENABLE_SANITIZERS)
            target_link_libraries(${target} Sanitizers::${name})
        endif()
        set(${target}_BUILD_ENABLE_SANITIZERS_${name}_RECOVER OFF CACHE BOOL BUILD_ENABLE_SANITIZERS_RECOVER)
        if(${target}_BUILD_ENABLE_SANITIZERS_${name}_RECOVER)
            target_compile_options(${target} PRIVATE  -fsanitize-recover=${name})
        endif()
     else()
         message(Error: ${CMAKE_CXX_COMPILER_ID} compiler does not support Sanitizer_${name} )
     endif()
endmacro()
#-fsanitize-recover=all
#export UBSAN_OPTIONS="log_path=UBSAN"
#export ASAN_OPTIONS="log_path=ASAN"
#export  CFLAGS="-fsanitize=address -fsanitize=undefined -fsanitize-recover=all"

set(Sanitizers_VERSION "0.1")
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
#-fsanitize-recover=all
#export UBSAN_OPTIONS="log_path=UBSAN"
#export ASAN_OPTIONS="log_path=ASAN"
#export  CFLAGS="-fsanitize=address -fsanitize=undefined -fsanitize-recover=all"

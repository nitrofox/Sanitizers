set(Sanitizers_VERSION "0.1")

macro(reg_sanitize name)
    add_library(Sanitizers_${name} INTERFACE)
    target_compile_options(Sanitizers_${name} INTERFACE "-fsanitize=${name}")
    target_link_options(Sanitizers_${name} INTERFACE "-fsanitize=${name}")
    add_library(Sanitizers::${name} ALIAS Sanitizers_${name})
endmacro()

macro(reg_sanitize_costum name com)
    add_library(Sanitizers_${name} INTERFACE)
    target_compile_options(Sanitizers_${name} INTERFACE ${com}")
    target_link_options(Sanitizers_${name} INTERFACE ${com}")
    add_library(Sanitizers::${name} ALIAS Sanitizers_${name})
endmacro()
# CLang It is not possible to combine more than one of the -fsanitize=address, -fsanitize=thread, and -fsanitize=memory checkers in the same program.
# AddressSanitizer, a memory error detector.
if (UNIX)
reg_sanitize(address) #gcc,clang

reg_sanitize(kernel-address) #gcc
reg_sanitize(pointer-compare) #gcc
reg_sanitize(pointer-subtract) #gcc

#MemorySanitizer, a detector of uninitialized reads. Requires instrumentation of all program code.
reg_sanitize(memory) #gcc,clang

# ThreadSanitizer, a data race detector.
reg_sanitize(thread) #gcc,clang
reg_sanitize(leak) #gcc

# UndefinedBehaviorSanitizer, a fast and compatible undefined behavior checker.
reg_sanitize(undefined) #gcc,clang

# control flow integrity checks. Requires -flto.
reg_sanitize(cfi) #clang
target_compile_options(Sanitizers_cfi INTERFACE "-flto")
target_link_options(Sanitizers_cfi INTERFACE "-flto")
target_compile_options(Sanitizers_cfi INTERFACE "-fvisibility=hidden")
target_link_options(Sanitizers_cfi INTERFACE "-fvisibility=hidden")
# safe stack protection against stack-based memory corruption errors.
reg_sanitize(safe-stack) #clang

#DataFlowSanitizer, a general data flow analysis.
reg_sanitize(dataflow) #clang
elseif(MSVC)
    message(WARNING " =(((")
else()
    message(WARNING " =(((")
endif()

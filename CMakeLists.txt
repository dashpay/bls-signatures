CMAKE_MINIMUM_REQUIRED(VERSION 3.18.0 FATAL_ERROR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release"
    CACHE STRING "Possible values are empty, Debug, Release, RelWithDebInfo, MinSizeRel, ..."
    FORCE
  )
endif()

project(BLS)

set(BUILD_BLS_JS_BINDINGS "1" CACHE STRING "")
set(BUILD_BLS_PYTHON_BINDINGS "1" CACHE STRING "")
set(BUILD_BLS_TESTS "1" CACHE STRING "")
set(BUILD_BLS_BENCHMARKS "1" CACHE STRING "")

message(STATUS "Build python bindings: ${BUILD_BLS_PYTHON_BINDINGS}")
message(STATUS "Build tests: ${BUILD_BLS_TESTS}")
message(STATUS "Build benchmarks: ${BUILD_BLS_BENCHMARKS}")

# Add path for custom modules
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake_modules
)

# Relic related options

set(STBIN "off" CACHE STRING "Relic - Build static binaries")

find_package(gmp)
if (GMP_FOUND)
  message(STATUS "Found libgmp")
  set(ARITH "gmp" CACHE STRING "")
else()
  set(ARITH "easy" CACHE STRING "")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(WSIZE "32" CACHE STRING "Relic - Processor word size")
else()
  set(WSIZE "64" CACHE STRING "Relic - Processor word size")
endif()

if(EMSCRIPTEN)
  # emscripten needs arch set to be none since it can't compile assembly
  set(ARCH "" CACHE STRING "")
  # emscripten is a 32 bit compiler
  set(WSIZE "32" CACHE STRING "Relic - Processor word size")
endif()

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(TIMER "ANSI" CACHE STRING "")
  set(MULTI "OPENMP" CACHE STRING "")
else()
  set(TIMER "CYCLE" CACHE STRING "")
  set(MULTI "PTHREAD" CACHE STRING "")
endif()

set(CHECK "off" CACHE STRING "")
set(VERBS "off" CACHE STRING "")
set(ALLOC "AUTO" CACHE STRING "")
set(SHLIB "off" CACHE STRING "")
set(DOCUM "off" CACHE STRING "")
set(FP_PRIME "381" CACHE STRING "Relic - Prime modulus size")

if(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  set(SEED "UDEV" CACHE STRING "")
  set(FP_QNRES "off" CACHE STRING "")
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(SEED "WCGR" CACHE STRING "")
  set(FP_QNRES "on" CACHE STRING "")
else()
  set(SEED "UDEV" CACHE STRING "")
  set(FP_QNRES "on" CACHE STRING "")
endif()

set(FP_METHD "INTEG;INTEG;INTEG;MONTY;LOWER;SLIDE" CACHE STRING "")

if(MSVC)
  set(COMP_FLAGS "" CACHE STRING "")
else()
  set(COMP_FLAGS "-O3 -funroll-loops -fomit-frame-pointer" CACHE STRING "")
endif()

set(FP_PMERS "off" CACHE STRING "")
set(FPX_METHD "INTEG;INTEG;LAZYR" CACHE STRING "")
set(EP_PLAIN "off" CACHE STRING "")
set(EP_SUPER "off" CACHE STRING "")
# Disable relic tests and benchmarks
set(TESTS "0" CACHE STRING "Relic - Number of times each test is ran")
set(BENCH "0" CACHE STRING "Relic - Number of times each benchmark is ran")

set(QUIET "on" CACHE STRING "Relic - Build with printing disabled")

set(PP_EXT "LAZYR" CACHE STRING "")
set(PP_METHD "LAZYR;OATEP" CACHE STRING "")

# Disable mimalloc shared libraries and tests, enable secure mode
set(MI_SECURE       "on" CACHE STRING "")

set(MI_BUILD_SHARED "off" CACHE STRING "")
set(MI_BUILD_TESTS  "off" CACHE STRING "")
set(MI_OVERRIDE     "off" CACHE STRING "")

add_subdirectory(depends/relic)
add_subdirectory(depends/mimalloc)

# blst (depends/blst) provides an accelerated deserialization path for
# BLS12-381 points. It is only usable on 64-bit little-endian x86_64/aarch64
# hosts, where the bundled assembly is supported and relic's internal
# field-element layout (6x64-bit little-endian limbs, Montgomery form with
# R = 2^384) matches blst's exactly.
if(EMSCRIPTEN)
  set(BLST_SUPPORTED OFF)
else()
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" BLST_HOST_PROCESSOR)
  if(BLST_HOST_PROCESSOR MATCHES "^(x86_64|amd64|aarch64|arm64)$" AND CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BLST_SUPPORTED ON)
  else()
    set(BLST_SUPPORTED OFF)
  endif()
endif()
option(USE_BLST "Use the bundled blst library to accelerate BLS12-381 deserialization" ${BLST_SUPPORTED})
if(USE_BLST AND NOT BLST_SUPPORTED)
  message(FATAL_ERROR "blst is not supported on this host (requires little-endian x86_64 or aarch64)")
endif()
message(STATUS "Use blst: ${USE_BLST}")
if(USE_BLST)
  add_subdirectory(depends/blst)
endif()

#message(STATUS "Patching Relic to make setjmp.h inclusion conditional")
#
#execute_process(
#  COMMAND bash -c "git apply ${CMAKE_SOURCE_DIR}/setjmp_patch.diff"
#  WORKING_DIRECTORY ${RELIC_SRC}
#)

add_subdirectory(src)


# Write include paths for rust binding
if(EMSCRIPTEN)
  file(APPEND "${CMAKE_CURRENT_LIST_DIR}/build/include_paths.txt" "${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES}/c++/v1/;")
endif()

file(APPEND "${CMAKE_CURRENT_LIST_DIR}/build/include_paths.txt" "${CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES};")

if(GMP_INCLUDES)
  file(APPEND "${CMAKE_CURRENT_LIST_DIR}/build/include_paths.txt" "${GMP_INCLUDES};")
endif()

# Write gmp library path for rust binding
if(GMP_LIBRARIES)
  file(APPEND "${CMAKE_CURRENT_LIST_DIR}/build/gmp_libraries.txt" "${GMP_LIBRARIES}")
endif()

if(EMSCRIPTEN)
  if(BUILD_BLS_JS_BINDINGS)
    add_subdirectory(js-bindings)
  endif()
else()
  # emscripten can't build python bindings, it produces only javascript
  # add_subdirectory(contrib/pybind11)
  if(BUILD_BLS_PYTHON_BINDINGS)
    add_subdirectory(binds/python)
  endif()
endif()

# Minimal CMake build for the vendored blst library (v0.3.16). blst ships its
# own build.sh/build.bat, but the sources compile directly as a small static
# library: one C translation unit (src/server.c, which #includes every other
# .c file) plus the pre-generated per-platform assembly (build/assembly.S,
# which #includes the correct flavour for the target OS/ABI).

enable_language(ASM)

add_library(blst STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src/server.c
  ${CMAKE_CURRENT_SOURCE_DIR}/build/assembly.S
)

set_target_properties(blst PROPERTIES
  C_STANDARD 99
  POSITION_INDEPENDENT_CODE ON
)

# __BLST_PORTABLE__ compiles both the ADX and the generic x86_64 code paths
# and selects between them at run time; it has no effect on aarch64. It must
# be visible to both the C and the assembly translation unit.
target_compile_definitions(blst PRIVATE __BLST_PORTABLE__)
target_compile_options(blst PRIVATE
  $<$<COMPILE_LANGUAGE:C>:-fno-builtin>
)

target_include_directories(blst
  PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/bindings
)

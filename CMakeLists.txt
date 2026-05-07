cmake_minimum_required(VERSION 4.0)

set(CMAKE_POLICY_DEFAULT_CMP0169 OLD)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)
find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)

project(bare_wasm3 C)

bare_target(target)

# Fetch wasm3 — a minimal, embeddable WASM interpreter in C
fetch_package("github:wasm3/wasm3#79d412ea5fcf92f0efe658d52827a0e0a96ff442")

add_bare_module(bare_wasm3)

target_sources(
  ${bare_wasm3}
  PRIVATE
    src/binding.c
)

target_link_libraries(
  ${bare_wasm3}
  PUBLIC
    m3
)

# wasm3 may need math on some platforms
if(UNIX)
  target_link_libraries(${bare_wasm3} PUBLIC m)
endif()

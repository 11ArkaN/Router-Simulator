cmake_minimum_required(VERSION 3.22)
project(router_simulator_core LANGUAGES CXX)

# The active profile owns the fixed Wasm memory budget. Keeping the generated
# value in CMake prevents the linker and runtime model from drifting apart.
include(${CMAKE_CURRENT_SOURCE_DIR}/generated-profile.cmake)

option(ROUTER_BUILD_TESTS "Build core conformance tests" ON)
option(ROUTER_BUILD_MANUAL "Build the manual runtime session" ON)
option(ROUTER_BUILD_BENCHMARKS "Build packet-path benchmarks" ON)
set(ROUTER_SANITIZERS "" CACHE STRING "Native sanitizer set: address,undefined or thread")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Warnings are part of every executable contract, not only router_core. Test,
# benchmark and C ABI code can otherwise hide a narrowing conversion or unused
# result even though CI reports the library itself as warning-free.
if(MSVC)
  # C4324 reports that alignas(64) inserted padding. The padding is the stated
  # cache-isolation contract of SpscRing and TelemetryPageV1, not an accidental
  # layout loss. Keep every other level-four warning fatal and silence only this
  # MSVC diagnostic so Windows validates the same intentional layout as Clang.
  # /EHsc is required because public boundaries report allocation and test
  # failures through standard C++ exceptions. Without it MSVC warns inside the
  # standard library itself and would not unwind automatic owners correctly.
  add_compile_options(/W4 /WX /wd4324 /EHsc)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(router_build_options INTERFACE)
target_include_directories(router_build_options INTERFACE include)

# Targets encode the permitted dependency direction. Splitting translation
# units alone is insufficient because a lower layer could otherwise include a
# management header and keep compiling inside one archive.
add_library(router_primitives STATIC src/packet.cpp)
target_link_libraries(router_primitives PUBLIC router_build_options)

add_library(router_device STATIC
  src/device_routing.cpp
  src/hardware.cpp
  src/routing.cpp
)
target_link_libraries(router_device PUBLIC router_primitives router_build_options)

add_library(router_network STATIC
  src/network.cpp
  src/network_adjacency.cpp
  src/network_endpoint.cpp
  src/network_link_fabric.cpp
)
target_link_libraries(router_network PUBLIC router_device router_primitives router_build_options)

add_library(router_management STATIC
  src/capture_store.cpp
  src/checkpoint.cpp
  src/cli.cpp
  src/cli_classic.cpp
  src/cli_md.cpp
  src/cli_parser.cpp
  src/project_configuration.cpp
)
target_link_libraries(router_management PUBLIC
  router_network router_device router_primitives router_build_options)

add_library(router_runtime STATIC
  src/runtime.cpp
  src/runtime_checkpoint.cpp
  src/runtime_project.cpp
  src/runtime_projection.cpp
)
target_link_libraries(router_runtime PUBLIC
  router_management router_network router_device router_primitives router_build_options)

# Existing tools and the stable Wasm ABI consume one facade target. INTERFACE
# adds no archive or runtime dispatch and preserves the explicit layers above.
add_library(router_core INTERFACE)
target_link_libraries(router_core INTERFACE router_runtime)

if(NOT EMSCRIPTEN AND ROUTER_SANITIZERS)
  # Sanitizers are native-only because Wasm pthread execution is validated in
  # the browser build. Applying the flags transitively ensures test executables
  # and every layer use the same instrumented allocation runtime.
  if(MSVC)
    if(NOT ROUTER_SANITIZERS STREQUAL "address")
      message(FATAL_ERROR "MSVC supports ROUTER_SANITIZERS=address only")
    endif()
    # Address instrumentation is applied to every layer and test executable.
    # Incremental linking is disabled because the sanitizer linker requires it.
    target_compile_options(router_build_options INTERFACE /fsanitize=address)
    target_link_options(router_build_options INTERFACE /INCREMENTAL:NO)
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(router_build_options INTERFACE
      "-fsanitize=${ROUTER_SANITIZERS}" -fno-omit-frame-pointer)
    target_link_options(router_build_options INTERFACE "-fsanitize=${ROUTER_SANITIZERS}")
  else()
    message(FATAL_ERROR "ROUTER_SANITIZERS is unsupported by this compiler")
  endif()
endif()

if(EMSCRIPTEN)
  # Every object that can reach atomics or std::thread must be compiled with
  # pthread features. Applying this to the core prevents mixed archives that
  # link successfully in native builds but are invalid shared-memory Wasm.
  # The hot packet path lives in this archive, so optimizing only the final
  # executable leaves parsers, checksums and forwarding at Clang's -O0 default.
  # Keep the optimization contract on the archive itself to make every Wasm
  # consumer, including the browser runtime, use the same production code.
  target_compile_options(router_build_options INTERFACE -pthread -O3)
  # Source: Emscripten pthreads documentation. The JavaScript expression is
  # evaluated during module startup and pre-creates clamp(hardwareConcurrency
  # minus one, 2, 4) workers. Two become control and forwarding owners; spare
  # workers remain available for later profile shards without blocking spawn.
  set(ROUTER_PTHREAD_POOL_OPTION
      "-sPTHREAD_POOL_SIZE=Math.min(${ROUTER_PTHREAD_POOL_MAX},Math.max(${ROUTER_PTHREAD_POOL_MIN},navigator.hardwareConcurrency-1))")
  set(ROUTER_MEMORY_OPTION "-sINITIAL_MEMORY=${ROUTER_WASM_INITIAL_MEMORY}")
endif()

if(ROUTER_BUILD_BENCHMARKS)
  add_executable(packet_benchmark tools/packet_benchmark.cpp)
  target_link_libraries(packet_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(packet_benchmark PRIVATE -O3 -pthread)
    target_link_options(packet_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}")
    set_target_properties(packet_benchmark PROPERTIES SUFFIX ".js")
  endif()
  add_executable(structure_benchmark tools/structure_benchmark.cpp)
  target_link_libraries(structure_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(structure_benchmark PRIVATE -O3 -pthread)
    target_link_options(structure_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}"
      "-sALLOW_MEMORY_GROWTH=0")
    set_target_properties(structure_benchmark PROPERTIES SUFFIX ".js")
  endif()
  add_executable(runtime_benchmark tools/runtime_benchmark.cpp)
  target_link_libraries(runtime_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(runtime_benchmark PRIVATE -O3 -pthread)
    target_link_options(runtime_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}"
      "-sALLOW_MEMORY_GROWTH=0")
    set_target_properties(runtime_benchmark PROPERTIES SUFFIX ".js")
  endif()
endif()

if(ROUTER_BUILD_MANUAL)
  add_executable(manual_session tools/manual_session.cpp)
  target_link_libraries(manual_session PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(manual_session PRIVATE -pthread)
    target_link_options(manual_session PRIVATE -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}")
    set_target_properties(manual_session PROPERTIES SUFFIX ".js")
  endif()
endif()

if(EMSCRIPTEN)
  add_executable(simulator src/wasm_api.cpp)
  target_link_libraries(simulator PRIVATE router_core)
  target_compile_options(simulator PRIVATE -pthread -O3)
  target_link_options(simulator PRIVATE
    -pthread
    -O3
    "${ROUTER_PTHREAD_POOL_OPTION}"
    "${ROUTER_MEMORY_OPTION}"
    "-sALLOW_MEMORY_GROWTH=0"
    "-sMODULARIZE=1"
    "-sEXPORT_ES6=1"
    "-sEXPORT_NAME=createRouterRuntime"
    "-sENVIRONMENT=worker"
    "-sEXPORTED_FUNCTIONS=['_malloc','_free','_rs_create','_rs_command','_rs_capture_prepare','_rs_capture_data','_rs_capture_size','_rs_shutdown','_runtime_initialize','_runtime_capabilities','_lab_open','_lab_close','_lab_submit_command','_cli_open_session','_cli_push_input','_cli_read_output','_telemetry_get_page','_telemetry_get_page_size','_telemetry_get_layout','_capture_start','_capture_stop','_capture_export_pcapng','_checkpoint_export','_checkpoint_export_size','_checkpoint_import','_project_import']"
    # HEAPU8 is an explicit Emscripten module API dependency. Newer optimized
    # builds keep the internal view lexical unless it is exported, so relying
    # on an accidental Module property makes browser startup version-sensitive.
    "-sEXPORTED_RUNTIME_METHODS=['ccall','HEAPU8']"
  )
  set_target_properties(simulator PROPERTIES SUFFIX ".js")
endif()

if(ROUTER_BUILD_TESTS)
  enable_testing()
  add_executable(core_tests
    src/wasm_api.cpp
    tests/cli_test.cpp
    tests/packet_test.cpp
    tests/routing_test.cpp
    tests/runtime_test.cpp
  )
  target_link_libraries(core_tests PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(core_tests PRIVATE -pthread)
    target_link_options(core_tests PRIVATE -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}"
      "-sNO_DISABLE_EXCEPTION_CATCHING")
    set_target_properties(core_tests PROPERTIES SUFFIX ".js")
  endif()
  add_test(NAME core_tests COMMAND core_tests)

  # These tests link below Runtime and the Wasm ABI. A module that accidentally
  # grows an orchestration dependency fails here even if the integration target
  # would otherwise provide the missing symbol transitively.
  add_executable(module_tests
    tests/checkpoint_test.cpp
    tests/hardware_test.cpp
    tests/module_test_main.cpp
    tests/network_test.cpp
    tests/project_configuration_test.cpp
  )
  target_link_libraries(module_tests PRIVATE router_management)
  if(EMSCRIPTEN)
    target_compile_options(module_tests PRIVATE -pthread)
    target_link_options(module_tests PRIVATE -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}"
      # Module suites deliberately throw on a failed invariant so the runner
      # can print the violated contract. Without Wasm exception catching the
      # first failure becomes an opaque __cxa_throw assertion instead.
      "-sNO_DISABLE_EXCEPTION_CATCHING")
    set_target_properties(module_tests PROPERTIES SUFFIX ".js")
  endif()
  add_test(NAME module_tests COMMAND module_tests)
  if(NOT EMSCRIPTEN)
    add_executable(capture_fixture tools/capture_fixture.cpp)
    target_link_libraries(capture_fixture PRIVATE router_core)
    set(CAPTURE_FIXTURE "${CMAKE_CURRENT_BINARY_DIR}/conformance.pcapng")
    add_test(NAME capture_fixture COMMAND capture_fixture "${CAPTURE_FIXTURE}")
    # Wireshark's Windows installer does not add its directory to PATH by
    # default. The explicit official installation locations keep conformance
    # enabled on native Windows without introducing WSL or a shell wrapper.
    find_program(TSHARK_EXECUTABLE tshark HINTS
      "$ENV{ProgramFiles}/Wireshark")
    if(TSHARK_EXECUTABLE)
      add_test(NAME tshark_pcapng
        COMMAND "${TSHARK_EXECUTABLE}" -n -r "${CAPTURE_FIXTURE}" -c 1)
      set_tests_properties(tshark_pcapng PROPERTIES DEPENDS capture_fixture)
    endif()
  endif()
endif()

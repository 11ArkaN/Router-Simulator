cmake_minimum_required(VERSION 3.22)
project(router_simulator_core LANGUAGES CXX)

# The active profile owns the fixed Wasm memory budget. Keeping the generated
# value in CMake prevents the linker and runtime model from drifting apart.
include(${CMAKE_CURRENT_SOURCE_DIR}/generated-profile.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/generated-device-catalog.cmake)

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
  src/lab_registry.cpp
  src/multi_device_routing.cpp
  src/routing.cpp
  src/router_hardware_inventory.cpp
)
target_link_libraries(router_device PUBLIC router_primitives router_build_options)

add_library(router_network STATIC
  src/capture_store.cpp
  src/multi_device_fabric.cpp
  src/network_plane.cpp
  src/network_endpoint.cpp
  src/router_forwarder.cpp
)
target_link_libraries(router_network PUBLIC router_device router_primitives router_build_options)

add_library(router_management STATIC
  src/cli.cpp
  src/cli_classic.cpp
  src/cli_md.cpp
  src/cli_parser.cpp
  src/session_workflows.cpp
)
target_link_libraries(router_management PUBLIC
  router_network router_device router_primitives router_build_options)

add_library(router_runtime STATIC
  src/control_projection_worker.cpp
  src/lab_runtime.cpp
  src/lab_checkpoint.cpp
  src/network_plane_worker.cpp
  src/runtime_memory_budget.cpp
  src/runtime_supervisor.cpp
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
  # evaluated before C++ startup and reserves exactly the pthread count needed
  # by the generated host-CPU shard policy. The browser Worker itself owns the
  # primary control shard and is therefore not part of this pool.
  set(ROUTER_PTHREAD_POOL_OPTION
      "-sPTHREAD_POOL_SIZE=(navigator.hardwareConcurrency<=${ROUTER_LOGICAL_CPU_LOW_MAX}?${ROUTER_PTHREAD_POOL_LOW}:(navigator.hardwareConcurrency<=${ROUTER_LOGICAL_CPU_MEDIUM_MAX}?${ROUTER_PTHREAD_POOL_MEDIUM}:${ROUTER_PTHREAD_POOL_HIGH}))")
  set(ROUTER_MEMORY_OPTION "-sINITIAL_MEMORY=${ROUTER_WASM_INITIAL_MEMORY}")
  set(ROUTER_STACK_OPTION "-sSTACK_SIZE=${ROUTER_WASM_STACK_BYTES}")
endif()

if(ROUTER_BUILD_BENCHMARKS)
  add_executable(packet_benchmark tools/packet_benchmark.cpp)
  target_link_libraries(packet_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(packet_benchmark PRIVATE -O3 -pthread)
    target_link_options(packet_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      "-sEXIT_RUNTIME=1")
    set_target_properties(packet_benchmark PROPERTIES SUFFIX ".js")
  endif()
  add_executable(structure_benchmark tools/structure_benchmark.cpp)
  target_link_libraries(structure_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(structure_benchmark PRIVATE -O3 -pthread)
    target_link_options(structure_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      "-sALLOW_MEMORY_GROWTH=0" "-sEXIT_RUNTIME=1")
    set_target_properties(structure_benchmark PROPERTIES SUFFIX ".js")
  endif()
  add_executable(runtime_benchmark tools/runtime_benchmark.cpp)
  target_link_libraries(runtime_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(runtime_benchmark PRIVATE -O3 -pthread)
    target_link_options(runtime_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      "-sALLOW_MEMORY_GROWTH=0" "-sNO_DISABLE_EXCEPTION_CATCHING"
      "-sEXIT_RUNTIME=1")
    set_target_properties(runtime_benchmark PROPERTIES SUFFIX ".js")
  endif()
endif()

if(ROUTER_BUILD_MANUAL)
  add_executable(manual_session tools/manual_session.cpp)
  target_link_libraries(manual_session PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(manual_session PRIVATE -pthread)
    target_link_options(manual_session PRIVATE -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      "-sEXIT_RUNTIME=1")
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
    "${ROUTER_STACK_OPTION}"
    "-sALLOW_MEMORY_GROWTH=0"
    "-sMODULARIZE=1"
    "-sEXPORT_ES6=1"
    "-sEXPORT_NAME=createRouterRuntime"
    "-sENVIRONMENT=worker"
    "-sEXPORTED_FUNCTIONS=['_malloc','_free','_runtime_initialize','_runtime_capabilities','_lab_close','_lab_submit_command','_telemetry_get_page','_telemetry_get_page_size','_telemetry_publish','_telemetry_get_layout','_capture_export_pcapng','_capture_export_size','_checkpoint_export','_checkpoint_export_size','_checkpoint_import']"
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
    tests/core_test_main.cpp
    tests/cli_test.cpp
    tests/control_projection_worker_test.cpp
    tests/lab_runtime_test.cpp
    tests/packet_test.cpp
    tests/runtime_supervisor_test.cpp
    tests/network_plane_worker_test.cpp
  )
  target_link_libraries(core_tests PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(core_tests PRIVATE -pthread)
    # Checkpoint integration deliberately keeps the source and restored
    # LabRuntime alive together inside one Node Wasm instance. Production swaps
    # two browser Workers, each with its own 256 MiB memory, so the test target
    # needs two production budgets without changing the simulator contract.
    set(ROUTER_TEST_MEMORY_OPTION "-sINITIAL_MEMORY=536870912")
    # The checkpoint replacement test intentionally overlaps two complete
    # high-CPU runtimes. Each runtime owns five pthreads in addition to its
    # calling Worker, so the test pool must contain ten actual workers. Using
    # the production expression here makes Emscripten recycle a terminated
    # owner and print late-command diagnostics after otherwise passing tests.
    set(ROUTER_TEST_PTHREAD_POOL_OPTION "-sPTHREAD_POOL_SIZE=10")
    target_link_options(core_tests PRIVATE -pthread
      "${ROUTER_TEST_PTHREAD_POOL_OPTION}" "${ROUTER_TEST_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      "-sNO_DISABLE_EXCEPTION_CATCHING"
      # Test executables are short-lived Node programs. Explicit runtime exit
      # joins the pre-created pthread pool after main returns; without it Node
      # keeps idle Worker objects alive and a passing suite appears to hang.
      "-sEXIT_RUNTIME=1")
    set_target_properties(core_tests PROPERTIES SUFFIX ".js")
  endif()
  add_test(NAME core_tests COMMAND core_tests)

  # These tests link below Runtime and the Wasm ABI. A module that accidentally
  # grows an orchestration dependency fails here even if the integration target
  # would otherwise provide the missing symbol transitively.
  add_executable(module_tests
    tests/capture_store_test.cpp
    tests/hardware_test.cpp
    tests/lab_registry_test.cpp
    tests/multi_device_fabric_test.cpp
    tests/multi_device_routing_test.cpp
    tests/module_test_main.cpp
    tests/network_plane_test.cpp
    tests/routing_test.cpp
    tests/router_hardware_inventory_test.cpp
    tests/shard_policy_test.cpp
    tests/router_forwarder_test.cpp
    tests/session_workflows_test.cpp
  )
  target_link_libraries(module_tests PRIVATE router_management)
  if(EMSCRIPTEN)
    target_compile_options(module_tests PRIVATE -pthread)
    target_link_options(module_tests PRIVATE -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      # Module suites deliberately throw on a failed invariant so the runner
      # can print the violated contract. Without Wasm exception catching the
      # first failure becomes an opaque __cxa_throw assertion instead.
      "-sNO_DISABLE_EXCEPTION_CATCHING"
      "-sEXIT_RUNTIME=1")
    set_target_properties(module_tests PROPERTIES SUFFIX ".js")
  endif()
  add_test(NAME module_tests COMMAND module_tests)
  add_executable(capture_fixture tools/capture_fixture.cpp)
  target_link_libraries(capture_fixture PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(capture_fixture PRIVATE -pthread)
    target_link_options(capture_fixture PRIVATE -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      # NODERAWFS maps the process working directory directly, allowing the
      # same PCAP fixture writer to produce a file for the native tshark binary.
      # Source: https://emscripten.org/docs/tools_reference/settings_reference.html
      # setting NODERAWFS.
      "-sNODERAWFS=1" "-sNO_DISABLE_EXCEPTION_CATCHING" "-sEXIT_RUNTIME=1")
    set_target_properties(capture_fixture PROPERTIES SUFFIX ".js")
  else()
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

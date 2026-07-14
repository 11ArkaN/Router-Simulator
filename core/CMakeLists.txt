cmake_minimum_required(VERSION 3.22)
project(router_simulator_core LANGUAGES CXX)

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
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_library(router_core STATIC
  src/cli.cpp
  src/hardware.cpp
  src/network.cpp
  src/packet.cpp
  src/routing.cpp
  src/runtime.cpp
)
target_include_directories(router_core PUBLIC include)

if(NOT EMSCRIPTEN AND ROUTER_SANITIZERS AND
   CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
  # Sanitizers are native-only because Wasm pthread execution is validated in
  # the browser build. Applying the flags transitively ensures test executables
  # and router_core use the same instrumented allocation and thread runtime.
  target_compile_options(router_core PUBLIC "-fsanitize=${ROUTER_SANITIZERS}" -fno-omit-frame-pointer)
  target_link_options(router_core PUBLIC "-fsanitize=${ROUTER_SANITIZERS}")
endif()

if(EMSCRIPTEN)
  # Every object that can reach atomics or std::thread must be compiled with
  # pthread features. Applying this to the core prevents mixed archives that
  # link successfully in native builds but are invalid shared-memory Wasm.
  # The hot packet path lives in this archive, so optimizing only the final
  # executable leaves parsers, checksums and forwarding at Clang's -O0 default.
  # Keep the optimization contract on the archive itself to make every Wasm
  # consumer, including the browser runtime, use the same production code.
  target_compile_options(router_core PUBLIC -pthread -O3)
endif()

if(ROUTER_BUILD_BENCHMARKS)
  add_executable(packet_benchmark tools/packet_benchmark.cpp)
  target_link_libraries(packet_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(packet_benchmark PRIVATE -O3 -pthread)
    target_link_options(packet_benchmark PRIVATE -O3 -pthread "-sPTHREAD_POOL_SIZE=2" "-sINITIAL_MEMORY=67108864")
    set_target_properties(packet_benchmark PROPERTIES SUFFIX ".js")
  endif()
  add_executable(structure_benchmark tools/structure_benchmark.cpp)
  target_link_libraries(structure_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(structure_benchmark PRIVATE -O3 -pthread)
    target_link_options(structure_benchmark PRIVATE -O3 -pthread "-sPTHREAD_POOL_SIZE=2" "-sINITIAL_MEMORY=134217728" "-sALLOW_MEMORY_GROWTH=0")
    set_target_properties(structure_benchmark PROPERTIES SUFFIX ".js")
  endif()
  add_executable(runtime_benchmark tools/runtime_benchmark.cpp)
  target_link_libraries(runtime_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(runtime_benchmark PRIVATE -O3 -pthread)
    target_link_options(runtime_benchmark PRIVATE -O3 -pthread "-sPTHREAD_POOL_SIZE=2" "-sINITIAL_MEMORY=268435456" "-sALLOW_MEMORY_GROWTH=0")
    set_target_properties(runtime_benchmark PROPERTIES SUFFIX ".js")
  endif()
endif()

if(ROUTER_BUILD_MANUAL)
  add_executable(manual_session tools/manual_session.cpp)
  target_link_libraries(manual_session PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(manual_session PRIVATE -pthread)
    target_link_options(manual_session PRIVATE -pthread "-sPTHREAD_POOL_SIZE=2" "-sINITIAL_MEMORY=201326592")
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
    "-sPTHREAD_POOL_SIZE=2"
    "-sINITIAL_MEMORY=268435456"
    "-sALLOW_MEMORY_GROWTH=0"
    "-sMODULARIZE=1"
    "-sEXPORT_ES6=1"
    "-sEXPORT_NAME=createRouterRuntime"
    "-sENVIRONMENT=worker"
    "-sEXPORTED_FUNCTIONS=['_malloc','_free','_rs_create','_rs_command','_rs_capture_prepare','_rs_capture_data','_rs_capture_size','_rs_shutdown','_runtime_initialize','_runtime_capabilities','_lab_open','_lab_close','_lab_submit_command','_cli_open_session','_cli_push_input','_cli_read_output','_telemetry_get_page','_telemetry_get_page_size','_capture_start','_capture_stop','_capture_export_pcapng','_checkpoint_export','_checkpoint_export_size','_checkpoint_import','_project_export','_project_import']"
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
    target_link_options(core_tests PRIVATE -pthread "-sPTHREAD_POOL_SIZE=2" "-sINITIAL_MEMORY=201326592" "-sNO_DISABLE_EXCEPTION_CATCHING")
    set_target_properties(core_tests PROPERTIES SUFFIX ".js")
  endif()
  add_test(NAME core_tests COMMAND core_tests)
  if(NOT EMSCRIPTEN)
    add_executable(capture_fixture tools/capture_fixture.cpp)
    target_link_libraries(capture_fixture PRIVATE router_core)
    set(CAPTURE_FIXTURE "${CMAKE_CURRENT_BINARY_DIR}/conformance.pcapng")
    add_test(NAME capture_fixture COMMAND capture_fixture "${CAPTURE_FIXTURE}")
    find_program(TSHARK_EXECUTABLE tshark)
    if(TSHARK_EXECUTABLE)
      add_test(NAME tshark_pcapng
        COMMAND "${TSHARK_EXECUTABLE}" -n -r "${CAPTURE_FIXTURE}" -c 1)
      set_tests_properties(tshark_pcapng PROPERTIES DEPENDS capture_fixture)
    endif()
  endif()
endif()

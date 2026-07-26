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

# Native conformance builds use the host OpenSSL development package. Wasm
# keeps using the separately pinned archive below because host libraries cannot
# be linked into a shared-memory Emscripten module. Requiring 3.5 preserves the
# EVP and provider contracts used by the production 3.5.x dependency line.
if(NOT EMSCRIPTEN)
  find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto SSL)
endif()

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
add_library(router_primitives STATIC
    src/dns/dns_packet.cpp
    src/dns/dns_svcb.cpp
    src/dns/ddr_discovery.cpp
  src/dns/dns_authoritative.cpp
  src/dns/dns_cache.cpp
  src/dns/dns_master_file.cpp
  src/dns/dns_resolver.cpp
  src/dns/dnssec_record.cpp
  src/dns/dnssec_validation.cpp
  src/dns/dnssec_chain.cpp
  src/dns/dnssec_denial.cpp
  # Authoritative DNSSEC assembly only joins already signed wire records. It
  # has no cryptographic dependency and must therefore remain available to
  # native conformance tests as well as the OpenSSL-backed Wasm build.
  src/dns/dnssec_authoritative_response.cpp
  src/dns/dnssec_nsec3_chain.cpp
  src/dns/dnssec_response_validation.cpp
  src/dhcpv6/dhcpv6_client.cpp
  src/dhcpv6/dhcpv6_lease.cpp
  src/dhcpv6/dhcpv6_packet.cpp
  src/dhcpv6/dhcpv6_relay.cpp
  src/dhcpv6/dhcpv6_relay_lease.cpp
  src/dhcpv6/dhcpv6_relay_route.cpp
  src/dhcpv6/dhcpv6_retransmission.cpp
  src/dhcpv6/dhcpv6_server.cpp
  src/forwarding/ethernet_switch.cpp
  src/ip/ip_address.cpp
  src/ip/ipv4_path_mtu.cpp
  src/ip/ipv4_reassembly.cpp
  src/ip/ipv6_extension.cpp
  src/ip/ipv6_fragmentation.cpp
  src/ip/ipv6_path_mtu.cpp
  src/ip/ipv6_source_selection.cpp
  src/ip/ipv6_stable_iid.cpp
  src/security/ikev2_packet.cpp
  src/security/ikev2_authentication.cpp
  src/security/ikev2_exchange.cpp
  src/security/ikev2_fragmentation.cpp
  src/security/ikev2_kdf.cpp
  src/security/ikev2_negotiation.cpp
  src/security/ikev2_payload.cpp
  src/security/ikev2_payload_data.cpp
  src/security/ikev2_peer_path.cpp
  src/security/ikev2_profile.cpp
  src/security/ikev2_sa.cpp
  src/security/ikev2_session_service.cpp
  src/security/ikev2_udp_service.cpp
  src/security/ipsec_packet.cpp
  src/security/ipsec_ah_canonical.cpp
  src/security/ipsec_ah_processor.cpp
  # The forwarding security owner composes the SPD, SAD, AH and ESP modules.
  # Cryptographic algorithms enter through explicit dependency callbacks, so
  # this orchestration source is portable and belongs in every core build.
  src/security/ipsec_forwarding_security.cpp
  src/security/ipsec_esp_gcm.cpp
  src/security/ipsec_esp_processor.cpp
  src/security/ipsec_lifetime.cpp
  src/security/ipsec_integrity.cpp
  src/security/ipsec_nat_t.cpp
  src/security/ipsec_policy.cpp
  src/security/ipsec_replay.cpp
  src/security/ipsec_sad.cpp
  src/ip/mld_packet.cpp
  src/ip/mld_import_policy.cpp
  src/ip/mld_listener.cpp
  src/ip/mld_router.cpp
  src/ip/neighbor_discovery_packet.cpp
  # OSPF packet framing is a protocol primitive. It depends only on IP address
  # and checksum helpers and cannot acquire LSDB, runtime or CLI ownership.
  src/ospf/ospf_fsm.cpp
  src/ospf/ospf_configuration.cpp
  src/ospf/ospf_interface.cpp
  src/ospf/ospf_database_exchange.cpp
  src/ospf/ospf_lsdb.cpp
  src/ospf/ospf_lsa.cpp
  src/ospf/ospf_lsa_builder.cpp
  src/ospf/ospf_packet.cpp
  src/ospf/ospf_authentication.cpp
  src/ospf/ospf_keychain.cpp
  src/ospf/ospf_area_coordinator.cpp
  src/ospf/ospf_process.cpp
  src/ospf/ospf_process_checkpoint.cpp
  src/ospf/ospf_process_database.cpp
  src/ospf/ospf_process_origination.cpp
  src/ospf/ospf_process_output.cpp
  src/ospf/ospf_route_calculator.cpp
  src/ospf/ospf_spf.cpp
  src/ospf/ospf_topology.cpp
  src/forwarding/route_policy.cpp
  src/forwarding/packet.cpp
  src/security/sha256.cpp
  src/transport/tcp_packet.cpp
  src/transport/tcp_congestion.cpp
  src/transport/tcp_connection.cpp
  src/transport/tcp_checkpoint_codec.cpp
  src/transport/tcp_endpoint.cpp
  src/transport/tcp_control_block.cpp
  src/transport/tcp_failure.cpp
  src/transport/tcp_isn.cpp
  src/transport/tcp_options.cpp
  src/transport/tcp_receive_buffer.cpp
  src/transport/tcp_receive_window.cpp
  src/transport/tcp_retransmission.cpp
  src/transport/tcp_sack_scoreboard.cpp
  src/transport/tcp_send_buffer.cpp
  src/transport/tcp_sender.cpp
  src/transport/tcp_timers.cpp
  src/transport/tcp_transmission_history.cpp
  src/security/tls_profile.cpp
  src/transport/udp_packet.cpp
  src/transport/udp_transport.cpp
)
target_link_libraries(router_primitives PUBLIC router_build_options)
if(NOT EMSCRIPTEN)
  target_link_libraries(router_primitives PUBLIC OpenSSL::SSL OpenSSL::Crypto)
endif()

if(EMSCRIPTEN)
  # OpenSSL is built once with the same native-Windows Emscripten toolchain as
  # the core. Keeping the dependency imported avoids silently compiling crypto
  # with different pthread or ABI settings. The bootstrap script pins and
  # verifies the upstream archive before producing this archive.
  set(ROUTER_OPENSSL_ROOT
      "${CMAKE_CURRENT_SOURCE_DIR}/../.tools/dependencies/wasm/openssl-3.5.7")
  set(ROUTER_OPENSSL_CRYPTO "${ROUTER_OPENSSL_ROOT}/lib/libcrypto.a")
  set(ROUTER_OPENSSL_SSL "${ROUTER_OPENSSL_ROOT}/lib/libssl.a")
  set(ROUTER_NGHTTP2_ROOT
      "${CMAKE_CURRENT_SOURCE_DIR}/../.tools/dependencies/wasm/nghttp2-1.69.0")
  set(ROUTER_NGHTTP3_ROOT
      "${CMAKE_CURRENT_SOURCE_DIR}/../.tools/dependencies/wasm/nghttp3-1.17.0")
  set(ROUTER_NGTCP2_ROOT
      "${CMAKE_CURRENT_SOURCE_DIR}/../.tools/dependencies/wasm/ngtcp2-1.24.0")
  set(ROUTER_NGHTTP2_LIBRARY "${ROUTER_NGHTTP2_ROOT}/lib/libnghttp2.a")
  set(ROUTER_NGHTTP3_LIBRARY "${ROUTER_NGHTTP3_ROOT}/lib/libnghttp3.a")
  set(ROUTER_NGTCP2_LIBRARY "${ROUTER_NGTCP2_ROOT}/lib/libngtcp2.a")
  set(ROUTER_NGTCP2_OSSL_LIBRARY
      "${ROUTER_NGTCP2_ROOT}/lib/libngtcp2_crypto_ossl.a")
  if(NOT EXISTS "${ROUTER_OPENSSL_CRYPTO}" OR
     NOT EXISTS "${ROUTER_OPENSSL_SSL}")
    message(FATAL_ERROR
      "Pinned Wasm OpenSSL is missing. Run pnpm dependencies:bootstrap.")
  endif()
  if(NOT EXISTS "${ROUTER_NGHTTP2_LIBRARY}" OR
     NOT EXISTS "${ROUTER_NGHTTP3_LIBRARY}" OR
     NOT EXISTS "${ROUTER_NGTCP2_LIBRARY}" OR
     NOT EXISTS "${ROUTER_NGTCP2_OSSL_LIBRARY}")
    message(FATAL_ERROR
      "Pinned Wasm HTTP and QUIC libraries are missing. Run pnpm dependencies:bootstrap.")
  endif()
  add_library(router_openssl_crypto STATIC IMPORTED GLOBAL)
  set_target_properties(router_openssl_crypto PROPERTIES
    IMPORTED_LOCATION "${ROUTER_OPENSSL_CRYPTO}"
    INTERFACE_INCLUDE_DIRECTORIES "${ROUTER_OPENSSL_ROOT}/include")
  add_library(router_openssl_ssl STATIC IMPORTED GLOBAL)
  set_target_properties(router_openssl_ssl PROPERTIES
    IMPORTED_LOCATION "${ROUTER_OPENSSL_SSL}"
    INTERFACE_INCLUDE_DIRECTORIES "${ROUTER_OPENSSL_ROOT}/include")
  target_link_libraries(router_openssl_ssl INTERFACE router_openssl_crypto)
  # These imported targets expose only memory-driven protocol engines. Socket
  # ownership stays in the emulator transports, so linking a third-party wire
  # codec cannot create a path around Ethernet, port, queue or link ownership.
  add_library(router_nghttp2 STATIC IMPORTED GLOBAL)
  set_target_properties(router_nghttp2 PROPERTIES
    IMPORTED_LOCATION "${ROUTER_NGHTTP2_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${ROUTER_NGHTTP2_ROOT}/include")
  add_library(router_nghttp3 STATIC IMPORTED GLOBAL)
  set_target_properties(router_nghttp3 PROPERTIES
    IMPORTED_LOCATION "${ROUTER_NGHTTP3_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${ROUTER_NGHTTP3_ROOT}/include")
  add_library(router_ngtcp2 STATIC IMPORTED GLOBAL)
  set_target_properties(router_ngtcp2 PROPERTIES
    IMPORTED_LOCATION "${ROUTER_NGTCP2_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${ROUTER_NGTCP2_ROOT}/include")
  add_library(router_ngtcp2_crypto_ossl STATIC IMPORTED GLOBAL)
  set_target_properties(router_ngtcp2_crypto_ossl PROPERTIES
    IMPORTED_LOCATION "${ROUTER_NGTCP2_OSSL_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${ROUTER_NGTCP2_ROOT}/include")
  target_link_libraries(router_ngtcp2_crypto_ossl INTERFACE
                        router_ngtcp2 router_openssl_ssl router_openssl_crypto)
  target_sources(router_primitives PRIVATE src/dns/dnssec_openssl.cpp
                                            src/security/secret_vault.cpp
                                            src/security/ikev2_aes_gcm.cpp
                                            src/security/ikev2_encrypted_payload.cpp
                                            src/security/ikev2_dh.cpp
                                            src/security/ikev2_nat_detection.cpp
                                            src/dns/dnssec_signer.cpp
                                            src/dns/dnssec_zone_signer.cpp
                                            src/dns/dnssec_key_lifecycle.cpp
                                            src/dns/dnssec_nsec_chain.cpp
                                            src/dns/dnssec_zone_keys.cpp
                                            src/dns/dnssec_signed_zone.cpp
                                            src/dns/dnssec_signed_zone_owner.cpp
                                            src/security/pki_store.cpp
                                            src/security/tls_engine.cpp
                                            src/transport/http2_session.cpp
                                            src/transport/dot_session.cpp
                                            src/transport/doh_message.cpp
                                            src/transport/doh2_session.cpp
                                            src/transport/quic_connection.cpp
                                            src/transport/doq_session.cpp
                                            src/transport/http3_session.cpp
                                            src/transport/doh3_session.cpp)
  target_link_libraries(router_primitives PUBLIC router_openssl_ssl
                                                 router_openssl_crypto
                                                 router_nghttp2
                                                 router_nghttp3
                                                 router_ngtcp2_crypto_ossl
                                                 router_ngtcp2)
endif()

add_library(router_device STATIC
  src/forwarding/device_routing.cpp
  src/device/hardware.cpp
  src/device/ies_service.cpp
  src/runtime/lab_registry.cpp
  src/forwarding/multi_device_routing.cpp
  src/forwarding/routing.cpp
  src/device/router_hardware_inventory.cpp
)
target_link_libraries(router_device PUBLIC router_primitives router_build_options)

add_library(router_network STATIC
  src/runtime/capture_store.cpp
  src/dhcpv6/dhcpv6_endpoint_service.cpp
  src/dns/dns_endpoint_service.cpp
  src/ip/ipv6_dad.cpp
  src/ip/ipv6_destination_cache.cpp
  src/ip/ipv6_neighbor_cache.cpp
  src/ip/ipv6_host_autoconfiguration.cpp
  src/ip/icmpv4_statistics.cpp
  src/ip/icmpv6_statistics.cpp
  src/ip/ipv6_router_advertisement.cpp
  src/device/router_ipv6_address_table.cpp
  src/forwarding/multi_device_fabric.cpp
  src/runtime/network_plane.cpp
  # OSPF is a separate control pthread, but its packet channels terminate at
  # forwarding shards. Keeping the worker in the network layer preserves the
  # primitive protocol library's independence from lab device handles.
  src/ospf/ospf_control_worker.cpp
  src/forwarding/network_endpoint.cpp
  src/forwarding/router_forwarder.cpp
  src/forwarding/sap_forwarding.cpp
)
target_include_directories(router_network PRIVATE src)
target_link_libraries(router_network PUBLIC router_device router_primitives router_build_options)

add_library(router_management STATIC
  src/cli/cli.cpp
  src/cli/cli_classic.cpp
  src/cli/cli_md.cpp
  src/cli/cli_parser.cpp
  src/cli/ies_cli_configuration.cpp
  src/cli/ipsec_cli_configuration.cpp
  src/cli/ospf_cli_configuration.cpp
  src/runtime/session_workflows.cpp
  src/cli/tls_cli_configuration.cpp
)
target_include_directories(router_management PRIVATE src)
target_link_libraries(router_management PUBLIC
  router_network router_device router_primitives router_build_options)

add_library(router_runtime STATIC
  src/runtime/control_projection_worker.cpp
  src/runtime/lab_runtime.cpp
  src/runtime/lab_checkpoint.cpp
  src/runtime/network_plane_worker.cpp
  src/runtime/runtime_memory_budget.cpp
  src/runtime/runtime_memory_growth.cpp
  src/runtime/runtime_supervisor.cpp
  src/runtime/runtime_supervisor_checkpoint.cpp
  src/runtime/runtime_supervisor_hosts.cpp
  src/runtime/runtime_supervisor_interfaces.cpp
  src/runtime/runtime_supervisor_routing.cpp
  src/runtime/runtime_supervisor_services.cpp
)
target_include_directories(router_runtime PRIVATE src)
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
  set(ROUTER_MEMORY_GROWTH_OPTIONS
      "-sALLOW_MEMORY_GROWTH=1"
      "-sMAXIMUM_MEMORY=${ROUTER_WASM_MAXIMUM_MEMORY}"
      "-sMEMORY_GROWTH_LINEAR_STEP=${ROUTER_WASM_GROWTH_STEP}"
      "-sGROWABLE_ARRAYBUFFERS=1")
  set(ROUTER_STACK_OPTION "-sSTACK_SIZE=${ROUTER_WASM_STACK_BYTES}")
endif()

if(ROUTER_BUILD_BENCHMARKS)
  add_executable(packet_benchmark tools/packet_benchmark.cpp)
  target_link_libraries(packet_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(packet_benchmark PRIVATE -O3 -pthread)
    target_link_options(packet_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      ${ROUTER_MEMORY_GROWTH_OPTIONS}
      "-sEXIT_RUNTIME=1")
    set_target_properties(packet_benchmark PROPERTIES SUFFIX ".js")
  endif()
  add_executable(structure_benchmark tools/structure_benchmark.cpp)
  target_link_libraries(structure_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(structure_benchmark PRIVATE -O3 -pthread)
    target_link_options(structure_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      ${ROUTER_MEMORY_GROWTH_OPTIONS} "-sEXIT_RUNTIME=1")
    set_target_properties(structure_benchmark PROPERTIES SUFFIX ".js")
  endif()
  add_executable(runtime_benchmark tools/runtime_benchmark.cpp)
  target_link_libraries(runtime_benchmark PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(runtime_benchmark PRIVATE -O3 -pthread)
    target_link_options(runtime_benchmark PRIVATE -O3 -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      ${ROUTER_MEMORY_GROWTH_OPTIONS} "-sNO_DISABLE_EXCEPTION_CATCHING"
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
      ${ROUTER_MEMORY_GROWTH_OPTIONS}
      "-sEXIT_RUNTIME=1")
    set_target_properties(manual_session PROPERTIES SUFFIX ".js")
  endif()
endif()

if(EMSCRIPTEN)
  add_executable(simulator src/runtime/wasm_api.cpp)
  target_link_libraries(simulator PRIVATE router_core)
  target_compile_options(simulator PRIVATE -pthread -O3)
  target_link_options(simulator PRIVATE
    -pthread
    -O3
    "${ROUTER_PTHREAD_POOL_OPTION}"
    "${ROUTER_MEMORY_OPTION}"
    "${ROUTER_STACK_OPTION}"
    ${ROUTER_MEMORY_GROWTH_OPTIONS}
    "-sMODULARIZE=1"
    "-sEXPORT_ES6=1"
    "-sEXPORT_NAME=createRouterRuntime"
    "-sENVIRONMENT=worker"
    "-sEXPORTED_FUNCTIONS=['_malloc','_free','_runtime_initialize','_secret_vault_initialize','_runtime_capabilities','_memory_epoch','_memory_size','_memory_reserve','_lab_close','_lab_submit_command','_telemetry_get_page','_telemetry_get_page_size','_telemetry_publish','_telemetry_get_layout','_capture_export_pcapng','_capture_export_size','_capture_clear','_checkpoint_export','_checkpoint_export_size','_checkpoint_import']"
    # HEAPU8 is an explicit Emscripten module API dependency. Newer optimized
    # builds keep the internal view lexical unless it is exported, so relying
    # on an accidental Module property makes browser startup version-sensitive.
    "-sEXPORTED_RUNTIME_METHODS=['ccall','HEAPU8','wasmMemory']"
  )
  set_target_properties(simulator PROPERTIES SUFFIX ".js")
endif()

if(ROUTER_BUILD_TESTS)
  enable_testing()
  add_executable(core_tests
    src/runtime/wasm_api.cpp
    tests/runners/core_test_main.cpp
    tests/cli/cli_test.cpp
    tests/runtime/control_projection_worker_test.cpp
    tests/ip/ip_address_test.cpp
    tests/runtime/lab_runtime_test.cpp
    tests/ip/neighbor_discovery_packet_test.cpp
    tests/forwarding/packet_test.cpp
    tests/runtime/runtime_supervisor_test.cpp
    tests/runtime/runtime_memory_growth_test.cpp
    tests/runtime/wasm_api_test.cpp
    tests/runtime/network_plane_worker_test.cpp
  )
  target_link_libraries(core_tests PRIVATE router_core)
  if(EMSCRIPTEN)
    target_compile_options(core_tests PRIVATE -pthread)
    # Checkpoint integration deliberately keeps the source and restored
    # LabRuntime alive together inside one Node Wasm instance. Production swaps
    # two browser Workers, each with its own 320 MiB memory, so the test target
    # needs two production budgets without changing the simulator contract.
    set(ROUTER_TEST_MEMORY_OPTION "-sINITIAL_MEMORY=671088640")
    # The checkpoint replacement test intentionally overlaps two complete
    # high-CPU runtimes. Each runtime owns five pthreads in addition to its
    # calling Worker, so the test pool must contain ten actual workers. Using
    # the production expression here makes Emscripten recycle a terminated
    # owner and print late-command diagnostics after otherwise passing tests.
    set(ROUTER_TEST_PTHREAD_POOL_OPTION "-sPTHREAD_POOL_SIZE=10")
    target_link_options(core_tests PRIVATE -pthread
      "${ROUTER_TEST_PTHREAD_POOL_OPTION}" "${ROUTER_TEST_MEMORY_OPTION}" "${ROUTER_STACK_OPTION}"
      ${ROUTER_MEMORY_GROWTH_OPTIONS}
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
    tests/runtime/capture_store_test.cpp
    tests/dhcpv6/dhcpv6_client_test.cpp
    tests/dhcpv6/dhcpv6_lease_test.cpp
    tests/dhcpv6/dhcpv6_packet_test.cpp
    tests/dhcpv6/dhcpv6_relay_test.cpp
    tests/dhcpv6/dhcpv6_relay_lease_test.cpp
    tests/dhcpv6/dhcpv6_relay_route_test.cpp
    tests/dhcpv6/dhcpv6_retransmission_test.cpp
    tests/dhcpv6/dhcpv6_server_test.cpp
    tests/forwarding/ethernet_switch_test.cpp
    tests/dns/dns_packet_test.cpp
    tests/dns/ddr_discovery_test.cpp
    tests/dns/dns_authoritative_test.cpp
    tests/dns/dns_cache_test.cpp
    tests/dns/dns_master_file_test.cpp
    tests/dns/dns_resolver_test.cpp
    tests/dns/dnssec_record_test.cpp
    tests/dns/dnssec_validation_test.cpp
    tests/dns/dnssec_chain_test.cpp
    tests/dns/dnssec_denial_test.cpp
    tests/dns/dns_endpoint_service_test.cpp
    tests/device/hardware_test.cpp
    tests/runtime/lab_registry_test.cpp
    tests/ip/ipv4_reassembly_test.cpp
    tests/ip/ipv6_dad_test.cpp
    tests/ip/ipv6_extension_test.cpp
    tests/ip/ipv6_fragmentation_test.cpp
    tests/ip/ipv6_destination_cache_test.cpp
    tests/ip/ipv6_host_autoconfiguration_test.cpp
    tests/ip/icmpv4_statistics_test.cpp
    tests/ip/icmpv6_statistics_test.cpp
    tests/device/ies_service_test.cpp
    tests/cli/ies_cli_configuration_test.cpp
    tests/cli/ospf_cli_configuration_test.cpp
    tests/ospf/ospf_area_coordinator_test.cpp
    tests/ip/ipv6_path_mtu_test.cpp
    tests/ip/ipv4_path_mtu_test.cpp
    tests/ip/ipv6_neighbor_cache_test.cpp
    tests/ip/ipv6_router_advertisement_test.cpp
    tests/device/router_ipv6_address_table_test.cpp
    tests/ip/ipv6_source_selection_test.cpp
    tests/ip/ipv6_stable_iid_test.cpp
    tests/security/ikev2_packet_test.cpp
    tests/security/ikev2_authentication_test.cpp
    tests/security/ikev2_exchange_test.cpp
    tests/security/ikev2_fragmentation_test.cpp
    tests/security/ikev2_kdf_test.cpp
    tests/security/ikev2_negotiation_test.cpp
    tests/security/ikev2_payload_test.cpp
    tests/security/ikev2_payload_data_test.cpp
    tests/security/ikev2_peer_path_test.cpp
    tests/security/ikev2_profile_test.cpp
    tests/security/ikev2_sa_test.cpp
    tests/security/ikev2_session_service_test.cpp
    tests/security/ikev2_udp_service_test.cpp
    tests/security/ipsec_test.cpp
    tests/security/ipsec_ah_canonical_test.cpp
    tests/security/ipsec_ah_processor_test.cpp
    tests/security/ipsec_lifetime_test.cpp
    tests/security/ipsec_integrity_test.cpp
    tests/cli/ipsec_cli_configuration_test.cpp
    tests/security/ipsec_nat_t_test.cpp
    tests/ip/mld_packet_test.cpp
    tests/ip/mld_import_policy_test.cpp
    tests/ip/mld_listener_test.cpp
    tests/ip/mld_router_test.cpp
    tests/ospf/ospf_fsm_test.cpp
    tests/ospf/ospf_configuration_test.cpp
    tests/ospf/ospf_interface_test.cpp
    tests/ospf/ospf_database_exchange_test.cpp
    tests/ospf/ospf_lsdb_test.cpp
    tests/ospf/ospf_lsa_test.cpp
    tests/ospf/ospf_lsa_builder_test.cpp
    tests/ospf/ospf_packet_test.cpp
    tests/ospf/ospf_authentication_test.cpp
    tests/ospf/ospf_keychain_test.cpp
    tests/ospf/ospf_process_address_family_test.cpp
    tests/ospf/ospf_process_broadcast_test.cpp
    tests/ospf/ospf_process_point_to_point_test.cpp
    tests/ospf/ospf_process_restart_test.cpp
    tests/ospf/ospf_process_test.cpp
    tests/ospf/ospf_route_calculator_test.cpp
    tests/ospf/ospf_packet_channel_test.cpp
    tests/ospf/ospf_route_channel_test.cpp
    tests/ospf/ospf_spf_test.cpp
    tests/ospf/ospf_topology_test.cpp
    tests/forwarding/route_policy_test.cpp
    tests/forwarding/multi_device_fabric_test.cpp
    tests/forwarding/multi_device_routing_test.cpp
    tests/runners/module_test_main.cpp
    tests/forwarding/network_endpoint_ipv4_test.cpp
    tests/forwarding/network_endpoint_ipv6_test.cpp
    tests/runtime/network_plane_test.cpp
    tests/forwarding/routing_test.cpp
    tests/device/router_hardware_inventory_test.cpp
    tests/runtime/shard_policy_test.cpp
    tests/forwarding/router_forwarder_ipv4_redirect_test.cpp
    tests/forwarding/router_forwarder_local_ipv4_test.cpp
    tests/forwarding/router_forwarder_ospfv3_test.cpp
    tests/forwarding/router_forwarder_test.cpp
    tests/forwarding/sap_forwarding_test.cpp
    tests/runtime/session_workflows_test.cpp
    tests/transport/tcp_packet_test.cpp
    tests/transport/tcp_congestion_test.cpp
    tests/transport/tcp_connection_test.cpp
    tests/transport/tcp_endpoint_test.cpp
    tests/transport/tcp_control_block_test.cpp
    tests/transport/tcp_failure_test.cpp
    tests/transport/tcp_isn_test.cpp
    tests/transport/tcp_options_test.cpp
    tests/transport/tcp_receive_buffer_test.cpp
    tests/transport/tcp_receive_window_test.cpp
    tests/transport/tcp_retransmission_test.cpp
    tests/transport/tcp_sack_scoreboard_test.cpp
    tests/transport/tcp_send_buffer_test.cpp
    tests/transport/tcp_sender_test.cpp
    tests/transport/tcp_timers_test.cpp
    tests/transport/tcp_transmission_history_test.cpp
    tests/transport/tcp_sequence_test.cpp
    tests/security/tls_profile_test.cpp
    tests/transport/udp_packet_test.cpp
    tests/transport/udp_transport_test.cpp
  )
  target_include_directories(module_tests PRIVATE src)
  if(EMSCRIPTEN)
    # The provider test uses an RFC-published signature and therefore runs in
    # the same Wasm environment and libcrypto archive as production.
    target_sources(module_tests PRIVATE tests/dns/dnssec_openssl_test.cpp
                                        tests/security/secret_vault_test.cpp
                                        tests/security/ikev2_aes_gcm_test.cpp
                                        tests/security/ikev2_encrypted_payload_test.cpp
                                        tests/security/ikev2_dh_test.cpp
                                        tests/security/ikev2_nat_detection_test.cpp
                                        tests/security/ipsec_esp_processor_test.cpp
                                        tests/security/ipsec_esp_gcm_test.cpp
                                        tests/dns/dnssec_signer_test.cpp
                                        tests/dns/dnssec_zone_signer_test.cpp
                                        tests/dns/dnssec_key_lifecycle_test.cpp
                                        tests/dns/dnssec_nsec_chain_test.cpp
                                        tests/dns/dnssec_nsec3_chain_test.cpp
                                        tests/dns/dnssec_authoritative_response_test.cpp
                                        tests/dns/dnssec_response_validation_test.cpp
                                        tests/dns/dnssec_zone_keys_test.cpp
                                        tests/dns/dnssec_signed_zone_test.cpp
                                        tests/dns/dnssec_signed_zone_owner_test.cpp
                                        tests/security/pki_store_test.cpp
                                        tests/security/tls_engine_test.cpp
                                        tests/transport/http2_session_test.cpp
                                        tests/transport/dot_session_test.cpp
                                        tests/transport/doh2_session_test.cpp
                                        tests/transport/quic_connection_test.cpp
                                        tests/transport/http3_session_test.cpp)
  endif()
  target_link_libraries(module_tests PRIVATE router_management)
  if(EMSCRIPTEN)
    target_compile_options(module_tests PRIVATE -pthread)
    # The aggregate module runner invokes independent maximum-capacity
    # fixtures in one executable. Its diagnostic call frames are not part of
    # the production worker path, so reserve a separate 2 MiB test stack rather
    # than inflating every live pthread in the browser runtime.
    set(ROUTER_MODULE_TEST_STACK_OPTION "-sSTACK_SIZE=2097152")
    target_link_options(module_tests PRIVATE -pthread
      "${ROUTER_PTHREAD_POOL_OPTION}" "${ROUTER_MEMORY_OPTION}" "${ROUTER_MODULE_TEST_STACK_OPTION}"
      # NetworkPlane module tests construct several independent full-capacity
      # owners in one process. Use the same generated growth ceiling as the
      # browser runtime so additional protocol state cannot make the test
      # harness fail at its initial reservation while production would grow.
      ${ROUTER_MEMORY_GROWTH_OPTIONS}
      # Module suites deliberately throw on a failed invariant so the runner
      # can print the violated contract. Without Wasm exception catching the
      # first failure becomes an opaque __cxa_throw assertion instead.
      "-sNO_DISABLE_EXCEPTION_CATCHING"
      "-sEXIT_RUNTIME=1")
    set_target_properties(module_tests PROPERTIES SUFFIX ".js")
  elseif(MSVC)
    # Several conformance fixtures retain complete maximum-size frames and
    # protocol checkpoints in one test function. MSVC reserves one native
    # stack frame for all of those lexical objects at function entry, while the
    # production owners themselves live on the heap. Match the generated Wasm
    # stack budget so the Windows diagnostic runner tests behavior instead of
    # failing at process entry because of its default 1 MiB executable stack.
    target_link_options(module_tests PRIVATE /STACK:67108864)
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

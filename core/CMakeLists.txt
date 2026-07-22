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
    src/dns_packet.cpp
    src/dns_svcb.cpp
    src/ddr_discovery.cpp
  src/dns_authoritative.cpp
  src/dns_cache.cpp
  src/dns_master_file.cpp
  src/dns_resolver.cpp
  src/dnssec_record.cpp
  src/dnssec_validation.cpp
  src/dnssec_chain.cpp
  src/dnssec_denial.cpp
  # Authoritative DNSSEC assembly only joins already signed wire records. It
  # has no cryptographic dependency and must therefore remain available to
  # native conformance tests as well as the OpenSSL-backed Wasm build.
  src/dnssec_authoritative_response.cpp
  src/dnssec_nsec3_chain.cpp
  src/dnssec_response_validation.cpp
  src/dhcpv6_client.cpp
  src/dhcpv6_lease.cpp
  src/dhcpv6_packet.cpp
  src/dhcpv6_relay.cpp
  src/dhcpv6_relay_lease.cpp
  src/dhcpv6_relay_route.cpp
  src/dhcpv6_retransmission.cpp
  src/dhcpv6_server.cpp
  src/ip_address.cpp
  src/ipv4_path_mtu.cpp
  src/ipv4_reassembly.cpp
  src/ipv6_extension.cpp
  src/ipv6_fragmentation.cpp
  src/ipv6_path_mtu.cpp
  src/ipv6_source_selection.cpp
  src/ipv6_stable_iid.cpp
  src/ikev2_packet.cpp
  src/ikev2_authentication.cpp
  src/ikev2_exchange.cpp
  src/ikev2_fragmentation.cpp
  src/ikev2_kdf.cpp
  src/ikev2_negotiation.cpp
  src/ikev2_payload.cpp
  src/ikev2_payload_data.cpp
  src/ikev2_peer_path.cpp
  src/ikev2_profile.cpp
  src/ikev2_sa.cpp
  src/ikev2_session_service.cpp
  src/ikev2_udp_service.cpp
  src/ipsec_packet.cpp
  src/ipsec_ah_canonical.cpp
  src/ipsec_ah_processor.cpp
  # The forwarding security owner composes the SPD, SAD, AH and ESP modules.
  # Cryptographic algorithms enter through explicit dependency callbacks, so
  # this orchestration source is portable and belongs in every core build.
  src/ipsec_forwarding_security.cpp
  src/ipsec_esp_gcm.cpp
  src/ipsec_esp_processor.cpp
  src/ipsec_lifetime.cpp
  src/ipsec_integrity.cpp
  src/ipsec_nat_t.cpp
  src/ipsec_policy.cpp
  src/ipsec_replay.cpp
  src/ipsec_sad.cpp
  src/mld_packet.cpp
  src/mld_import_policy.cpp
  src/mld_listener.cpp
  src/mld_router.cpp
  src/neighbor_discovery_packet.cpp
  src/packet.cpp
  src/sha256.cpp
  src/tcp_packet.cpp
  src/tcp_congestion.cpp
  src/tcp_connection.cpp
  src/tcp_checkpoint_codec.cpp
  src/tcp_endpoint.cpp
  src/tcp_control_block.cpp
  src/tcp_failure.cpp
  src/tcp_isn.cpp
  src/tcp_options.cpp
  src/tcp_receive_buffer.cpp
  src/tcp_receive_window.cpp
  src/tcp_retransmission.cpp
  src/tcp_sack_scoreboard.cpp
  src/tcp_send_buffer.cpp
  src/tcp_sender.cpp
  src/tcp_timers.cpp
  src/tcp_transmission_history.cpp
  src/tls_profile.cpp
  src/udp_packet.cpp
  src/udp_transport.cpp
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
  target_sources(router_primitives PRIVATE src/dnssec_openssl.cpp
                                            src/secret_vault.cpp
                                            src/ikev2_aes_gcm.cpp
                                            src/ikev2_encrypted_payload.cpp
                                            src/ikev2_dh.cpp
                                            src/ikev2_nat_detection.cpp
                                            src/dnssec_signer.cpp
                                            src/dnssec_zone_signer.cpp
                                            src/dnssec_key_lifecycle.cpp
                                            src/dnssec_nsec_chain.cpp
                                            src/dnssec_zone_keys.cpp
                                            src/dnssec_signed_zone.cpp
                                            src/dnssec_signed_zone_owner.cpp
                                            src/pki_store.cpp
                                            src/tls_engine.cpp
                                            src/http2_session.cpp
                                            src/dot_session.cpp
                                            src/doh_message.cpp
                                            src/doh2_session.cpp
                                            src/quic_connection.cpp
                                            src/doq_session.cpp
                                            src/http3_session.cpp
                                            src/doh3_session.cpp)
  target_link_libraries(router_primitives PUBLIC router_openssl_ssl
                                                 router_openssl_crypto
                                                 router_nghttp2
                                                 router_nghttp3
                                                 router_ngtcp2_crypto_ossl
                                                 router_ngtcp2)
endif()

add_library(router_device STATIC
  src/device_routing.cpp
  src/hardware.cpp
  src/ies_service.cpp
  src/lab_registry.cpp
  src/multi_device_routing.cpp
  src/routing.cpp
  src/router_hardware_inventory.cpp
)
target_link_libraries(router_device PUBLIC router_primitives router_build_options)

add_library(router_network STATIC
  src/capture_store.cpp
  src/dhcpv6_endpoint_service.cpp
  src/dns_endpoint_service.cpp
  src/ipv6_dad.cpp
  src/ipv6_destination_cache.cpp
  src/ipv6_neighbor_cache.cpp
  src/ipv6_host_autoconfiguration.cpp
  src/icmpv4_statistics.cpp
  src/icmpv6_statistics.cpp
  src/ipv6_router_advertisement.cpp
  src/router_ipv6_address_table.cpp
  src/multi_device_fabric.cpp
  src/network_plane.cpp
  src/network_endpoint.cpp
  src/router_forwarder.cpp
  src/sap_forwarding.cpp
)
target_link_libraries(router_network PUBLIC router_device router_primitives router_build_options)

add_library(router_management STATIC
  src/cli.cpp
  src/cli_classic.cpp
  src/cli_md.cpp
  src/cli_parser.cpp
  src/ies_cli_configuration.cpp
  src/ipsec_cli_configuration.cpp
  src/session_workflows.cpp
  src/tls_cli_configuration.cpp
)
target_link_libraries(router_management PUBLIC
  router_network router_device router_primitives router_build_options)

add_library(router_runtime STATIC
  src/control_projection_worker.cpp
  src/lab_runtime.cpp
  src/lab_checkpoint.cpp
  src/network_plane_worker.cpp
  src/runtime_memory_budget.cpp
  src/runtime_memory_growth.cpp
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
  add_executable(simulator src/wasm_api.cpp)
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
    "-sEXPORTED_FUNCTIONS=['_malloc','_free','_runtime_initialize','_secret_vault_initialize','_runtime_capabilities','_memory_epoch','_memory_size','_memory_reserve','_lab_close','_lab_submit_command','_telemetry_get_page','_telemetry_get_page_size','_telemetry_publish','_telemetry_get_layout','_capture_export_pcapng','_capture_export_size','_checkpoint_export','_checkpoint_export_size','_checkpoint_import']"
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
    src/wasm_api.cpp
    tests/core_test_main.cpp
    tests/cli_test.cpp
    tests/control_projection_worker_test.cpp
    tests/ip_address_test.cpp
    tests/lab_runtime_test.cpp
    tests/neighbor_discovery_packet_test.cpp
    tests/packet_test.cpp
    tests/runtime_supervisor_test.cpp
    tests/runtime_memory_growth_test.cpp
    tests/wasm_api_test.cpp
    tests/network_plane_worker_test.cpp
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
    tests/capture_store_test.cpp
    tests/dhcpv6_client_test.cpp
    tests/dhcpv6_lease_test.cpp
    tests/dhcpv6_packet_test.cpp
    tests/dhcpv6_relay_test.cpp
    tests/dhcpv6_relay_lease_test.cpp
    tests/dhcpv6_relay_route_test.cpp
    tests/dhcpv6_retransmission_test.cpp
    tests/dhcpv6_server_test.cpp
    tests/dns_packet_test.cpp
    tests/ddr_discovery_test.cpp
    tests/dns_authoritative_test.cpp
    tests/dns_cache_test.cpp
    tests/dns_master_file_test.cpp
    tests/dns_resolver_test.cpp
    tests/dnssec_record_test.cpp
    tests/dnssec_validation_test.cpp
    tests/dnssec_chain_test.cpp
    tests/dnssec_denial_test.cpp
    tests/dns_endpoint_service_test.cpp
    tests/hardware_test.cpp
    tests/lab_registry_test.cpp
    tests/ipv4_reassembly_test.cpp
    tests/ipv6_dad_test.cpp
    tests/ipv6_extension_test.cpp
    tests/ipv6_fragmentation_test.cpp
    tests/ipv6_destination_cache_test.cpp
    tests/ipv6_host_autoconfiguration_test.cpp
    tests/icmpv4_statistics_test.cpp
    tests/icmpv6_statistics_test.cpp
    tests/ies_service_test.cpp
    tests/ies_cli_configuration_test.cpp
    tests/ipv6_path_mtu_test.cpp
    tests/ipv4_path_mtu_test.cpp
    tests/ipv6_neighbor_cache_test.cpp
    tests/ipv6_router_advertisement_test.cpp
    tests/router_ipv6_address_table_test.cpp
    tests/ipv6_source_selection_test.cpp
    tests/ipv6_stable_iid_test.cpp
    tests/ikev2_packet_test.cpp
    tests/ikev2_authentication_test.cpp
    tests/ikev2_exchange_test.cpp
    tests/ikev2_fragmentation_test.cpp
    tests/ikev2_kdf_test.cpp
    tests/ikev2_negotiation_test.cpp
    tests/ikev2_payload_test.cpp
    tests/ikev2_payload_data_test.cpp
    tests/ikev2_peer_path_test.cpp
    tests/ikev2_profile_test.cpp
    tests/ikev2_sa_test.cpp
    tests/ikev2_session_service_test.cpp
    tests/ikev2_udp_service_test.cpp
    tests/ipsec_test.cpp
    tests/ipsec_ah_canonical_test.cpp
    tests/ipsec_ah_processor_test.cpp
    tests/ipsec_lifetime_test.cpp
    tests/ipsec_integrity_test.cpp
    tests/ipsec_cli_configuration_test.cpp
    tests/ipsec_nat_t_test.cpp
    tests/mld_packet_test.cpp
    tests/mld_import_policy_test.cpp
    tests/mld_listener_test.cpp
    tests/mld_router_test.cpp
    tests/multi_device_fabric_test.cpp
    tests/multi_device_routing_test.cpp
    tests/module_test_main.cpp
    tests/network_endpoint_ipv4_test.cpp
    tests/network_endpoint_ipv6_test.cpp
    tests/network_plane_test.cpp
    tests/routing_test.cpp
    tests/router_hardware_inventory_test.cpp
    tests/shard_policy_test.cpp
    tests/router_forwarder_test.cpp
    tests/sap_forwarding_test.cpp
    tests/session_workflows_test.cpp
    tests/tcp_packet_test.cpp
    tests/tcp_congestion_test.cpp
    tests/tcp_connection_test.cpp
    tests/tcp_endpoint_test.cpp
    tests/tcp_control_block_test.cpp
    tests/tcp_failure_test.cpp
    tests/tcp_isn_test.cpp
    tests/tcp_options_test.cpp
    tests/tcp_receive_buffer_test.cpp
    tests/tcp_receive_window_test.cpp
    tests/tcp_retransmission_test.cpp
    tests/tcp_sack_scoreboard_test.cpp
    tests/tcp_send_buffer_test.cpp
    tests/tcp_sender_test.cpp
    tests/tcp_timers_test.cpp
    tests/tcp_transmission_history_test.cpp
    tests/tcp_sequence_test.cpp
    tests/tls_profile_test.cpp
    tests/udp_packet_test.cpp
    tests/udp_transport_test.cpp
  )
  if(EMSCRIPTEN)
    # The provider test uses an RFC-published signature and therefore runs in
    # the same Wasm environment and libcrypto archive as production.
    target_sources(module_tests PRIVATE tests/dnssec_openssl_test.cpp
                                        tests/secret_vault_test.cpp
                                        tests/ikev2_aes_gcm_test.cpp
                                        tests/ikev2_encrypted_payload_test.cpp
                                        tests/ikev2_dh_test.cpp
                                        tests/ikev2_nat_detection_test.cpp
                                        tests/ipsec_esp_processor_test.cpp
                                        tests/ipsec_esp_gcm_test.cpp
                                        tests/dnssec_signer_test.cpp
                                        tests/dnssec_zone_signer_test.cpp
                                        tests/dnssec_key_lifecycle_test.cpp
                                        tests/dnssec_nsec_chain_test.cpp
                                        tests/dnssec_nsec3_chain_test.cpp
                                        tests/dnssec_authoritative_response_test.cpp
                                        tests/dnssec_response_validation_test.cpp
                                        tests/dnssec_zone_keys_test.cpp
                                        tests/dnssec_signed_zone_test.cpp
                                        tests/dnssec_signed_zone_owner_test.cpp
                                        tests/pki_store_test.cpp
                                        tests/tls_engine_test.cpp
                                        tests/http2_session_test.cpp
                                        tests/dot_session_test.cpp
                                        tests/doh2_session_test.cpp
                                        tests/quic_connection_test.cpp
                                        tests/http3_session_test.cpp)
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

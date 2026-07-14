# Native entry point for repository-level CMake presets. The production core
# remains an independently configurable subproject because Emscripten builds
# invoke core/CMakeLists.txt directly and must not depend on frontend files.

cmake_minimum_required(VERSION 3.22)
project(router_simulator_native LANGUAGES CXX)

# CTest discovers tests recursively only when the repository-level build tree
# is testing-enabled before the core subdirectory registers its test targets.
enable_testing()
add_subdirectory(core)

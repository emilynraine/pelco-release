cmake_minimum_required(VERSION 3.16)
project(pelco_release VERSION 0.1.0 LANGUAGES C)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(PREL_TOP_LEVEL ON)
else()
  set(PREL_TOP_LEVEL OFF)
endif()
option(PREL_BUILD_TESTS "Build the conformance runner" ${PREL_TOP_LEVEL})

find_package(OpenSSL 1.1.1 REQUIRED COMPONENTS Crypto)

add_library(pelco_release
  src/prel_json.c
  src/prel_sha256.c
  src/prel_reader.c
  src/prel_crypto_openssl.c)
set_target_properties(pelco_release PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
target_include_directories(pelco_release
  PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include> $<INSTALL_INTERFACE:include>
  PRIVATE src)
target_link_libraries(pelco_release PRIVATE OpenSSL::Crypto)
if(NOT MSVC)
  target_compile_options(pelco_release PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)
endif()

install(TARGETS pelco_release)
install(FILES include/pelco_release.h TYPE INCLUDE)

if(PREL_BUILD_TESTS)
  enable_testing()
  add_executable(run_vectors test/run_vectors.c)
  set_target_properties(run_vectors PROPERTIES C_STANDARD 99)
  target_include_directories(run_vectors PRIVATE src)
  target_link_libraries(run_vectors PRIVATE pelco_release)
  add_test(NAME vectors COMMAND run_vectors ${CMAKE_CURRENT_SOURCE_DIR}/../vectors)
endif()

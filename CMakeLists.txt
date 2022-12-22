cmake_minimum_required(VERSION 3.0.0)

project(libcryptography VERSION 7.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(cryptography SHARED 
./src/cryptography/SymmetricKey.cc
./src/cryptography/AsymmetricKey.cc
)

set_target_properties(cryptography PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 7)

target_link_libraries(cryptography crypto)

add_executable(symmetric_crypto_test ./tests/SymmetricCrypto.cc)
target_link_libraries(symmetric_crypto_test cryptography)

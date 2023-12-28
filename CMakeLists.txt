cmake_minimum_required(VERSION 3.5.0)

project(libcryptography VERSION 7.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(cryptography SHARED 
./src/AsymmetricKey.cc
./src/AsymmetricEvpCipherContext.cc
./src/SymmetricEvpCipherContext.cc
./src/EvpMdContext.cc
./src/CryptoContext.cc
./src/File.cc
./src/Libcryptography.cc
./src/OnionParsing.cc
)

add_library(cryptography7 STATIC 
./src/AsymmetricKey.cc
./src/AsymmetricEvpCipherContext.cc
./src/SymmetricEvpCipherContext.cc
./src/EvpMdContext.cc
./src/CryptoContext.cc
./src/File.cc
./src/Libcryptography.cc
./src/OnionParsing.cc
)

set_target_properties(cryptography PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 7)
target_link_libraries(cryptography crypto)

add_executable(libcryptography_wrapper_test ./tests/Cryptowrapper.cc)
target_link_libraries(libcryptography_wrapper_test cryptography)

add_executable(envelopes_test ./tests/Envelopes.cc)
target_link_libraries(envelopes_test cryptography)

install(FILES
${CMAKE_BINARY_DIR}/libcryptography.so
${CMAKE_BINARY_DIR}/libcryptography.so.7
${CMAKE_BINARY_DIR}/libcryptography.so.7.0.0
DESTINATION "/usr/local/lib")

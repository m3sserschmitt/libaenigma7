cmake_minimum_required(VERSION 3.0.0)

project(libcryptography VERSION 7.0.0)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(cryptography SHARED 
./src/AsymmetricKey.cc
./src/AsymmetricEvpCipherContext.cc
./src/SymmetricEvpCipherContext.cc
./src/CryptoContext.cc
./src/File.cc
)

#add_library(cryptography7 STATIC 
#./src/cryptography/AsymmetricKey.cc
#./src/cryptography/AsymmetricCipher.cc
#./src/cryptography/SymmetricCipher.cc
#./src/cryptography/CryptoContext.cc
#)

set_target_properties(cryptography PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION 7)

target_link_libraries(cryptography crypto)

add_executable(libcryptography_test ./tests/Crypto.cc)
target_link_libraries(libcryptography_test cryptography)

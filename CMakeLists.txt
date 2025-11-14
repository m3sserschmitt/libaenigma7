cmake_minimum_required(VERSION 3.22.0)
project(libaenigma VERSION 7.0.0)

add_library(aenigma SHARED 
./src/cryptography/AsymmetricKey.cc
./src/cryptography/AsymmetricEvpCipherContext.cc
./src/cryptography/SymmetricEvpCipherContext.cc
./src/cryptography/EvpMdContext.cc
./src/cryptography/EvpCipherContext.cc
./src/cryptography/PublicKey.cc
./src/cryptography/PrivateKey.cc
./src/cryptography/KernelKeys.cc
./src/cryptography/Aenigma.cc
)

add_library(aenigma7 STATIC 
./src/cryptography/AsymmetricKey.cc
./src/cryptography/AsymmetricEvpCipherContext.cc
./src/cryptography/SymmetricEvpCipherContext.cc
./src/cryptography/EvpMdContext.cc
./src/cryptography/EvpCipherContext.cc
./src/cryptography/PublicKey.cc
./src/cryptography/PrivateKey.cc
./src/cryptography/KernelKeys.cc
./src/cryptography/Aenigma.cc
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(aenigma PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})
target_link_libraries(aenigma crypto)

if(ANDROID)
    message(STATUS "Skipping kernelkeys functions on platform Android.")
else ()
    target_link_libraries(aenigma keyutils)

    add_executable(aenigma_test ./tests/AenigmaTest.cc)
    target_link_libraries(aenigma_test aenigma)
endif ()

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

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

set_target_properties(aenigma PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

if(ANDROID)
    include_directories(${OPENSSL_ROOT_DIR}/include)

    add_library(crypto SHARED IMPORTED)
    set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${OPENSSL_ROOT_DIR}/lib/libcrypto.so)

    target_link_libraries(aenigma crypto)
else ()
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
    target_link_libraries(aenigma crypto)
    target_link_libraries(aenigma7 crypto)

    target_link_libraries(aenigma keyutils)
    target_link_libraries(aenigma7 keyutils)

    add_executable(aenigma_test ./tests/AenigmaTest.cc)
    target_link_libraries(aenigma_test aenigma)
endif ()

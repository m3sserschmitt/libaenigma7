cmake_minimum_required(VERSION 3.22.0)
project(libaenigma VERSION 7.0.0)

set(LIB_AENIGMA_KERNELKEYS_VERSION 1.0.0)
set(LIB_AENIGMA_KERNELKEYS_SOVERSION 1)
set(LIB_AENIGMA_INSTALL_DIR "libaenigma")
set(LIB_AENIGMA_ANDROID_INSTALL_DIR "libaenigma-android")

add_library(aenigma SHARED 
./src/cryptography/AsymmetricKey.cc
./src/cryptography/AsymmetricEvpCipherContext.cc
./src/cryptography/SymmetricEvpCipherContext.cc
./src/cryptography/EvpMdContext.cc
./src/cryptography/CryptoContext.cc
./src/cryptography/File.cc
./src/cryptography/Encryption.cc
./src/cryptography/Factories.cc
./src/cryptography/OnionParsing.cc
./src/cryptography/Utils.cc
./src/cryptography/OnionBuilding.cc
./src/cryptography/EvpCipherContext.cc
)

add_library(aenigma7 STATIC 
./src/cryptography/AsymmetricKey.cc
./src/cryptography/AsymmetricEvpCipherContext.cc
./src/cryptography/SymmetricEvpCipherContext.cc
./src/cryptography/EvpMdContext.cc
./src/cryptography/CryptoContext.cc
./src/cryptography/File.cc
./src/cryptography/Encryption.cc
./src/cryptography/Factories.cc
./src/cryptography/OnionParsing.cc
./src/cryptography/Utils.cc
./src/cryptography/OnionBuilding.cc
./src/cryptography/EvpCipherContext.cc
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
set_target_properties(aenigma PROPERTIES VERSION ${PROJECT_VERSION} SOVERSION ${PROJECT_VERSION_MAJOR})

if(ANDROID)
    message(STATUS "Skipping kernelkeys library when building for platform Android.")
    message(STATUS "Install rule will not be defined when building for platform Android.")

    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/openssl-src/include)

    add_library(crypto STATIC IMPORTED)
    set_target_properties(crypto PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/openssl-bin/${CMAKE_ANDROID_ARCH_ABI}/lib/libcrypto.a)
    target_link_libraries(aenigma crypto)

    install(FILES ${CMAKE_BINARY_DIR}/libaenigma.so DESTINATION ${LIB_AENIGMA_ANDROID_INSTALL_DIR}/${CMAKE_ANDROID_ARCH_ABI})
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/cryptography DESTINATION ${LIB_AENIGMA_ANDROID_INSTALL_DIR}/${CMAKE_ANDROID_ARCH_ABI}/include)
else ()
    target_link_libraries(aenigma crypto)
    add_library(aenigma-kernelkeys SHARED ./src/kernelkeys/KernelKeys.c)
    add_library(aenigma-kernelkeys${LIB_AENIGMA_KERNELKEYS_SOVERSION} STATIC ./src/kernelkeys/KernelKeys.c)
    set_target_properties(aenigma-kernelkeys PROPERTIES VERSION ${LIB_AENIGMA_KERNELKEYS_VERSION} SOVERSION ${LIB_AENIGMA_KERNELKEYS_SOVERSION})
    target_link_libraries(aenigma-kernelkeys keyutils)
    add_executable(aenigma_test ./tests/AenigmaTest.cc)
    target_link_libraries(aenigma_test aenigma)

    install(FILES
            ${CMAKE_BINARY_DIR}/libaenigma.so
            ${CMAKE_BINARY_DIR}/libaenigma.so.${PROJECT_VERSION_MAJOR}
            ${CMAKE_BINARY_DIR}/libaenigma.so.${PROJECT_VERSION}
            ${CMAKE_BINARY_DIR}/libaenigma-kernelkeys.so
            ${CMAKE_BINARY_DIR}/libaenigma-kernelkeys.so.${LIB_AENIGMA_KERNELKEYS_SOVERSION}
            ${CMAKE_BINARY_DIR}/libaenigma-kernelkeys.so.${LIB_AENIGMA_KERNELKEYS_VERSION}
            DESTINATION ${LIB_AENIGMA_INSTALL_DIR})
    install(DIRECTORY ${CMAKE_SOURCE_DIR}/include DESTINATION ${LIB_AENIGMA_INSTALL_DIR})
endif ()

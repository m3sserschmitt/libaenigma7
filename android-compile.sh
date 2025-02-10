#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <ABI>   Android ABI"
    exit 1
fi

API_FLAG=""
if [ -z "${ANDROID_API}" ]; then
    API_FLAG="-DCMAKE_ANDROID_API=21"
else
    API_FLAG="-DCMAKE_ANDROID_API=$ANDROID_API"
fi
ABI="$1"
CORES=$(nproc --all)
echo "Configuring for $ABI."
rm -rf ./android-build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS_RELEASE="-O3" -DCMAKE_CXX_FLAGS_RELEASE="-O3" -DANDROID_NDK=$ANDROID_NDK_HOME -DCMAKE_SYSTEM_NAME=Android -DCMAKE_ANDROID_NDK=$ANDROID_NDK_HOME -DCMAKE_ANDROID_ARCH_ABI=$ABI -DCMAKE_ANDROID_STL_TYPE=c++_shared -DCMAKE_ANDROID_NDK_TOOLCHAIN_VERSION=clang $API_FLAG -DCMAKE_INSTALL_PREFIX=./ -B./android-build
cd ./android-build
make -j$CORES
make install

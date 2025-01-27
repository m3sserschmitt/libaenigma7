#!/bin/bash

SCRIPT_PATH=$(dirname "$(realpath "$0")")
BIN="openssl-bin"
CORES=$(nproc --all)
OPENSSL_VERSION=""
API_LEVEL=""
OPENSSL_DIR="openssl-src"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <VERSION>   Openssl version to compile"
    exit 1
fi

if [ -z "${ANDROID_API}" ]; then
    API_LEVEL="21"
else
    API_LEVEL=$ANDROID_API
fi
OPENSSL_VERSION="$1"
OPENSSL_ARCHIVE="openssl-$OPENSSL_VERSION.tar.gz"

if [ -e $OPENSSL_ARCHIVE ]; then
    echo "$OPENSSL_ARCHIVE already exists."
else
    echo "$OPENSSL_ARCHIVE does not exists; Starting download..."
    wget https://www.openssl.org/source/$OPENSSL_ARCHIVE
fi

rm -rf $BIN
rm -rf $OPENSSL_DIR

tar -xf $OPENSSL_ARCHIVE
mv openssl-$OPENSSL_VERSION $OPENSSL_DIR

mkdir $BIN
mkdir $BIN/arm64-v8a
mkdir $BIN/armeabi-v7a
mkdir $BIN/x86
mkdir $BIN/x86_64

cd $OPENSSL_DIR

OPTIONS="no-shared"

./Configure android-arm $OPTIONS -D__ANDROID_API__=$API_LEVEL --prefix=$SCRIPT_PATH/$BIN/armeabi-v7a
make clean
make -j$CORES
make install_sw

./Configure android-arm64 $OPTIONS -D__ANDROID_API__=$API_LEVEL --prefix=$SCRIPT_PATH/$BIN/arm64-v8a
make clean
make -j$CORES
make install_sw

./Configure android-x86 $OPTIONS -D__ANDROID_API__=$API_LEVEL --prefix=$SCRIPT_PATH/$BIN/x86
make clean
make -j$CORES
make install_sw

./Configure android-x86_64 $OPTIONS -D__ANDROID_API__=$API_LEVEL --prefix=$SCRIPT_PATH/$BIN/x86_64
make clean
make -j$CORES
make install_sw

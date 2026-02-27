#!/bin/bash

# Aenigma - Federal messaging system
# Copyright © 2024-2025 Romulus-Emanuel Ruja <romulus-emanuel.ruja@tutanota.com>

# This file is part of Aenigma project.

# Aenigma is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# Aenigma is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with Aenigma.  If not, see <https://www.gnu.org/licenses/>.

set -Eeuo pipefail

SCRIPT_PATH=$(dirname "$(realpath "$0")")
OPENSSL_SOURCE="$SCRIPT_PATH/openssl"
OPENSSL_URL="https://github.com/openssl/openssl.git"
OPENSSL_BRANCH="openssl-3.0"
OPENSSL_TAG="openssl-3.0.19"
OPENSSL_ANDROID="$SCRIPT_PATH/openssl-android"
ANDROID_API="26"
CPU_CORES=$(nproc)

if [ ! -d "$OPENSSL_SOURCE" ]; then
    git clone --branch "$OPENSSL_BRANCH" --single-branch "$OPENSSL_URL" "$OPENSSL_SOURCE"
fi

cd "$OPENSSL_SOURCE"
git checkout "tags/$OPENSSL_TAG"

mkdir -p "$OPENSSL_ANDROID/armeabi-v7a"
./Configure android-arm -D__ANDROID_API__=$ANDROID_API --prefix=$OPENSSL_ANDROID/armeabi-v7a no-ssl shared no-tests
make clean
make -j"$CPU_CORES"
make install_sw

mkdir -p "$OPENSSL_ANDROID/arm64-v8a"
./Configure android-arm64 -D__ANDROID_API__=$ANDROID_API --prefix=$OPENSSL_ANDROID/arm64-v8a no-ssl shared no-tests
make clean
make -j"$CPU_CORES"
make install_sw

mkdir -p "$OPENSSL_ANDROID/x86"
./Configure android-x86 -D__ANDROID_API__=$ANDROID_API --prefix=$OPENSSL_ANDROID/x86 no-ssl shared no-tests
make clean
make -j"$CPU_CORES"
make install_sw

mkdir -p "$OPENSSL_ANDROID/x86_64"
./Configure android-x86_64 -D__ANDROID_API__=$ANDROID_API --prefix=$OPENSSL_ANDROID/x86_64 no-ssl shared no-tests
make clean
make -j"$CPU_CORES"
make install_sw

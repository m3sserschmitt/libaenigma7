### Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

These instructions will guide you through the building process for multiple platforms and assumes that
the following commands will be used on a Debian/Ubuntu distro.
You need `OpenSSL` library to be installed on your machine. Type this command in your terminal:

`openssl version`

If you see something similar to this: `OpenSSL 3.0.11 19 Sep 2023 (Library: OpenSSL 3.0.11 19 Sep 2023)`, it means that you have OpenSSL installed. Otherwise checkout [OpenSSL](https://www.openssl.org/) for details about installation process. You will also need `openssl-dev` and `libkeyutils-dev` installed in order to compile the source code. This packages could be installed using:

```bash
sudo apt-get install -y libssl-dev libkeyutils-dev gcc g++ make cmake
```

If you intend to build for Debian/Ubuntu arm64, `libssl-dev` and `libkeyutils-dev` can be installed using:

```bash
sudo dpkg --add-architecture arm64
sudo apt update
sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu make cmake libssl-dev:arm64 libkeyutils-dev:arm64
```

If you intend to build for Android, make sure to have Android SDK installed on your machine
and export its location like this

```bash
export ANDROID_NDK_ROOT=<sdk-path>/ndk/<ndk-version>
export PATH=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/<system>/bin:$PATH
```

>In the previous commands `<ndk-version>` is your installed NDK version,
>`<sdk-path>` is the path of your installed Android SDK and
>`<system>` is your local machine OS: `linux-x86_64`, `darwin-x86_64` `windows-x86_64` or `windows`.


### Building

The build process is automated by a series of scrips.

```bash
# go to source code:
cd /path/to/local/repository

# ensure all scripts in repository folder are executable:
sudo chmod +x ./*.sh

# build for current platform:
./build.sh

# build for arm64:
./build-arm64.sh

# build for android arm64-v8a, armeabi-v7a, x86, x86_64
# step 1: build openssl for android
./build-openssl-android.sh

# step 2: build the library and link against the prebuild version of openssl
./build-android.sh
```

### Authors

* **Romulus-Emanuel Ruja** <<romulus-emanuel.ruja@tutanota.com>>

### License

This project is licensed under the MIT License. Feel free to copy, modify and distribute it - see the [LICENSE](LICENSE) file for details.
## Getting Started

These instructions will get you a copy of the project up and running on your local machine.

### Prerequisites

This project is intended for Linux operating systems.
You need `OpenSSL` library to be installed on your machine. Type this command in your terminal:

`openssl version`

If you see something similar to this: `OpenSSL 3.0.11 19 Sep 2023 (Library: OpenSSL 3.0.11 19 Sep 2023)`, it means that you have OpenSSL installed. Otherwise checkout [OpenSSL](https://www.openssl.org/) for details about installation process. You will also need `openssl-dev` and `libkeyutils-dev` installed in order to compile the source code. This packages could be installed using `sudo apt-get install libssl-dev libkeyutils-dev` command.

### Installing

You need a copy of source code. Clone the repository using git:

`git clone https://github.com/m3sserschmitt/libaenigma7.git` 

OR

Download the `.zip` file and extract it.

Change the directory to newly downloaded source code:

`cd /path/to/local/repository`

Run cmake to create Makefiles:

`cmake -B./build`.

`cd build`

Now library can be compiled using `make`:

`make all`

Last command will compile both static and shared library.

Run `make install` if you want to install the shared library into `/usr/local/lib` directory.

Also you can checkout `./tests` directory for examples.

## Authors

* **Romulus-Emanuel Ruja** <<romulus-emanuel.ruja@tutanota.com>>

## License

This project is licensed under the MIT License. Feel free to copy, modify and distribute it - see the [LICENSE](LICENSE) file for details.
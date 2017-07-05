[libfreefare .NET wrapper](https://github.com/episage/SharpFreeFare)
====================

This is .NET project which lets you use [libfreefare](https://github.com/nfc-tools/libfreefare) from .NET C# or F#.

Related projects
---------------------
https://github.com/episage/SharpNFC

Requirements
---------------------

- Linux
- Mono
- installed libnfc
- installed libfreefare
- C# project [SharpNFC](https://github.com/episage/SharpNfc) referenced in the same solution

Installation
---------------------

In this particular case I used:

- Raspberry PI
- Arch Linux

Below is the code I use to download sources of libfreefare, libnfc, compile and install them.

```bash
wget https://libfreefare.googlecode.com/files/libfreefare-0.4.0.tar.bz2
wget https://libnfc.googlecode.com/files/libnfc-1.7.0.tar.bz2
tar xvjf libnfc-1.7.0.tar.bz2
tar xvjf libfreefare-0.4.0.tar.bz2

cd libnfc-1.7.0
./configure --prefix=/usr
make
make install
cd ..

cd libfreefare-0.4.0
./configure --prefix=/usr
make
make install
cd ..

wget https://alioth.debian.org/frs/download.php/file/3991/pcsc-lite-1.8.11.tar.bz2
tar xvjf pcsc-lite-1.8.11.tar.bz2
cd pcsc-lite-1.8.11
./configure --disable-libudev --enable-libusb
make
make install
cd ..
```

On recent Linux kernel (>= 3.1) you need to prevent modprobe from autoload pn533 and nfc modules.
To do that, create `/etc/modprobe.d/blacklist-libnfc.conf` with this content:

```text
blacklist pn533
blacklist nfc
```

Usage
---------------------

Attach this project to your solution and reference it.

Contributions
---------------------

Please contribute to this project

- update libfreefare and other dependencies in the bash script above
- make sure that the .NET unmanaged code is compatible with current libfreefare

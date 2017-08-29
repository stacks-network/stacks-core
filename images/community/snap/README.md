# Blockstack snap

A [snap](https://snapcraft.io) package offers a secure and isolated environment
for applications, with automatic and transactional updates. The blockstack snap
can be installed in all the
[supported Linux distros](https://snapcraft.io/docs/core/install).

## Build

To build this snap from source in an Ubuntu 16.04 machine, or later:

    $ sudo apt install git snapcraft
    $ git clone https://github.com/blockstack/blockstack-core
    $ cd blockstack-core/images/community
    $ snapcraft
    $ sudo snap install *.snap --dangerous

# varuint-bitcoin

[![NPM Package](https://img.shields.io/npm/v/varuint-bitcoin.svg?style=flat-square)](https://www.npmjs.org/package/varuint-bitcoin)
[![Build Status](https://img.shields.io/travis/bitcoinjs/varuint-bitcoin.svg?branch=master&style=flat-square)](https://travis-ci.org/bitcoinjs/varuint-bitcoin)

[![abstract-encoding](https://img.shields.io/badge/abstract--encoding-compliant-brightgreen.svg?style=flat-square)](https://github.com/mafintosh/abstract-encoding)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

encode/decode number as [bitcoin variable length integer](https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer)

| value | storage length (bytes) |
|:------:|:--------------:|
| [0, 0xfd) | 1 |
| [0xfd, 0xffff] | 3 |
| [0x010000, 0xffffffff] | 5 |
| [0x0100000000, 0x1fffffffffffff] | 9 |

## License

MIT

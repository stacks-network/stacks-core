# WIF

[![TRAVIS](https://secure.travis-ci.org/bitcoinjs/wif.png)](http://travis-ci.org/bitcoinjs/wif)
[![NPM](http://img.shields.io/npm/v/wif.svg)](https://www.npmjs.org/package/wif)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

Bitcoin Wallet Import Format encoding/decoding module.


## Example

``` javascript
var wif = require('wif')

var privateKey = new Buffer('0000000000000000000000000000000000000000000000000000000000000001', 'hex')

var key = wif.encode(128, privateKey, true)
// => KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn

var obj = wif.decode(key)
// => {
//	version: 128,
//	privateKey: <Buffer 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01>,
//	compressed: true
//}

wif.encode(obj)
// => KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn
```

## LICENSE [MIT](LICENSE)

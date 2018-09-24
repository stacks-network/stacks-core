# merkle-lib

[![Build Status](https://travis-ci.org/bitcoinjs/merkle-lib.png?branch=master)](https://travis-ci.org/bitcoinjs/merkle-lib)
[![NPM](https://img.shields.io/npm/v/merkle-lib.svg)](https://www.npmjs.org/package/merkle-lib)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

A performance conscious library for merkle root and tree calculations.

**NOTE**: As is,  this implementation is vulnerable to a forgery attack ([as a second pre-image attack](https://en.wikipedia.org/wiki/Merkle_tree#Second_preimage_attack)), see these[\[1\]](https://crypto.stackexchange.com/questions/2106/what-is-the-purpose-of-using-different-hash-functions-for-the-leaves-and-interna)[\[2\]](https://crypto.stackexchange.com/questions/43430/what-is-the-reason-to-separate-domains-in-the-internal-hash-algorithm-of-a-merkl) crypto.stackexchange questions for an explanation.
To avoid this vulnerability,  you should pre-hash your leaves *using a different hash function* than the function provided such that `H(x) != H'(x)`.


## Examples
Preamble
``` javscript
var crypto = require('crypto')

function sha256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}

var data = [
  'cafebeef',
  'ffffffff',
  'aaaaaaaa',
  'bbbbbbbb',
  'cccccccc'
].map(x => new Buffer(x, 'hex'))

// ... now, the examples
```

Tree
``` javascript
var merkle = require('merkle-lib')
var tree = merkle(data, sha256)

console.log(tree.map(x => x.toString('hex')))
// => [
//  'cafebeef',
//  'ffffffff',
//  'aaaaaaaa',
//  'bbbbbbbb',
//  'cccccccc',
//  'bda5c39dec343da54ce91c57bf8e796c2ca16a1bd8cae6a2cefbdd16efc32578',
//  '8b722baf6775a313f1032ba9984c0dce32ff3c40d7a67b5df8de4dbaa43a3db0',
//  '3d2f424783df5853c8d7121b1371650c04241f318e1b0cd46bedbc805b9164c3',
//  'bb232963fd0efdeacb0fd76e26cf69055fa5facc19a5f5c2f2f27a6925d1db2f',
//  '2256e70bea2c591190a0d4d6c1415acd7458fae84d8d85cdc68b851da27777d4',
//  'c2692b0e127b3b774a92f6e1d8ff8c3a5ea9eef9a1d389fe294f0a7a2fec9be1'
//]
```

Root only (equivalent to `tree[tree.length - 1]`)
``` javascript
var fastRoot = require('merkle-lib/fastRoot')
var root = fastRoot(data, sha256)

console.log(root.toString('hex'))
// => 'c2692b0e127b3b774a92f6e1d8ff8c3a5ea9eef9a1d389fe294f0a7a2fec9be1'
```

Proof (with verify)
``` javascript
var merkleProof = require('merkle-lib/proof')
var proof = merkleProof(tree, data[0])

if (proof === null) {
  console.error('No proof exists!')
}

console.log(proof.map(x => x && x.toString('hex')))
// => [
//   'cafebeef',
//   'ffffffff',
//   null,
//   '8b722baf6775a313f1032ba9984c0dce32ff3c40d7a67b5df8de4dbaa43a3db0',
//   null,
//   '2256e70bea2c591190a0d4d6c1415acd7458fae84d8d85cdc68b851da27777d4',
//   'c2692b0e127b3b774a92f6e1d8ff8c3a5ea9eef9a1d389fe294f0a7a2fec9be1'
// ]

console.log(merkleProof.verify(proof, sha256))
// => true
```


#### Credits
Thanks to [Meni Rosenfield on bitcointalk](https://bitcointalk.org/index.php?topic=403231.msg9054025#msg9054025) for the math.

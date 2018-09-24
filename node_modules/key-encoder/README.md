# Key Encoder JS

[![CircleCI](https://img.shields.io/circleci/project/blockstack/key-encoder-js.svg)](https://circleci.com/gh/blockstack/key-encoder-js)
[![npm](https://img.shields.io/npm/l/key-encoder.svg)](https://www.npmjs.com/package/key-encoder)
[![Slack](http://slack.blockstack.org/badge.svg)](http://slack.blockstack.org/)

[![](https://nodei.co/npm/key-encoder.png?downloads=true)](https://www.npmjs.com/package/key-encoder)

### Installation

```
$ npm install key-encoder
```

### Getting Started

To get started, first define your key encoder and raw private/public keys.

#### SECP256k1 Key Encoders

```js
var KeyEncoder = require('key-encoder'),
    keyEncoder = new KeyEncoder('secp256k1')
```

As shown above, there is built in support for SECP256k1 (the curve Bitcoin uses), but you can pass in your own curve parameters for any curve you'd like.

#### Key Encoders w/ Custom Curves

```js
var EC = require('elliptic').ec
var encoderOptions = {
    curveParameters: [1, 3, 132, 0, 10],
    privatePEMOptions: {label: 'EC PRIVATE KEY'},
    publicPEMOptions: {label: 'PUBLIC KEY'},
    curve: new EC('secp256k1')
}
var keyEncoder = new KeyEncoder(encoderOptions)
```

#### Declaring Raw Keys

```js
var rawPrivateKey = '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
    rawPublicKey = '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75'
```

### Encoding Private Keys

Encode to and from raw, PEM, and DER formats.

#### Encoding Private Keys as PEMs

```js
var pemPrivateKey = keyEncoder.encodePrivate(rawPrivateKey, 'raw', 'pem')
```

Example output:

```
-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK
oUQDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL+ytxPv/Q9QIye5I4YVgb1VNe
6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==
-----END EC PRIVATE KEY-----
```

#### Encoding Private Keys to DER Format

```js
var derPrivateKey = keyEncoder.encodePrivate(rawPrivateKey, 'raw', 'der')
```

Example output:

```
30740201010420844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5ba00706052b8104000aa14403420004147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75
```

### Encoding Public Keys

Encode to and from raw, PEM, and DER formats.

#### Encoding Public Keys as PEMs

```js
var pemPublicKey = keyEncoder.encodePublic(rawPublicKey, 'raw', 'pem')
```

Example output:

```
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL
+ytxPv/Q9QIye5I4YVgb1VNe6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==
-----END PUBLIC KEY-----
```

#### Encoding Public Keys to DER Format

```js
var derPublicKey = keyEncoder.encodePublic(rawPublicKey, 'raw', 'der')
```

Example output:

```
3056301006072a8648ce3d020106052b8104000a03420004147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75
```

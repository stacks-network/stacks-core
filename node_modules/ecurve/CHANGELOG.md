1.0.5 / 2016-12-22
------------------
- mod optimization [#29]


1.0.4 / 2016-10-19
------------------
- mod optimization [#28]

1.0.3 / 2016-06-08
------------------
- removed testling
- JavaScript Standard Style
- fixed for Webpack

1.0.2 / 2015-08-27
------------------
- add license field
- small cleanup in Point: https://github.com/cryptocoinjs/ecurve/pull/24

1.0.1 / 2015-02-02
------------------
- bugfix using bytelength in Point (https://github.com/cryptocoinjs/ecurve/commit/dd66233dac444e48ba937f1e7a91e568a67a442c)

1.0.0 / 2014-06-25
------------------
* removed curve `secp224r1` because we're using curve specific optimizations for other curves see [#21](https://github.com/cryptocoinjs/ecurve/issues/21)

0.10.0 / 2014-06-25
-------------------
* moved curves to json [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/18)
* added jshint [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/20)
* added NIST test vectors [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/commit/a35b1e210e6da46f8823e4044c8862fa58c078d0)
* added pointFromX() on `Curve` instance [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/commit/91296c13bb1283480335264677458281f8d2a7df)

0.9.0 / 2014-06-12
------------------
* broke compatibility, simplified fields on `Curve` class. [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/17)

0.8.0 / 2014-06-10
------------------
* broke compatiblity, removed `Point` class from `Curve`. [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/16)

no longer works:

```js
var Curve = require('ecurve').Curve
var Point = Curve.Point
```

better way:

```js
var Curve = requre('ecurve').Curve
var Point = require('ecurve').Point
```


0.7.0 / 2014-06-10
------------------
* major clean up by [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/9)
* removed semicolons as per http://cryptocoinjs.com/about/contributing/
* removed `terst` and replaced with Node.js `assert` as per http://cryptocoinjs.com/about/contributing/
* more clean up by [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/10)
* `ECCurveFp` field `q` renamed to `p` / [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/10)
* `ecparams` field `g` renamed to `G` / [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/10)
* `ECFieldElementFp` shown unnecessary (deleted) / [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/11)
* Chopped of all namespacing for function/class names. / [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/13)
* Fixed validation and added method `isOnCurve()` / [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/12)
* added methods `fromAffine()`, added properties `affineX` and `affineY` to `Point`. This is because
`Point` internally stores coordinates as Jacobian. [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/14)
* Renamed `getECParams()` to `getCurveByName()` [Daniel Cousens](https://github.com/cryptocoinjs/ecurve/pull/15)

0.6.0 / 2014-05-31
------------------
* broke compability to make module exporting more logical, so had to bump minor version.

0.5.0 / 2014-05-31
------------------
* added http://ci.testling.com support
* changed `ECPointFP.decodeFrom()` to accept `Buffer` instead of `Array`. Thanks BitcoinJS devs / [Daniel Cousens](https://github.com/dcousens) :)
* changed `ECPointFP.prototype.getEncoded()` to return a `Buffer` instead of an `Array`
* added `compressed` property to instances of `ECPointFp`, set to `true` by default
* `ECCurveFp.prototype.decodePointHex` removed. This change brings additonal clarity and removes untested (unused)
portions of `decodePointHex`.

Old way:

```js
var G = curve.decodePointHex("04"
      + "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"
      + "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
```

New way:

```js
var x = BigInteger.fromHex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")
var y = BigInteger.fromHex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
var G = new ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y));
```

* deleted file `util.js` which contained `integerToBytes(bigInt, sizeInBytes)`, new
way: `[].slice.call(bigInt.toBuffer(sizeInBytes))`
* removed unused methods: `ECPointFp.prototype.add2D`, `ECPointFp.prototype.twice2D`, and `ECPointFp.prototype.multiply2D`
* renamed `getCurve()` to `getECParams()` to alleviate confusion:

New way:

```js
var ecurve = require('ecurve')
var ecparams = ecurve.getECParams('secp256k1')
```

* renamed result `ecparams` [names.js] object methods `getN()`, `getH()`, `getG()`, and `getCurve()` to properties `n`, `h`, `g`, `curve`. This isn't
Java. JavaScript has excellent property support through `Object.defineProperty`.
* renamed `ECCurveFp` methods `getQ()`, `getA()`, and `getB()` to properties. See justfication in previous change.

0.4.0 / 2014-05-29
------------------
* moved module `ecurve-names` into this module
* moved docs to cryptocoinjs.com
* moved `ECFieldElementFp` to `field-element.js`
* moved `ECPointFp` to `point.js`
* moved `ECCurveFp` to `curve.js`
* upgraded `bigi@0.2.x` to `bigi@^1.1.0`
* added travis-ci and coveralls support

0.3.2 / 2014-04-14
------------------
* bugfix: `decodeFrom` works with compressed keys, #8

0.3.1 / 2014-03-13
------------------
* bug fix: `ECPointFp.decodeFrom` was incorrectly moved to `ECPointFp.prototype`

0.3.0 / 2014-03-05
------------------
* Fixed point export format to adhere to SEC guidelines (Bug #2)
* Removed AMD/Component support
* added browser test

0.2.0 / 2013-12-08
------------------
* changed dep to `bigi`

0.1.0 / 2013-11-20
------------------
* changed package name
* removed AMD support

0.0.1 / 2013-11-06
------------------
* initial release

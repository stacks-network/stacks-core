Unreleased
----------

1.4.2 / 2016-07-26
------------------
### Fixes
- [#25] `modInverse` should return positive

1.4.1 / 2015-08-26
-------------------
- bugfix: throw if `modInverse` with zero. https://github.com/cryptocoinjs/bigi/pull/21

1.4.0 / 2014-11-20
------------------
- added `jshint.json` and `benchmark/` to `.npmignore`
- added `isProbablePrime()` https://github.com/cryptocoinjs/bigi/pull/16

1.3.0 / 2014-08-27
------------------
* added method `byteLength()`, #13

1.2.1 / 2014-07-03
-----------------
* added duck-typed BigInteger.isBigInteger(), #12

1.2.0 / 2014-06-10
------------------
* removed semicolons, cleanup, added basic tests, jshint [Daniel Cousens](https://github.com/cryptocoinjs/bigi/pull/9)
* added TravisCI
* added Coveralls
* added Testling

1.1.0 / 2014-05-13
-------------------
* extend test data and include DER integers
* fix *ByteArrayUnsigned implementation
* add tests for *ByteArrayUnsigned
* rename toByteArraySigned -> toDERInteger
* rework toBuffer/toHex for performance

1.0.0 / 2014-04-28
------------------
* added methods `toBuffer()`, `fromBuffer()`, `toHex()`, `fromHex()`, #1
* removed `bower.json` and `component.json` support
* http://cryptocoinjs.com/modules/misc/bigi/
* renamed test file

0.2.0 / 2013-12-07
------------------
* renamed from `cryptocoin-bigint` to `bigi`

0.1.0 / 2013-11-20
------------------
* removed AMD support

0.0.1 / 2013-11-03
------------------
* initial release

[#26]: https://github.com/cryptocoinjs/bigi/pull/26      "bigi: modInverse() should return positive number [bug]"
[#25]: https://github.com/cryptocoinjs/bigi/issues/25    "bnModInverse() sometimes returns negative numbers; it shouldn't [bug]"
[#24]: https://github.com/cryptocoinjs/bigi/issues/24    "bigi flow definitions"
[#23]: https://github.com/cryptocoinjs/bigi/issues/23    "new BigInteger(1) fails [bug]"
[#22]: https://github.com/cryptocoinjs/bigi/issues/22    "Passing a Buffer into BigInteger Constructor? [question]"
[#21]: https://github.com/cryptocoinjs/bigi/pull/21      "throw if attempt modInverse with 0 [bug]"
[#20]: https://github.com/cryptocoinjs/bigi/issues/20    "Need isBigInteger [question]"
[#19]: https://github.com/cryptocoinjs/bigi/issues/19    "How does one create a BigInteger from an integer?"
[#18]: https://github.com/cryptocoinjs/bigi/issues/18    "Accept Intergers in the constuctor"
[#17]: https://github.com/cryptocoinjs/bigi/issues/17    "Missing byteCount function"
[#16]: https://github.com/cryptocoinjs/bigi/pull/16      "Add `isProbablePrime` method"
[#15]: https://github.com/cryptocoinjs/bigi/issues/15    "toByteArrayUnsigned() gives signed output"
[#14]: https://github.com/cryptocoinjs/bigi/pull/14      "Remove unused assert"
[#13]: https://github.com/cryptocoinjs/bigi/pull/13      "Add `byteLength` method"
[#12]: https://github.com/cryptocoinjs/bigi/pull/12      "Added isBigInteger static method"
[#11]: https://github.com/cryptocoinjs/bigi/pull/11      "benchmark: adds performance testing suite"
[#10]: https://github.com/cryptocoinjs/bigi/issues/10    "investigate this.array technique to improve performance"
[#9]: https://github.com/cryptocoinjs/bigi/pull/9        "Cleanup and basic tests"
[#8]: https://github.com/cryptocoinjs/bigi/pull/8        "Fix toDERInteger documentation"
[#7]: https://github.com/cryptocoinjs/bigi/pull/7        "Convert cleanup and DER fixes"
[#6]: https://github.com/cryptocoinjs/bigi/issues/6      "Remove commit with unneeded comments and code"
[#5]: https://github.com/cryptocoinjs/bigi/issues/5      "Refactor methods into separate files"
[#4]: https://github.com/cryptocoinjs/bigi/issues/4      "Add tests for methods"
[#3]: https://github.com/cryptocoinjs/bigi/issues/3      "Document Methods"
[#2]: https://github.com/cryptocoinjs/bigi/issues/2      "Look Into Internal Optimizations"
[#1]: https://github.com/cryptocoinjs/bigi/pull/1        "To/from buffer/hex"

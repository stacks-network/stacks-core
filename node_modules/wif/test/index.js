var wif = require('../')
var fixtures = require('./fixtures')
var tape = require('tape')

fixtures.valid.forEach(function (f) {
  tape('encode/encodeRaw returns ' + f.WIF + ' for ' + f.privateKeyHex.slice(0, 20) + '... (' + f.version + ')', function (t) {
    t.plan(1)

    var privateKey = new Buffer(f.privateKeyHex, 'hex')
    var actual = wif.encode(f.version, privateKey, f.compressed)
    t.equal(actual, f.WIF)
  })
})

fixtures.valid.forEach(function (f) {
  tape('decode/decodeRaw returns ' + f.privateKeyHex.slice(0, 20) + '... (' + f.version + ')' + ' for ' + f.WIF, function (t) {
    t.plan(3)

    var actual = wif.decode(f.WIF, f.version)
    t.equal(actual.version, f.version)
    t.equal(actual.privateKey.toString('hex'), f.privateKeyHex)
    t.equal(actual.compressed, f.compressed)
  })
})

fixtures.invalid.decode.forEach(function (f) {
  tape('throws ' + f.exception + ' for ' + f.WIF, function (t) {
    t.plan(1)
    t.throws(function () {
      wif.decode(f.WIF, f.version)
    }, new RegExp(f.exception))
  })
})

fixtures.valid.forEach(function (f) {
  tape('decode/encode for ' + f.WIF, function (t) {
    t.plan(1)

    var actual = wif.encode(wif.decode(f.WIF, f.version))
    t.equal(actual, f.WIF)
  })
})

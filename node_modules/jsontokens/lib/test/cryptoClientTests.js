'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

exports.runSECP256k1Tests = runSECP256k1Tests;

var _tape = require('tape');

var _tape2 = _interopRequireDefault(_tape);

var _index = require('../index');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function runSECP256k1Tests() {
  var privateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f';
  var privateKey2 = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f01';
  var privateKey3 = '494651c7602fa047590386dbf48ad47ecd2a25ae4f0f39334e57f5bc62771f';
  var publicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479';
  var publicKey3 = '02ccaa8fb748f1b1d260178092b8eb96be96097fb437a247ed03dbaf13fa5a5a35';
  var uncompresedPublicKey = '04fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea535847946393f8145252eea68afe67e287b3ed9b31685ba6c3b00060a73b9b1242d68f7';

  (0, _tape2.default)('derivePublicKey', function (t) {
    t.plan(8);

    var derivedPublicKey = _index.SECP256K1Client.derivePublicKey(privateKey);
    t.ok(derivedPublicKey, 'compressed public key should have been derived');
    t.equal(derivedPublicKey, publicKey, 'derived compressed public key should match the reference value');

    var derivedPublicKey2 = _index.SECP256K1Client.derivePublicKey(privateKey2);
    t.ok(derivedPublicKey2, 'compressed public key should have been derived');
    t.equal(derivedPublicKey2, publicKey, 'derived compressed public key should match the reference value');

    var derivedPublicKey3 = _index.SECP256K1Client.derivePublicKey(privateKey3);
    t.ok(derivedPublicKey3, 'compressed public key should have been derived');
    t.equal(derivedPublicKey3, publicKey3, 'derived compressed public key should match the reference value');

    var derivedUncompressedPublicKey = _index.SECP256K1Client.derivePublicKey(privateKey, false);
    t.ok(derivedUncompressedPublicKey, 'uncompressed public key should have been derived');
    t.equal(derivedUncompressedPublicKey, uncompresedPublicKey, 'derived uncompressed public key should match the reference');
  });

  (0, _tape2.default)('createHash + signHash', function (t) {
    t.plan(3);

    var message = "Hello, world!";
    var referenceSignature = "3046022100997b6210d959e67ad9cee01589d01daf0fe77ce0f002d040d769171c33504860022100e35a03d2354074d7e49d0499568e331be39af901a543d1731ea1ff8f423f21ab";

    var hash = _index.SECP256K1Client.createHash(message);
    var signature = _index.SECP256K1Client.signHash(hash, privateKey, 'der');

    t.ok(signature, 'signature should have been created');
    t.equal(typeof signature === 'undefined' ? 'undefined' : _typeof(signature), 'string', 'signature should be a string');
    t.equal(signature, referenceSignature, 'signature should match reference value');
  });
}
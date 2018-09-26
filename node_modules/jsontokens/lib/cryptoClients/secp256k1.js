'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.SECP256K1Client = undefined;

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _elliptic = require('elliptic');

var _crypto = require('crypto');

var _keyEncoder = require('key-encoder');

var _keyEncoder2 = _interopRequireDefault(_keyEncoder);

var _validator = require('validator');

var _ecdsaSigFormatter = require('./ecdsaSigFormatter');

var _errors = require('../errors');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var SECP256K1Client = exports.SECP256K1Client = function () {
  function SECP256K1Client() {
    _classCallCheck(this, SECP256K1Client);
  }

  _createClass(SECP256K1Client, null, [{
    key: 'createHash',
    value: function createHash(signingInput) {
      return (0, _crypto.createHash)('sha256').update(signingInput).digest();
    }
  }, {
    key: 'loadPrivateKey',
    value: function loadPrivateKey(rawPrivateKey) {
      if (rawPrivateKey.length === 66) {
        rawPrivateKey = rawPrivateKey.slice(0, 64);
      }
      return SECP256K1Client.ec.keyFromPrivate(rawPrivateKey);
    }
  }, {
    key: 'loadPublicKey',
    value: function loadPublicKey(rawPublicKey) {
      return SECP256K1Client.ec.keyFromPublic(rawPublicKey, 'hex');
    }
  }, {
    key: 'encodePublicKey',
    value: function encodePublicKey(publicKey, originalFormat, destinationFormat) {
      return SECP256K1Client.keyEncoder.encodePublic(publicKey, originalFormat, destinationFormat);
    }
  }, {
    key: 'derivePublicKey',
    value: function derivePublicKey(privateKey, compressed) {
      if (typeof privateKey !== 'string') {
        throw Error('private key must be a string');
      }
      if (!(0, _validator.isHexadecimal)(privateKey)) {
        throw Error('private key must be a hex string');
      }
      if (privateKey.length == 66) {
        privateKey = privateKey.slice(0, 64);
      } else if (privateKey.length <= 64) {
        // do nothing
      } else {
        throw Error('private key must be 66 characters or less');
      }
      if (compressed === undefined) {
        compressed = true;
      }
      var keypair = SECP256K1Client.ec.keyFromPrivate(privateKey);
      return keypair.getPublic(compressed, 'hex');
    }
  }, {
    key: 'signHash',
    value: function signHash(signingInputHash, rawPrivateKey) {
      var format = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 'jose';

      // make sure the required parameters are provided
      if (!(signingInputHash && rawPrivateKey)) {
        throw new _errors.MissingParametersError('a signing input hash and private key are all required');
      }
      // prepare the private key
      var privateKeyObject = SECP256K1Client.loadPrivateKey(rawPrivateKey);
      // calculate the signature
      var signatureObject = privateKeyObject.sign(signingInputHash);
      var derSignature = new Buffer(signatureObject.toDER());

      if (format === 'der') {
        return derSignature.toString('hex');
      } else if (format === 'jose') {
        // return the JOSE-formatted signature
        return (0, _ecdsaSigFormatter.derToJose)(derSignature, 'ES256');
      } else {
        throw Error('Invalid signature format');
      }
    }
  }, {
    key: 'loadSignature',
    value: function loadSignature(joseSignature) {
      // create and return the DER-formatted signature buffer
      return (0, _ecdsaSigFormatter.joseToDer)(joseSignature, 'ES256');
    }
  }, {
    key: 'verifyHash',
    value: function verifyHash(signingInputHash, derSignatureBuffer, rawPublicKey) {
      // make sure the required parameters are provided
      if (!(signingInputHash && derSignatureBuffer && rawPublicKey)) {
        throw new _errors.MissingParametersError('a signing input hash, der signature, and public key are all required');
      }
      // prepare the public key
      var publicKeyObject = SECP256K1Client.loadPublicKey(rawPublicKey);
      // verify the token
      return publicKeyObject.verify(signingInputHash, derSignatureBuffer);
    }
  }]);

  return SECP256K1Client;
}();

SECP256K1Client.algorithmName = 'ES256K';
SECP256K1Client.ec = new _elliptic.ec('secp256k1');
SECP256K1Client.keyEncoder = new _keyEncoder2.default({
  curveParameters: [1, 3, 132, 0, 10],
  privatePEMOptions: { label: 'EC PRIVATE KEY' },
  publicPEMOptions: { label: 'PUBLIC KEY' },
  curve: SECP256K1Client.ec
});
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.cryptoClients = exports.SECP256K1Client = undefined;

var _secp256k = require('./secp256k1');

var cryptoClients = {
  ES256K: _secp256k.SECP256K1Client
};

exports.SECP256K1Client = _secp256k.SECP256K1Client;
exports.cryptoClients = cryptoClients;
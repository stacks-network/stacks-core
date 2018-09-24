'use strict';

var _index = require('../index');

var hash = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f';
var rawPrivateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f';

console.log('hash:');
console.log(hash);

console.log('raw private key:');
console.log(rawPrivateKey);

var signature = _index.SECP256K1Client.signHash(hash, rawPrivateKey);

console.log('signature:');
console.log(signature);
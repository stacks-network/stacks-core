var KeyEncoder = require('./main'),
    keyEncoder = new KeyEncoder('secp256k1')

var rawPrivateKey = '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
    rawPublicKey = '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75'

var EC = require('elliptic').ec
var encoderOptions = {
    curveParameters: [1, 3, 132, 0, 10],
    privatePEMOptions: {label: 'EC PRIVATE KEY'},
    publicPEMOptions: {label: 'PUBLIC KEY'},
    curve: new EC('secp256k1')
}
var keyEncoder2 = new KeyEncoder(encoderOptions)

var privateKeyPEM = keyEncoder.encodePrivate(rawPrivateKey, 'raw', 'pem')

var publicKeyPEM = keyEncoder.encodePublic(rawPublicKey, 'raw', 'pem')

console.log(privateKeyPEM)
console.log(publicKeyPEM)

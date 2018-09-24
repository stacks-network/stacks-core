var test = require('tape'),
    KeyEncoder = require('./index'),
    ECPrivateKeyASN = KeyEncoder.ECPrivateKeyASN,
    SubjectPublicKeyInfoASN = KeyEncoder.SubjectPublicKeyInfoASN,
    BN = require('bn.js')

var keys = {
    rawPrivate: '844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5b',
    rawPublic: '04147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75',
    pemPrivate: '-----BEGIN EC PRIVATE KEY-----\n' +
    'MHQCAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK\n' +
    'oUQDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL+ytxPv/Q9QIye5I4YVgb1VNe\n' +
    '6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==\n' +
    '-----END EC PRIVATE KEY-----',
    pemCompactPrivate: '-----BEGIN EC PRIVATE KEY-----\n' +
    'MC4CAQEEIIRAVcyhPv14znmkw6TFq6XbDr63rp1WkGwD0zPFZo1boAcGBSuBBAAK\n' +
    '-----END EC PRIVATE KEY-----',
    pemPublic: '-----BEGIN PUBLIC KEY-----\n' +
    'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEFHt56eHdMyTO6hFf9AN7bId8c3dxMUGL\n' +
    '+ytxPv/Q9QIye5I4YVgb1VNe6uAGdlJp9AT19cUiFOlyGwSqfQQKdQ==\n' +
    '-----END PUBLIC KEY-----',
    derPrivate: '30740201010420844055cca13efd78ce79a4c3a4c5aba5db0ebeb7ae9d56906c03d333c5668d5ba00706052b8104000aa14403420004147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75',
    derPublic: '3056301006072a8648ce3d020106052b8104000a03420004147b79e9e1dd3324ceea115ff4037b6c877c73777131418bfb2b713effd0f502327b923861581bd5535eeae006765269f404f5f5c52214e9721b04aa7d040a75'
}

var keyEncoder = new KeyEncoder('secp256k1')

test('encodeECPrivateKeyASN', function(t) {
    t.plan(3)

    var secp256k1Parameters = [1, 3, 132, 0, 10],
        pemOptions =  {label: 'EC PRIVATE KEY'}

    var privateKeyObject = {
        version: new BN(1),
        privateKey: new Buffer(keys.rawPrivate, 'hex'),
        parameters: secp256k1Parameters,
        publicKey: { unused: 0, data: new Buffer(keys.rawPublic, 'hex') }
    }

    var privateKeyPEM = ECPrivateKeyASN.encode(privateKeyObject, 'pem', pemOptions)
    t.equal(privateKeyPEM, keys.pemPrivate, 'encoded PEM private key should match the OpenSSL reference')

    var decodedPrivateKeyObject = ECPrivateKeyASN.decode(privateKeyPEM, 'pem', pemOptions)
    t.equal(JSON.stringify(privateKeyObject), JSON.stringify(decodedPrivateKeyObject), 'encoded-and-decoded private key object should match the original')

    var openSSLPrivateKeyObject = ECPrivateKeyASN.decode(keys.pemPrivate, 'pem', pemOptions)
    t.equal(JSON.stringify(privateKeyObject), JSON.stringify(openSSLPrivateKeyObject), 'private key object should match the one decoded from the OpenSSL PEM')
})

test('encodeSubjectPublicKeyInfoASN', function(t) {
    t.plan(1)

    var secp256k1Parameters = [1, 3, 132, 0, 10],
        pemOptions =  {label: 'PUBLIC KEY'}

    var publicKeyObject = {
        algorithm: {
            id: [1, 2, 840, 10045, 2, 1],
            curve: secp256k1Parameters
        },
        pub: {
            unused: 0,
            data: new Buffer(keys.rawPublic, 'hex')
        }
    }

    var publicKeyPEM = SubjectPublicKeyInfoASN.encode(publicKeyObject, 'pem', pemOptions)
    t.equal(publicKeyPEM, keys.pemPublic, 'encoded PEM public key should match the OpenSSL reference')
})

test('encodeRawPrivateKey', function(t) {
    t.plan(2)

    var privateKeyPEM = keyEncoder.encodePrivate(keys.rawPrivate, 'raw', 'pem')
    t.equal(privateKeyPEM, keys.pemPrivate, 'encoded PEM private key should match the OpenSSL reference')

    var privateKeyDER = keyEncoder.encodePrivate(keys.rawPrivate, 'raw', 'der')
    t.equal(privateKeyDER, keys.derPrivate, 'encoded DER private key should match the OpenSSL reference')
})

test('encodeDERPrivateKey', function(t) {
    t.plan(2)

    var rawPrivateKey = keyEncoder.encodePrivate(keys.derPrivate, 'der', 'raw')
    t.equal(rawPrivateKey, keys.rawPrivate, 'encoded raw private key should match the OpenSSL reference')

    var privateKeyPEM = keyEncoder.encodePrivate(keys.derPrivate, 'der', 'pem')
    t.equal(privateKeyPEM, keys.pemPrivate, 'encoded PEM private key should match the OpenSSL reference')
})

test('encodePEMPrivateKey', function(t) {
    t.plan(2)

    var rawPrivateKey = keyEncoder.encodePrivate(keys.pemPrivate, 'pem', 'raw')
    t.equal(rawPrivateKey, keys.rawPrivate, 'encoded raw private key should match the OpenSSL reference')

    var privateKeyDER = keyEncoder.encodePrivate(keys.pemPrivate, 'pem', 'der')
    t.equal(privateKeyDER, keys.derPrivate, 'encoded DER private key should match the OpenSSL reference')
})

test('encodeRawPublicKey', function(t) {
    t.plan(2)

    var publicKeyPEM = keyEncoder.encodePublic(keys.rawPublic, 'raw', 'pem')
    t.equal(publicKeyPEM, keys.pemPublic, 'encoded PEM public key should match the OpenSSL reference')

    var publicKeyDER = keyEncoder.encodePublic(keys.rawPublic, 'raw', 'der')
    t.equal(publicKeyDER, keys.derPublic, 'encoded DER public key should match the OpenSSL reference')
})

test('encodeDERPublicKey', function(t) {
    t.plan(2)

    var rawPublicKey = keyEncoder.encodePublic(keys.derPublic, 'der', 'raw')
    t.equal(rawPublicKey, keys.rawPublic, 'encoded raw public key should match the OpenSSL reference')

    var publicKeyPEM = keyEncoder.encodePublic(keys.derPublic, 'der', 'pem')
    t.equal(publicKeyPEM, keys.pemPublic, 'encoded PEM public key should match the OpenSSL reference')
})

test('encodePEMPublicKey', function(t) {
    t.plan(2)

    var rawPublicKey = keyEncoder.encodePublic(keys.pemPublic, 'pem', 'raw')
    t.equal(rawPublicKey, keys.rawPublic, 'encoded raw public key should match the OpenSSL reference')

    var publicKeyDER = keyEncoder.encodePublic(keys.pemPublic, 'pem', 'der')
    t.equal(publicKeyDER, keys.derPublic, 'encoded DER public key should match the OpenSSL reference')
})

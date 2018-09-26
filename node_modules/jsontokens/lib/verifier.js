'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});
exports.TokenVerifier = undefined;

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _base64url = require('base64url');

var _base64url2 = _interopRequireDefault(_base64url);

var _cryptoClients = require('./cryptoClients');

var _decode = require('./decode');

var _decode2 = _interopRequireDefault(_decode);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var TokenVerifier = exports.TokenVerifier = function () {
    function TokenVerifier(signingAlgorithm, rawPublicKey) {
        _classCallCheck(this, TokenVerifier);

        if (!(signingAlgorithm && rawPublicKey)) {
            throw new MissingParametersError('a signing algorithm and public key are required');
        }
        if (typeof signingAlgorithm !== 'string') {
            throw 'signing algorithm parameter must be a string';
        }
        signingAlgorithm = signingAlgorithm.toUpperCase();
        if (!_cryptoClients.cryptoClients.hasOwnProperty(signingAlgorithm)) {
            throw 'invalid signing algorithm';
        }
        this.tokenType = 'JWT';
        this.cryptoClient = _cryptoClients.cryptoClients[signingAlgorithm];
        this.rawPublicKey = rawPublicKey;
    }

    _createClass(TokenVerifier, [{
        key: 'verify',
        value: function verify(token) {
            if (typeof token === 'string') {
                return this.verifyCompact(token);
            } else if ((typeof token === 'undefined' ? 'undefined' : _typeof(token)) === 'object') {
                return this.verifyExpanded(token);
            } else {
                return false;
            }
        }
    }, {
        key: 'verifyCompact',
        value: function verifyCompact(token) {
            // decompose the token into parts
            var tokenParts = token.split('.');

            // calculate the signing input hash
            var signingInput = tokenParts[0] + '.' + tokenParts[1];
            var signingInputHash = this.cryptoClient.createHash(signingInput);

            // extract the signature as a DER array
            var derSignatureBuffer = this.cryptoClient.loadSignature(tokenParts[2]);

            // verify the signed hash
            return this.cryptoClient.verifyHash(signingInputHash, derSignatureBuffer, this.rawPublicKey);
        }
    }, {
        key: 'verifyExpanded',
        value: function verifyExpanded(token) {
            var _this = this;

            var signingInput = [token["header"].join('.'), _base64url2.default.encode(token["payload"])].join('.');
            var signingInputHash = this.cryptoClient.createHash(signingInput);

            var verified = true;

            token["signature"].map(function (signature) {
                var derSignatureBuffer = _this.cryptoClient.loadSignature(signature);
                var signatureVerified = _this.cryptoClient.verifyHash(signingInputHash, derSignatureBuffer, _this.rawPublicKey);
                if (!signatureVerified) {
                    verified = false;
                }
            });

            return verified;
        }
    }]);

    return TokenVerifier;
}();
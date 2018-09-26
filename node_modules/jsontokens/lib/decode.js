'use strict';

Object.defineProperty(exports, "__esModule", {
    value: true
});

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

exports.decodeToken = decodeToken;

var _base64url = require('base64url');

var _base64url2 = _interopRequireDefault(_base64url);

var _errors = require('./errors');

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function decodeToken(token) {
    if (typeof token === 'string') {
        // decompose the token into parts
        var tokenParts = token.split('.');
        var header = JSON.parse(_base64url2.default.decode(tokenParts[0]));
        var payload = JSON.parse(_base64url2.default.decode(tokenParts[1]));
        var signature = tokenParts[2];

        // return the token object
        return {
            header: header,
            payload: payload,
            signature: signature
        };
    } else if ((typeof token === 'undefined' ? 'undefined' : _typeof(token)) === 'object') {
        var _payload = token.payload;
        if (token.payload[0] !== '{') {
            _payload = _base64url2.default.decode(_payload);
        }

        var allHeaders = [];
        token.header.map(function (headerValue) {
            var header = JSON.parse(_base64url2.default.decode(headerValue));
            allHeaders.push(header);
        });

        return {
            header: allHeaders,
            payload: JSON.parse(_payload),
            signature: token.signature
        };
    }
}
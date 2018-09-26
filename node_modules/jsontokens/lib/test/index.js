'use strict';

var _cryptoClientTests = require('./cryptoClientTests');

var _mainTests = require('./mainTests');

(0, _mainTests.runMainTests)();
(0, _cryptoClientTests.runSECP256k1Tests)();
'use strict';

var _tapeRun = require('tape-run');

var _tapeRun2 = _interopRequireDefault(_tapeRun);

var _browserify = require('browserify');

var _browserify2 = _interopRequireDefault(_browserify);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

(0, _browserify2.default)('./lib/test/unitTests.js').bundle().pipe((0, _tapeRun2.default)()).on('results', console.log).pipe(process.stdout);

/*import run from 'browserify-test'

run({
  watch: false,
  transform: ['brfs', ['babelify', { presets: 'es2015' }]],
  files: ['./lib/unitTests.js'],
})*/
'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var MissingParametersError = exports.MissingParametersError = function (_Error) {
  _inherits(MissingParametersError, _Error);

  function MissingParametersError(message) {
    _classCallCheck(this, MissingParametersError);

    var _this = _possibleConstructorReturn(this, (MissingParametersError.__proto__ || Object.getPrototypeOf(MissingParametersError)).call(this));

    _this.name = 'MissingParametersError';
    _this.message = message || '';
    return _this;
  }

  return MissingParametersError;
}(Error);

var InvalidTokenError = exports.InvalidTokenError = function (_Error2) {
  _inherits(InvalidTokenError, _Error2);

  function InvalidTokenError(message) {
    _classCallCheck(this, InvalidTokenError);

    var _this2 = _possibleConstructorReturn(this, (InvalidTokenError.__proto__ || Object.getPrototypeOf(InvalidTokenError)).call(this));

    _this2.name = 'InvalidTokenError';
    _this2.message = message || '';
    return _this2;
  }

  return InvalidTokenError;
}(Error);
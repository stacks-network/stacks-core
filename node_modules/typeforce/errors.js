var native = require('./native')

function getTypeName (fn) {
  return fn.name || fn.toString().match(/function (.*?)\s*\(/)[1]
}

function getValueTypeName (value) {
  return native.Nil(value) ? '' : getTypeName(value.constructor)
}

function getValue (value) {
  if (native.Function(value)) return ''
  if (native.String(value)) return JSON.stringify(value)
  if (value && native.Object(value)) return ''
  return value
}

function tfJSON (type) {
  if (native.Function(type)) return type.toJSON ? type.toJSON() : getTypeName(type)
  if (native.Array(type)) return 'Array'
  if (type && native.Object(type)) return 'Object'

  return type !== undefined ? type : ''
}

function tfErrorString (type, value, valueTypeName) {
  var valueJson = getValue(value)

  return 'Expected ' + tfJSON(type) + ', got' +
    (valueTypeName !== '' ? ' ' + valueTypeName : '') +
    (valueJson !== '' ? ' ' + valueJson : '')
}

function TfTypeError (type, value, valueTypeName) {
  valueTypeName = valueTypeName || getValueTypeName(value)
  this.message = tfErrorString(type, value, valueTypeName)

  Error.captureStackTrace(this, TfTypeError)
  this.__type = type
  this.__value = value
  this.__valueTypeName = valueTypeName
}

TfTypeError.prototype = Object.create(Error.prototype)
TfTypeError.prototype.constructor = TfTypeError

function tfPropertyErrorString (type, label, name, value, valueTypeName) {
  var description = '" of type '
  if (label === 'key') description = '" with key type '

  return tfErrorString('property "' + tfJSON(name) + description + tfJSON(type), value, valueTypeName)
}

function TfPropertyTypeError (type, property, label, value, valueTypeName) {
  if (type) {
    valueTypeName = valueTypeName || getValueTypeName(value)
    this.message = tfPropertyErrorString(type, label, property, value, valueTypeName)
  } else {
    this.message = 'Unexpected property "' + property + '"'
  }

  Error.captureStackTrace(this, TfTypeError)
  this.__label = label
  this.__property = property
  this.__type = type
  this.__value = value
  this.__valueTypeName = valueTypeName
}

TfPropertyTypeError.prototype = Object.create(Error.prototype)
TfPropertyTypeError.prototype.constructor = TfTypeError

function tfCustomError (expected, actual) {
  return new TfTypeError(expected, {}, actual)
}

function tfSubError (e, property, label) {
  // sub child?
  if (e instanceof TfPropertyTypeError) {
    property = property + '.' + e.__property

    e = new TfPropertyTypeError(
      e.__type, property, e.__label, e.__value, e.__valueTypeName
    )

  // child?
  } else if (e instanceof TfTypeError) {
    e = new TfPropertyTypeError(
      e.__type, property, label, e.__value, e.__valueTypeName
    )
  }

  Error.captureStackTrace(e)
  return e
}

module.exports = {
  TfTypeError: TfTypeError,
  TfPropertyTypeError: TfPropertyTypeError,
  tfCustomError: tfCustomError,
  tfSubError: tfSubError,
  tfJSON: tfJSON,
  getValueTypeName: getValueTypeName
}

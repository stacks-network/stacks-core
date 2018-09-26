// returns an array of hashes of length: values.length / 2 + (values.length % 2)
function _derive (values, digestFn) {
  var length = values.length
  var results = []

  for (var i = 0; i < length; i += 2) {
    var left = values[i]
    var right = i + 1 === length ? left : values[i + 1]
    var data = Buffer.concat([left, right])

    results.push(digestFn(data))
  }

  return results
}

// returns the merkle tree
function merkle (values, digestFn) {
  if (!Array.isArray(values)) throw TypeError('Expected values Array')
  if (typeof digestFn !== 'function') throw TypeError('Expected digest Function')
  if (values.length === 1) return values.concat()

  var levels = [values]
  var level = values

  do {
    level = _derive(level, digestFn)
    levels.push(level)
  } while (level.length > 1)

  return [].concat.apply([], levels)
}

module.exports = merkle

// constant-space merkle root calculation algorithm
module.exports = function fastRoot (values, digestFn) {
  if (!Array.isArray(values)) throw TypeError('Expected values Array')
  if (typeof digestFn !== 'function') throw TypeError('Expected digest Function')

  var length = values.length
  var results = values.concat()

  while (length > 1) {
    var j = 0

    for (var i = 0; i < length; i += 2, ++j) {
      var left = results[i]
      var right = i + 1 === length ? left : results[i + 1]
      var data = Buffer.concat([left, right])

      results[j] = digestFn(data)
    }

    length = j
  }

  return results[0]
}

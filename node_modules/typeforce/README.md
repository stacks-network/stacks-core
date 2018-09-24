# typeforce
[![build status](https://secure.travis-ci.org/dcousens/typeforce.png)](http://travis-ci.org/dcousens/typeforce)
[![Version](https://img.shields.io/npm/v/typeforce.svg)](https://www.npmjs.org/package/typeforce)

Another biased type checking solution for Javascript.

Exception messages may change between patch versions,  as often the patch will change some behaviour that was unexpected and naturally it results in a different error message.

## Examples

``` javascript
var typeforce = require('typeforce')

var element = { prop: 'foo' }
var elementNumber = { prop: 2 }
var array = [element, element, elementNumber]

// supported primitives 'Array', 'Boolean', 'Buffer', 'Number', 'Object', 'String'
typeforce('Array', array)

typeforce('Number', array)
// TypeError: Expected Number, got Array

// array types
typeforce(['Object'], array)
typeforce(typeforce.arrayOf('Object'), array)

// supports recursive type templating
typeforce({ prop: 'Number' }, elementNumber)

// maybe types
typeforce('?Number', 2)
typeforce('?Number', null)
typeforce(typeforce.maybe(typeforce.Number), 2)
typeforce(typeforce.maybe(typeforce.Number), null)

// sum types
typeforce(typeforce.oneOf('String', 'Number'))

// value types
typeforce(typeforce.value(3.14), 3.14)

// custom types
function LongString (value, strict) {
  if (!typeforce.String(value)) return false
  if (value.length !== 32) return false
  return true
}

typeforce(LongString, '00000000000000000000000000000000')
// => OK!

typeforce(LongString, 'not long enough')
// TypeError: Expected LongString, got String 'not long enough'
```

**Pro**tips:
``` javascript
// use precompiled primitives for high performance
typeforce(typeforce.Array, array)

// or just precompile a template
var type = {
  foo: 'Number',
  bar: '?String'
}

var fastType = typeforce.compile(type)
// fastType => typeforce.object({
//   foo: typeforce.Number,
//   bar: typeforce.maybe(typeforce.String)
// })

// use strictness for recursive types to enforce whitelisting properties
typeforce({
  x: 'Number'
}, { x: 1 }, true)
// OK!

typeforce({
  x: 'Number'
}, { x: 1, y: 2 }, true)
// TypeError: Unexpected property 'y' of type Number
```

**Pro**tips (extended types):
``` javascript
typeforce(typeforce.tuple('String', 'Number'), ['foo', 1])
// OK!

typeforce(typeforce.tuple('Number', 'Number'), ['not a number', 1])
// TypeError: Expected property "0" of type Number, got String 'not a number'

typeforce(typeforce.map('Number'), {
  'anyKeyIsOK': 1
})
// OK!

typeforce(typeforce.map('Number', typeforce.HexN(8)), {
  'deadbeef': 1,
  'ffff0000': 2
})
// OK!

function Foo () {
  this.x = 2
}

typeforce(typeforce.quacksLike('Foo'), new Foo())
// OK!

// Note, any Foo will do
typeforce(typeforce.quacksLike('Foo'), new (function Foo() {}))
// OK!
```

**WARNING**: Be very wary of using the `quacksLike` type, as it relies on the `Foo.name` property.
If that property is mangled by a transpiler,  such as `uglifyjs`,  you will have a bad time.

## LICENSE [ISC](LICENSE)

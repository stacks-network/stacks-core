import BigIntPolyfill from 'big-integer';

if (typeof BigInt === 'undefined') {
  (global as any).BigInt = BigIntPolyfill;
}

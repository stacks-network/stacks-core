import type {
  TypedAbiArg,
  TypedAbiFunction,
  TypedAbiMap,
  TypedAbiVariable,
  Response,
} from '@clarigen/core';

export const contracts = {
  bns: {
    functions: {
      computeNamePrice: {
        name: 'compute-name-price',
        access: 'private',
        args: [
          { name: 'name', type: { buffer: { length: 48 } } },
          {
            name: 'price-function',
            type: {
              tuple: [
                { name: 'base', type: 'uint128' },
                {
                  name: 'buckets',
                  type: { list: { type: 'uint128', length: 16 } },
                },
                { name: 'coeff', type: 'uint128' },
                { name: 'no-vowel-discount', type: 'uint128' },
                { name: 'nonalpha-discount', type: 'uint128' },
              ],
            },
          },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          name: TypedAbiArg<Uint8Array, 'name'>,
          priceFunction: TypedAbiArg<
            {
              base: number | bigint;
              buckets: number | bigint[];
              coeff: number | bigint;
              noVowelDiscount: number | bigint;
              nonalphaDiscount: number | bigint;
            },
            'priceFunction'
          >,
        ],
        bigint
      >,
      getExpAtIndex: {
        name: 'get-exp-at-index',
        access: 'private',
        args: [
          { name: 'buckets', type: { list: { type: 'uint128', length: 16 } } },
          { name: 'index', type: 'uint128' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          buckets: TypedAbiArg<number | bigint[], 'buckets'>,
          index: TypedAbiArg<number | bigint, 'index'>,
        ],
        bigint
      >,
      hasInvalidChars: {
        name: 'has-invalid-chars',
        access: 'private',
        args: [{ name: 'name', type: { buffer: { length: 48 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[name: TypedAbiArg<Uint8Array, 'name'>], boolean>,
      hasNonalphaChars: {
        name: 'has-nonalpha-chars',
        access: 'private',
        args: [{ name: 'name', type: { buffer: { length: 48 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[name: TypedAbiArg<Uint8Array, 'name'>], boolean>,
      hasVowelsChars: {
        name: 'has-vowels-chars',
        access: 'private',
        args: [{ name: 'name', type: { buffer: { length: 48 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[name: TypedAbiArg<Uint8Array, 'name'>], boolean>,
      isCharValid: {
        name: 'is-char-valid',
        access: 'private',
        args: [{ name: 'char', type: { buffer: { length: 1 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[char: TypedAbiArg<Uint8Array, 'char'>], boolean>,
      isDigit: {
        name: 'is-digit',
        access: 'private',
        args: [{ name: 'char', type: { buffer: { length: 1 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[char: TypedAbiArg<Uint8Array, 'char'>], boolean>,
      isLowercaseAlpha: {
        name: 'is-lowercase-alpha',
        access: 'private',
        args: [{ name: 'char', type: { buffer: { length: 1 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[char: TypedAbiArg<Uint8Array, 'char'>], boolean>,
      isNamespaceAvailable: {
        name: 'is-namespace-available',
        access: 'private',
        args: [{ name: 'namespace', type: { buffer: { length: 20 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [namespace: TypedAbiArg<Uint8Array, 'namespace'>],
        boolean
      >,
      isNonalpha: {
        name: 'is-nonalpha',
        access: 'private',
        args: [{ name: 'char', type: { buffer: { length: 1 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[char: TypedAbiArg<Uint8Array, 'char'>], boolean>,
      isSpecialChar: {
        name: 'is-special-char',
        access: 'private',
        args: [{ name: 'char', type: { buffer: { length: 1 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[char: TypedAbiArg<Uint8Array, 'char'>], boolean>,
      isVowel: {
        name: 'is-vowel',
        access: 'private',
        args: [{ name: 'char', type: { buffer: { length: 1 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[char: TypedAbiArg<Uint8Array, 'char'>], boolean>,
      max: {
        name: 'max',
        access: 'private',
        args: [
          { name: 'a', type: 'uint128' },
          { name: 'b', type: 'uint128' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          a: TypedAbiArg<number | bigint, 'a'>,
          b: TypedAbiArg<number | bigint, 'b'>,
        ],
        bigint
      >,
      min: {
        name: 'min',
        access: 'private',
        args: [
          { name: 'a', type: 'uint128' },
          { name: 'b', type: 'uint128' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          a: TypedAbiArg<number | bigint, 'a'>,
          b: TypedAbiArg<number | bigint, 'b'>,
        ],
        bigint
      >,
      mintOrTransferName_q: {
        name: 'mint-or-transfer-name?',
        access: 'private',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
          { name: 'beneficiary', type: 'principal' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
          beneficiary: TypedAbiArg<string, 'beneficiary'>,
        ],
        Response<boolean, bigint>
      >,
      nameLeaseStartedAt_q: {
        name: 'name-lease-started-at?',
        access: 'private',
        args: [
          { name: 'namespace-launched-at', type: { optional: 'uint128' } },
          { name: 'namespace-revealed-at', type: 'uint128' },
          {
            name: 'name-props',
            type: {
              tuple: [
                { name: 'imported-at', type: { optional: 'uint128' } },
                { name: 'registered-at', type: { optional: 'uint128' } },
                { name: 'revoked-at', type: { optional: 'uint128' } },
                { name: 'zonefile-hash', type: { buffer: { length: 20 } } },
              ],
            },
          },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespaceLaunchedAt: TypedAbiArg<
            number | bigint | null,
            'namespaceLaunchedAt'
          >,
          namespaceRevealedAt: TypedAbiArg<
            number | bigint,
            'namespaceRevealedAt'
          >,
          nameProps: TypedAbiArg<
            {
              importedAt: number | bigint | null;
              registeredAt: number | bigint | null;
              revokedAt: number | bigint | null;
              zonefileHash: Uint8Array;
            },
            'nameProps'
          >,
        ],
        Response<bigint, bigint>
      >,
      updateNameOwnership_q: {
        name: 'update-name-ownership?',
        access: 'private',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
          { name: 'from', type: 'principal' },
          { name: 'to', type: 'principal' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
          from: TypedAbiArg<string, 'from'>,
          to: TypedAbiArg<string, 'to'>,
        ],
        Response<boolean, bigint>
      >,
      updateZonefileAndProps: {
        name: 'update-zonefile-and-props',
        access: 'private',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
          { name: 'registered-at', type: { optional: 'uint128' } },
          { name: 'imported-at', type: { optional: 'uint128' } },
          { name: 'revoked-at', type: { optional: 'uint128' } },
          { name: 'zonefile-hash', type: { buffer: { length: 20 } } },
          { name: 'op', type: { 'string-ascii': { length: 16 } } },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
          registeredAt: TypedAbiArg<number | bigint | null, 'registeredAt'>,
          importedAt: TypedAbiArg<number | bigint | null, 'importedAt'>,
          revokedAt: TypedAbiArg<number | bigint | null, 'revokedAt'>,
          zonefileHash: TypedAbiArg<Uint8Array, 'zonefileHash'>,
          op: TypedAbiArg<string, 'op'>,
        ],
        boolean
      >,
      nameImport: {
        name: 'name-import',
        access: 'public',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
          { name: 'beneficiary', type: 'principal' },
          { name: 'zonefile-hash', type: { buffer: { length: 20 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
          beneficiary: TypedAbiArg<string, 'beneficiary'>,
          zonefileHash: TypedAbiArg<Uint8Array, 'zonefileHash'>,
        ],
        Response<boolean, bigint>
      >,
      namePreorder: {
        name: 'name-preorder',
        access: 'public',
        args: [
          { name: 'hashed-salted-fqn', type: { buffer: { length: 20 } } },
          { name: 'stx-to-burn', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          hashedSaltedFqn: TypedAbiArg<Uint8Array, 'hashedSaltedFqn'>,
          stxToBurn: TypedAbiArg<number | bigint, 'stxToBurn'>,
        ],
        Response<bigint, bigint>
      >,
      nameRegister: {
        name: 'name-register',
        access: 'public',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
          { name: 'salt', type: { buffer: { length: 20 } } },
          { name: 'zonefile-hash', type: { buffer: { length: 20 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
          salt: TypedAbiArg<Uint8Array, 'salt'>,
          zonefileHash: TypedAbiArg<Uint8Array, 'zonefileHash'>,
        ],
        Response<boolean, bigint>
      >,
      nameRenewal: {
        name: 'name-renewal',
        access: 'public',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
          { name: 'stx-to-burn', type: 'uint128' },
          { name: 'new-owner', type: { optional: 'principal' } },
          {
            name: 'zonefile-hash',
            type: { optional: { buffer: { length: 20 } } },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
          stxToBurn: TypedAbiArg<number | bigint, 'stxToBurn'>,
          newOwner: TypedAbiArg<string | null, 'newOwner'>,
          zonefileHash: TypedAbiArg<Uint8Array | null, 'zonefileHash'>,
        ],
        Response<boolean, bigint>
      >,
      nameRevoke: {
        name: 'name-revoke',
        access: 'public',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
        ],
        Response<boolean, bigint>
      >,
      nameTransfer: {
        name: 'name-transfer',
        access: 'public',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
          { name: 'new-owner', type: 'principal' },
          {
            name: 'zonefile-hash',
            type: { optional: { buffer: { length: 20 } } },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
          newOwner: TypedAbiArg<string, 'newOwner'>,
          zonefileHash: TypedAbiArg<Uint8Array | null, 'zonefileHash'>,
        ],
        Response<boolean, bigint>
      >,
      nameUpdate: {
        name: 'name-update',
        access: 'public',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
          { name: 'zonefile-hash', type: { buffer: { length: 20 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
          zonefileHash: TypedAbiArg<Uint8Array, 'zonefileHash'>,
        ],
        Response<boolean, bigint>
      >,
      namespacePreorder: {
        name: 'namespace-preorder',
        access: 'public',
        args: [
          { name: 'hashed-salted-namespace', type: { buffer: { length: 20 } } },
          { name: 'stx-to-burn', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          hashedSaltedNamespace: TypedAbiArg<
            Uint8Array,
            'hashedSaltedNamespace'
          >,
          stxToBurn: TypedAbiArg<number | bigint, 'stxToBurn'>,
        ],
        Response<bigint, bigint>
      >,
      namespaceReady: {
        name: 'namespace-ready',
        access: 'public',
        args: [{ name: 'namespace', type: { buffer: { length: 20 } } }],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [namespace: TypedAbiArg<Uint8Array, 'namespace'>],
        Response<boolean, bigint>
      >,
      namespaceReveal: {
        name: 'namespace-reveal',
        access: 'public',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'namespace-salt', type: { buffer: { length: 20 } } },
          { name: 'p-func-base', type: 'uint128' },
          { name: 'p-func-coeff', type: 'uint128' },
          { name: 'p-func-b1', type: 'uint128' },
          { name: 'p-func-b2', type: 'uint128' },
          { name: 'p-func-b3', type: 'uint128' },
          { name: 'p-func-b4', type: 'uint128' },
          { name: 'p-func-b5', type: 'uint128' },
          { name: 'p-func-b6', type: 'uint128' },
          { name: 'p-func-b7', type: 'uint128' },
          { name: 'p-func-b8', type: 'uint128' },
          { name: 'p-func-b9', type: 'uint128' },
          { name: 'p-func-b10', type: 'uint128' },
          { name: 'p-func-b11', type: 'uint128' },
          { name: 'p-func-b12', type: 'uint128' },
          { name: 'p-func-b13', type: 'uint128' },
          { name: 'p-func-b14', type: 'uint128' },
          { name: 'p-func-b15', type: 'uint128' },
          { name: 'p-func-b16', type: 'uint128' },
          { name: 'p-func-non-alpha-discount', type: 'uint128' },
          { name: 'p-func-no-vowel-discount', type: 'uint128' },
          { name: 'lifetime', type: 'uint128' },
          { name: 'namespace-import', type: 'principal' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          namespaceSalt: TypedAbiArg<Uint8Array, 'namespaceSalt'>,
          pFuncBase: TypedAbiArg<number | bigint, 'pFuncBase'>,
          pFuncCoeff: TypedAbiArg<number | bigint, 'pFuncCoeff'>,
          pFuncB1: TypedAbiArg<number | bigint, 'pFuncB1'>,
          pFuncB2: TypedAbiArg<number | bigint, 'pFuncB2'>,
          pFuncB3: TypedAbiArg<number | bigint, 'pFuncB3'>,
          pFuncB4: TypedAbiArg<number | bigint, 'pFuncB4'>,
          pFuncB5: TypedAbiArg<number | bigint, 'pFuncB5'>,
          pFuncB6: TypedAbiArg<number | bigint, 'pFuncB6'>,
          pFuncB7: TypedAbiArg<number | bigint, 'pFuncB7'>,
          pFuncB8: TypedAbiArg<number | bigint, 'pFuncB8'>,
          pFuncB9: TypedAbiArg<number | bigint, 'pFuncB9'>,
          pFuncB10: TypedAbiArg<number | bigint, 'pFuncB10'>,
          pFuncB11: TypedAbiArg<number | bigint, 'pFuncB11'>,
          pFuncB12: TypedAbiArg<number | bigint, 'pFuncB12'>,
          pFuncB13: TypedAbiArg<number | bigint, 'pFuncB13'>,
          pFuncB14: TypedAbiArg<number | bigint, 'pFuncB14'>,
          pFuncB15: TypedAbiArg<number | bigint, 'pFuncB15'>,
          pFuncB16: TypedAbiArg<number | bigint, 'pFuncB16'>,
          pFuncNonAlphaDiscount: TypedAbiArg<
            number | bigint,
            'pFuncNonAlphaDiscount'
          >,
          pFuncNoVowelDiscount: TypedAbiArg<
            number | bigint,
            'pFuncNoVowelDiscount'
          >,
          lifetime: TypedAbiArg<number | bigint, 'lifetime'>,
          namespaceImport: TypedAbiArg<string, 'namespaceImport'>,
        ],
        Response<boolean, bigint>
      >,
      namespaceRevokeFunctionPriceEdition: {
        name: 'namespace-revoke-function-price-edition',
        access: 'public',
        args: [{ name: 'namespace', type: { buffer: { length: 20 } } }],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [namespace: TypedAbiArg<Uint8Array, 'namespace'>],
        Response<boolean, bigint>
      >,
      namespaceUpdateFunctionPrice: {
        name: 'namespace-update-function-price',
        access: 'public',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'p-func-base', type: 'uint128' },
          { name: 'p-func-coeff', type: 'uint128' },
          { name: 'p-func-b1', type: 'uint128' },
          { name: 'p-func-b2', type: 'uint128' },
          { name: 'p-func-b3', type: 'uint128' },
          { name: 'p-func-b4', type: 'uint128' },
          { name: 'p-func-b5', type: 'uint128' },
          { name: 'p-func-b6', type: 'uint128' },
          { name: 'p-func-b7', type: 'uint128' },
          { name: 'p-func-b8', type: 'uint128' },
          { name: 'p-func-b9', type: 'uint128' },
          { name: 'p-func-b10', type: 'uint128' },
          { name: 'p-func-b11', type: 'uint128' },
          { name: 'p-func-b12', type: 'uint128' },
          { name: 'p-func-b13', type: 'uint128' },
          { name: 'p-func-b14', type: 'uint128' },
          { name: 'p-func-b15', type: 'uint128' },
          { name: 'p-func-b16', type: 'uint128' },
          { name: 'p-func-non-alpha-discount', type: 'uint128' },
          { name: 'p-func-no-vowel-discount', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          pFuncBase: TypedAbiArg<number | bigint, 'pFuncBase'>,
          pFuncCoeff: TypedAbiArg<number | bigint, 'pFuncCoeff'>,
          pFuncB1: TypedAbiArg<number | bigint, 'pFuncB1'>,
          pFuncB2: TypedAbiArg<number | bigint, 'pFuncB2'>,
          pFuncB3: TypedAbiArg<number | bigint, 'pFuncB3'>,
          pFuncB4: TypedAbiArg<number | bigint, 'pFuncB4'>,
          pFuncB5: TypedAbiArg<number | bigint, 'pFuncB5'>,
          pFuncB6: TypedAbiArg<number | bigint, 'pFuncB6'>,
          pFuncB7: TypedAbiArg<number | bigint, 'pFuncB7'>,
          pFuncB8: TypedAbiArg<number | bigint, 'pFuncB8'>,
          pFuncB9: TypedAbiArg<number | bigint, 'pFuncB9'>,
          pFuncB10: TypedAbiArg<number | bigint, 'pFuncB10'>,
          pFuncB11: TypedAbiArg<number | bigint, 'pFuncB11'>,
          pFuncB12: TypedAbiArg<number | bigint, 'pFuncB12'>,
          pFuncB13: TypedAbiArg<number | bigint, 'pFuncB13'>,
          pFuncB14: TypedAbiArg<number | bigint, 'pFuncB14'>,
          pFuncB15: TypedAbiArg<number | bigint, 'pFuncB15'>,
          pFuncB16: TypedAbiArg<number | bigint, 'pFuncB16'>,
          pFuncNonAlphaDiscount: TypedAbiArg<
            number | bigint,
            'pFuncNonAlphaDiscount'
          >,
          pFuncNoVowelDiscount: TypedAbiArg<
            number | bigint,
            'pFuncNoVowelDiscount'
          >,
        ],
        Response<boolean, bigint>
      >,
      canNameBeRegistered: {
        name: 'can-name-be-registered',
        access: 'read_only',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
        ],
        Response<boolean, bigint>
      >,
      canNamespaceBeRegistered: {
        name: 'can-namespace-be-registered',
        access: 'read_only',
        args: [{ name: 'namespace', type: { buffer: { length: 20 } } }],
        outputs: { type: { response: { ok: 'bool', error: 'none' } } },
      } as TypedAbiFunction<
        [namespace: TypedAbiArg<Uint8Array, 'namespace'>],
        Response<boolean, null>
      >,
      canReceiveName: {
        name: 'can-receive-name',
        access: 'read_only',
        args: [{ name: 'owner', type: 'principal' }],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [owner: TypedAbiArg<string, 'owner'>],
        Response<boolean, bigint>
      >,
      checkNameOpsPreconditions: {
        name: 'check-name-ops-preconditions',
        access: 'read_only',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  {
                    name: 'name-props',
                    type: {
                      tuple: [
                        { name: 'imported-at', type: { optional: 'uint128' } },
                        {
                          name: 'registered-at',
                          type: { optional: 'uint128' },
                        },
                        { name: 'revoked-at', type: { optional: 'uint128' } },
                        {
                          name: 'zonefile-hash',
                          type: { buffer: { length: 20 } },
                        },
                      ],
                    },
                  },
                  {
                    name: 'namespace-props',
                    type: {
                      tuple: [
                        { name: 'can-update-price-function', type: 'bool' },
                        { name: 'launched-at', type: { optional: 'uint128' } },
                        { name: 'lifetime', type: 'uint128' },
                        { name: 'namespace-import', type: 'principal' },
                        {
                          name: 'price-function',
                          type: {
                            tuple: [
                              { name: 'base', type: 'uint128' },
                              {
                                name: 'buckets',
                                type: { list: { type: 'uint128', length: 16 } },
                              },
                              { name: 'coeff', type: 'uint128' },
                              { name: 'no-vowel-discount', type: 'uint128' },
                              { name: 'nonalpha-discount', type: 'uint128' },
                            ],
                          },
                        },
                        { name: 'revealed-at', type: 'uint128' },
                      ],
                    },
                  },
                  { name: 'owner', type: 'principal' },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
        ],
        Response<
          {
            nameProps: {
              importedAt: bigint | null;
              registeredAt: bigint | null;
              revokedAt: bigint | null;
              zonefileHash: Uint8Array;
            };
            namespaceProps: {
              canUpdatePriceFunction: boolean;
              launchedAt: bigint | null;
              lifetime: bigint;
              namespaceImport: string;
              priceFunction: {
                base: bigint;
                buckets: bigint[];
                coeff: bigint;
                noVowelDiscount: bigint;
                nonalphaDiscount: bigint;
              };
              revealedAt: bigint;
            };
            owner: string;
          },
          bigint
        >
      >,
      getNamePrice: {
        name: 'get-name-price',
        access: 'read_only',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
        ],
        Response<bigint, bigint>
      >,
      getNamespacePrice: {
        name: 'get-namespace-price',
        access: 'read_only',
        args: [{ name: 'namespace', type: { buffer: { length: 20 } } }],
        outputs: { type: { response: { ok: 'uint128', error: 'int128' } } },
      } as TypedAbiFunction<
        [namespace: TypedAbiArg<Uint8Array, 'namespace'>],
        Response<bigint, bigint>
      >,
      getNamespaceProperties: {
        name: 'get-namespace-properties',
        access: 'read_only',
        args: [{ name: 'namespace', type: { buffer: { length: 20 } } }],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'namespace', type: { buffer: { length: 20 } } },
                  {
                    name: 'properties',
                    type: {
                      tuple: [
                        { name: 'can-update-price-function', type: 'bool' },
                        { name: 'launched-at', type: { optional: 'uint128' } },
                        { name: 'lifetime', type: 'uint128' },
                        { name: 'namespace-import', type: 'principal' },
                        {
                          name: 'price-function',
                          type: {
                            tuple: [
                              { name: 'base', type: 'uint128' },
                              {
                                name: 'buckets',
                                type: { list: { type: 'uint128', length: 16 } },
                              },
                              { name: 'coeff', type: 'uint128' },
                              { name: 'no-vowel-discount', type: 'uint128' },
                              { name: 'nonalpha-discount', type: 'uint128' },
                            ],
                          },
                        },
                        { name: 'revealed-at', type: 'uint128' },
                      ],
                    },
                  },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [namespace: TypedAbiArg<Uint8Array, 'namespace'>],
        Response<
          {
            namespace: Uint8Array;
            properties: {
              canUpdatePriceFunction: boolean;
              launchedAt: bigint | null;
              lifetime: bigint;
              namespaceImport: string;
              priceFunction: {
                base: bigint;
                buckets: bigint[];
                coeff: bigint;
                noVowelDiscount: bigint;
                nonalphaDiscount: bigint;
              };
              revealedAt: bigint;
            };
          },
          bigint
        >
      >,
      isNameInGracePeriod: {
        name: 'is-name-in-grace-period',
        access: 'read_only',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
        ],
        Response<boolean, bigint>
      >,
      isNameLeaseExpired: {
        name: 'is-name-lease-expired',
        access: 'read_only',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
        ],
        Response<boolean, bigint>
      >,
      nameResolve: {
        name: 'name-resolve',
        access: 'read_only',
        args: [
          { name: 'namespace', type: { buffer: { length: 20 } } },
          { name: 'name', type: { buffer: { length: 48 } } },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'lease-ending-at', type: { optional: 'uint128' } },
                  { name: 'lease-started-at', type: 'uint128' },
                  { name: 'owner', type: 'principal' },
                  { name: 'zonefile-hash', type: { buffer: { length: 20 } } },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          namespace: TypedAbiArg<Uint8Array, 'namespace'>,
          name: TypedAbiArg<Uint8Array, 'name'>,
        ],
        Response<
          {
            leaseEndingAt: bigint | null;
            leaseStartedAt: bigint;
            owner: string;
            zonefileHash: Uint8Array;
          },
          bigint
        >
      >,
      resolvePrincipal: {
        name: 'resolve-principal',
        access: 'read_only',
        args: [{ name: 'owner', type: 'principal' }],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'name', type: { buffer: { length: 48 } } },
                  { name: 'namespace', type: { buffer: { length: 20 } } },
                ],
              },
              error: {
                tuple: [
                  { name: 'code', type: 'int128' },
                  {
                    name: 'name',
                    type: {
                      optional: {
                        tuple: [
                          { name: 'name', type: { buffer: { length: 48 } } },
                          {
                            name: 'namespace',
                            type: { buffer: { length: 20 } },
                          },
                        ],
                      },
                    },
                  },
                ],
              },
            },
          },
        },
      } as TypedAbiFunction<
        [owner: TypedAbiArg<string, 'owner'>],
        Response<
          {
            name: Uint8Array;
            namespace: Uint8Array;
          },
          {
            code: bigint;
            name: {
              name: Uint8Array;
              namespace: Uint8Array;
            } | null;
          }
        >
      >,
    },
    maps: {
      namePreorders: {
        name: 'name-preorders',
        key: {
          tuple: [
            { name: 'buyer', type: 'principal' },
            { name: 'hashed-salted-fqn', type: { buffer: { length: 20 } } },
          ],
        },
        value: {
          tuple: [
            { name: 'claimed', type: 'bool' },
            { name: 'created-at', type: 'uint128' },
            { name: 'stx-burned', type: 'uint128' },
          ],
        },
      } as TypedAbiMap<
        {
          buyer: string;
          hashedSaltedFqn: Uint8Array;
        },
        {
          claimed: boolean;
          createdAt: bigint;
          stxBurned: bigint;
        }
      >,
      nameProperties: {
        name: 'name-properties',
        key: {
          tuple: [
            { name: 'name', type: { buffer: { length: 48 } } },
            { name: 'namespace', type: { buffer: { length: 20 } } },
          ],
        },
        value: {
          tuple: [
            { name: 'imported-at', type: { optional: 'uint128' } },
            { name: 'registered-at', type: { optional: 'uint128' } },
            { name: 'revoked-at', type: { optional: 'uint128' } },
            { name: 'zonefile-hash', type: { buffer: { length: 20 } } },
          ],
        },
      } as TypedAbiMap<
        {
          name: Uint8Array;
          namespace: Uint8Array;
        },
        {
          importedAt: bigint | null;
          registeredAt: bigint | null;
          revokedAt: bigint | null;
          zonefileHash: Uint8Array;
        }
      >,
      namespacePreorders: {
        name: 'namespace-preorders',
        key: {
          tuple: [
            { name: 'buyer', type: 'principal' },
            {
              name: 'hashed-salted-namespace',
              type: { buffer: { length: 20 } },
            },
          ],
        },
        value: {
          tuple: [
            { name: 'claimed', type: 'bool' },
            { name: 'created-at', type: 'uint128' },
            { name: 'stx-burned', type: 'uint128' },
          ],
        },
      } as TypedAbiMap<
        {
          buyer: string;
          hashedSaltedNamespace: Uint8Array;
        },
        {
          claimed: boolean;
          createdAt: bigint;
          stxBurned: bigint;
        }
      >,
      namespaces: {
        name: 'namespaces',
        key: { buffer: { length: 20 } },
        value: {
          tuple: [
            { name: 'can-update-price-function', type: 'bool' },
            { name: 'launched-at', type: { optional: 'uint128' } },
            { name: 'lifetime', type: 'uint128' },
            { name: 'namespace-import', type: 'principal' },
            {
              name: 'price-function',
              type: {
                tuple: [
                  { name: 'base', type: 'uint128' },
                  {
                    name: 'buckets',
                    type: { list: { type: 'uint128', length: 16 } },
                  },
                  { name: 'coeff', type: 'uint128' },
                  { name: 'no-vowel-discount', type: 'uint128' },
                  { name: 'nonalpha-discount', type: 'uint128' },
                ],
              },
            },
            { name: 'revealed-at', type: 'uint128' },
          ],
        },
      } as TypedAbiMap<
        Uint8Array,
        {
          canUpdatePriceFunction: boolean;
          launchedAt: bigint | null;
          lifetime: bigint;
          namespaceImport: string;
          priceFunction: {
            base: bigint;
            buckets: bigint[];
            coeff: bigint;
            noVowelDiscount: bigint;
            nonalphaDiscount: bigint;
          };
          revealedAt: bigint;
        }
      >,
      ownerName: {
        name: 'owner-name',
        key: 'principal',
        value: {
          tuple: [
            { name: 'name', type: { buffer: { length: 48 } } },
            { name: 'namespace', type: { buffer: { length: 20 } } },
          ],
        },
      } as TypedAbiMap<
        string,
        {
          name: Uint8Array;
          namespace: Uint8Array;
        }
      >,
    },
    variables: {
      ERR_INSUFFICIENT_FUNDS: {
        name: 'ERR_INSUFFICIENT_FUNDS',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_ALREADY_EXISTS: {
        name: 'ERR_NAMESPACE_ALREADY_EXISTS',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_ALREADY_LAUNCHED: {
        name: 'ERR_NAMESPACE_ALREADY_LAUNCHED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_BLANK: {
        name: 'ERR_NAMESPACE_BLANK',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_CHARSET_INVALID: {
        name: 'ERR_NAMESPACE_CHARSET_INVALID',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_HASH_MALFORMED: {
        name: 'ERR_NAMESPACE_HASH_MALFORMED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_NOT_FOUND: {
        name: 'ERR_NAMESPACE_NOT_FOUND',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_NOT_LAUNCHED: {
        name: 'ERR_NAMESPACE_NOT_LAUNCHED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_OPERATION_UNAUTHORIZED: {
        name: 'ERR_NAMESPACE_OPERATION_UNAUTHORIZED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_PREORDER_ALREADY_EXISTS: {
        name: 'ERR_NAMESPACE_PREORDER_ALREADY_EXISTS',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_PREORDER_CLAIMABILITY_EXPIRED: {
        name: 'ERR_NAMESPACE_PREORDER_CLAIMABILITY_EXPIRED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_PREORDER_EXPIRED: {
        name: 'ERR_NAMESPACE_PREORDER_EXPIRED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_PREORDER_LAUNCHABILITY_EXPIRED: {
        name: 'ERR_NAMESPACE_PREORDER_LAUNCHABILITY_EXPIRED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_PREORDER_NOT_FOUND: {
        name: 'ERR_NAMESPACE_PREORDER_NOT_FOUND',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_PRICE_FUNCTION_INVALID: {
        name: 'ERR_NAMESPACE_PRICE_FUNCTION_INVALID',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_STX_BURNT_INSUFFICIENT: {
        name: 'ERR_NAMESPACE_STX_BURNT_INSUFFICIENT',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAMESPACE_UNAVAILABLE: {
        name: 'ERR_NAMESPACE_UNAVAILABLE',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_ALREADY_CLAIMED: {
        name: 'ERR_NAME_ALREADY_CLAIMED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_BLANK: {
        name: 'ERR_NAME_BLANK',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_CHARSET_INVALID: {
        name: 'ERR_NAME_CHARSET_INVALID',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_CLAIMABILITY_EXPIRED: {
        name: 'ERR_NAME_CLAIMABILITY_EXPIRED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_COULD_NOT_BE_MINTED: {
        name: 'ERR_NAME_COULD_NOT_BE_MINTED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_COULD_NOT_BE_TRANSFERED: {
        name: 'ERR_NAME_COULD_NOT_BE_TRANSFERED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_EXPIRED: {
        name: 'ERR_NAME_EXPIRED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_GRACE_PERIOD: {
        name: 'ERR_NAME_GRACE_PERIOD',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_HASH_MALFORMED: {
        name: 'ERR_NAME_HASH_MALFORMED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_NOT_FOUND: {
        name: 'ERR_NAME_NOT_FOUND',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_NOT_RESOLVABLE: {
        name: 'ERR_NAME_NOT_RESOLVABLE',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_OPERATION_UNAUTHORIZED: {
        name: 'ERR_NAME_OPERATION_UNAUTHORIZED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_PREORDERED_BEFORE_NAMESPACE_LAUNCH: {
        name: 'ERR_NAME_PREORDERED_BEFORE_NAMESPACE_LAUNCH',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_PREORDER_ALREADY_EXISTS: {
        name: 'ERR_NAME_PREORDER_ALREADY_EXISTS',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_PREORDER_EXPIRED: {
        name: 'ERR_NAME_PREORDER_EXPIRED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_PREORDER_FUNDS_INSUFFICIENT: {
        name: 'ERR_NAME_PREORDER_FUNDS_INSUFFICIENT',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_PREORDER_NOT_FOUND: {
        name: 'ERR_NAME_PREORDER_NOT_FOUND',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_REVOKED: {
        name: 'ERR_NAME_REVOKED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_STX_BURNT_INSUFFICIENT: {
        name: 'ERR_NAME_STX_BURNT_INSUFFICIENT',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_TRANSFER_FAILED: {
        name: 'ERR_NAME_TRANSFER_FAILED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NAME_UNAVAILABLE: {
        name: 'ERR_NAME_UNAVAILABLE',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_PANIC: {
        name: 'ERR_PANIC',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_PRINCIPAL_ALREADY_ASSOCIATED: {
        name: 'ERR_PRINCIPAL_ALREADY_ASSOCIATED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      NAMESPACE_LAUNCHABILITY_TTL: {
        name: 'NAMESPACE_LAUNCHABILITY_TTL',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      NAMESPACE_PREORDER_CLAIMABILITY_TTL: {
        name: 'NAMESPACE_PREORDER_CLAIMABILITY_TTL',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      NAMESPACE_PRICE_TIERS: {
        name: 'NAMESPACE_PRICE_TIERS',
        type: {
          list: {
            type: 'uint128',
            length: 20,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<bigint[]>,
      NAME_GRACE_PERIOD_DURATION: {
        name: 'NAME_GRACE_PERIOD_DURATION',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      NAME_PREORDER_CLAIMABILITY_TTL: {
        name: 'NAME_PREORDER_CLAIMABILITY_TTL',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      attachmentIndex: {
        name: 'attachment-index',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      ERR_INSUFFICIENT_FUNDS: 4_001n,
      ERR_NAMESPACE_ALREADY_EXISTS: 1_006n,
      ERR_NAMESPACE_ALREADY_LAUNCHED: 1_014n,
      ERR_NAMESPACE_BLANK: 1_013n,
      ERR_NAMESPACE_CHARSET_INVALID: 1_016n,
      ERR_NAMESPACE_HASH_MALFORMED: 1_015n,
      ERR_NAMESPACE_NOT_FOUND: 1_005n,
      ERR_NAMESPACE_NOT_LAUNCHED: 1_007n,
      ERR_NAMESPACE_OPERATION_UNAUTHORIZED: 1_011n,
      ERR_NAMESPACE_PREORDER_ALREADY_EXISTS: 1_003n,
      ERR_NAMESPACE_PREORDER_CLAIMABILITY_EXPIRED: 1_009n,
      ERR_NAMESPACE_PREORDER_EXPIRED: 1_002n,
      ERR_NAMESPACE_PREORDER_LAUNCHABILITY_EXPIRED: 1_010n,
      ERR_NAMESPACE_PREORDER_NOT_FOUND: 1_001n,
      ERR_NAMESPACE_PRICE_FUNCTION_INVALID: 1_008n,
      ERR_NAMESPACE_STX_BURNT_INSUFFICIENT: 1_012n,
      ERR_NAMESPACE_UNAVAILABLE: 1_004n,
      ERR_NAME_ALREADY_CLAIMED: 2_011n,
      ERR_NAME_BLANK: 2_010n,
      ERR_NAME_CHARSET_INVALID: 2_022n,
      ERR_NAME_CLAIMABILITY_EXPIRED: 2_012n,
      ERR_NAME_COULD_NOT_BE_MINTED: 2_020n,
      ERR_NAME_COULD_NOT_BE_TRANSFERED: 2_021n,
      ERR_NAME_EXPIRED: 2_008n,
      ERR_NAME_GRACE_PERIOD: 2_009n,
      ERR_NAME_HASH_MALFORMED: 2_017n,
      ERR_NAME_NOT_FOUND: 2_013n,
      ERR_NAME_NOT_RESOLVABLE: 2_019n,
      ERR_NAME_OPERATION_UNAUTHORIZED: 2_006n,
      ERR_NAME_PREORDERED_BEFORE_NAMESPACE_LAUNCH: 2_018n,
      ERR_NAME_PREORDER_ALREADY_EXISTS: 2_016n,
      ERR_NAME_PREORDER_EXPIRED: 2_002n,
      ERR_NAME_PREORDER_FUNDS_INSUFFICIENT: 2_003n,
      ERR_NAME_PREORDER_NOT_FOUND: 2_001n,
      ERR_NAME_REVOKED: 2_014n,
      ERR_NAME_STX_BURNT_INSUFFICIENT: 2_007n,
      ERR_NAME_TRANSFER_FAILED: 2_015n,
      ERR_NAME_UNAVAILABLE: 2_004n,
      ERR_PANIC: 0n,
      ERR_PRINCIPAL_ALREADY_ASSOCIATED: 3_001n,
      NAMESPACE_LAUNCHABILITY_TTL: 52_595n,
      NAMESPACE_PREORDER_CLAIMABILITY_TTL: 144n,
      NAMESPACE_PRICE_TIERS: [
        640_000_000_000n,
        64_000_000_000n,
        64_000_000_000n,
        6_400_000_000n,
        6_400_000_000n,
        6_400_000_000n,
        6_400_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
        640_000_000n,
      ],
      NAME_GRACE_PERIOD_DURATION: 5_000n,
      NAME_PREORDER_CLAIMABILITY_TTL: 144n,
      attachmentIndex: 0n,
    },
    non_fungible_tokens: [
      {
        name: 'names',
        type: {
          tuple: [
            { name: 'name', type: { buffer: { length: 48 } } },
            { name: 'namespace', type: { buffer: { length: 20 } } },
          ],
        },
      },
    ],
    fungible_tokens: [],
    epoch: 'Epoch24',
    clarity_version: 'Clarity2',
    contractName: 'bns',
  },
  bns_test: {
    functions: {
      testCanReceiveNameNone: {
        name: 'test-can-receive-name-none',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: { ok: 'bool', error: { 'string-ascii': { length: 32 } } },
          },
        },
      } as TypedAbiFunction<[], Response<boolean, string>>,
    },
    maps: {},
    variables: {},
    constants: {},
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch24',
    clarity_version: 'Clarity2',
    contractName: 'bns_test',
  },
  pox4: {
    functions: {
      addPoxAddrToIthRewardCycle: {
        name: 'add-pox-addr-to-ith-reward-cycle',
        access: 'private',
        args: [
          { name: 'cycle-index', type: 'uint128' },
          {
            name: 'params',
            type: {
              tuple: [
                { name: 'amount-ustx', type: 'uint128' },
                { name: 'first-reward-cycle', type: 'uint128' },
                { name: 'i', type: 'uint128' },
                { name: 'num-cycles', type: 'uint128' },
                {
                  name: 'pox-addr',
                  type: {
                    tuple: [
                      { name: 'hashbytes', type: { buffer: { length: 32 } } },
                      { name: 'version', type: { buffer: { length: 1 } } },
                    ],
                  },
                },
                {
                  name: 'reward-set-indexes',
                  type: { list: { type: 'uint128', length: 12 } },
                },
                { name: 'signer', type: { buffer: { length: 33 } } },
                { name: 'stacker', type: { optional: 'principal' } },
              ],
            },
          },
        ],
        outputs: {
          type: {
            tuple: [
              { name: 'amount-ustx', type: 'uint128' },
              { name: 'first-reward-cycle', type: 'uint128' },
              { name: 'i', type: 'uint128' },
              { name: 'num-cycles', type: 'uint128' },
              {
                name: 'pox-addr',
                type: {
                  tuple: [
                    { name: 'hashbytes', type: { buffer: { length: 32 } } },
                    { name: 'version', type: { buffer: { length: 1 } } },
                  ],
                },
              },
              {
                name: 'reward-set-indexes',
                type: { list: { type: 'uint128', length: 12 } },
              },
              { name: 'signer', type: { buffer: { length: 33 } } },
              { name: 'stacker', type: { optional: 'principal' } },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          cycleIndex: TypedAbiArg<number | bigint, 'cycleIndex'>,
          params: TypedAbiArg<
            {
              amountUstx: number | bigint;
              firstRewardCycle: number | bigint;
              i: number | bigint;
              numCycles: number | bigint;
              poxAddr: {
                hashbytes: Uint8Array;
                version: Uint8Array;
              };
              rewardSetIndexes: number | bigint[];
              signer: Uint8Array;
              stacker: string | null;
            },
            'params'
          >,
        ],
        {
          amountUstx: bigint;
          firstRewardCycle: bigint;
          i: bigint;
          numCycles: bigint;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          rewardSetIndexes: bigint[];
          signer: Uint8Array;
          stacker: string | null;
        }
      >,
      addPoxAddrToRewardCycles: {
        name: 'add-pox-addr-to-reward-cycles',
        access: 'private',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'first-reward-cycle', type: 'uint128' },
          { name: 'num-cycles', type: 'uint128' },
          { name: 'amount-ustx', type: 'uint128' },
          { name: 'stacker', type: 'principal' },
          { name: 'signer', type: { buffer: { length: 33 } } },
        ],
        outputs: {
          type: {
            response: {
              ok: { list: { type: 'uint128', length: 12 } },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          firstRewardCycle: TypedAbiArg<number | bigint, 'firstRewardCycle'>,
          numCycles: TypedAbiArg<number | bigint, 'numCycles'>,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          stacker: TypedAbiArg<string, 'stacker'>,
          signer: TypedAbiArg<Uint8Array, 'signer'>,
        ],
        Response<bigint[], bigint>
      >,
      addPoxPartialStacked: {
        name: 'add-pox-partial-stacked',
        access: 'private',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'first-reward-cycle', type: 'uint128' },
          { name: 'num-cycles', type: 'uint128' },
          { name: 'amount-ustx', type: 'uint128' },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          firstRewardCycle: TypedAbiArg<number | bigint, 'firstRewardCycle'>,
          numCycles: TypedAbiArg<number | bigint, 'numCycles'>,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
        ],
        boolean
      >,
      addPoxPartialStackedToIthCycle: {
        name: 'add-pox-partial-stacked-to-ith-cycle',
        access: 'private',
        args: [
          { name: 'cycle-index', type: 'uint128' },
          {
            name: 'params',
            type: {
              tuple: [
                { name: 'amount-ustx', type: 'uint128' },
                { name: 'num-cycles', type: 'uint128' },
                {
                  name: 'pox-addr',
                  type: {
                    tuple: [
                      { name: 'hashbytes', type: { buffer: { length: 32 } } },
                      { name: 'version', type: { buffer: { length: 1 } } },
                    ],
                  },
                },
                { name: 'reward-cycle', type: 'uint128' },
              ],
            },
          },
        ],
        outputs: {
          type: {
            tuple: [
              { name: 'amount-ustx', type: 'uint128' },
              { name: 'num-cycles', type: 'uint128' },
              {
                name: 'pox-addr',
                type: {
                  tuple: [
                    { name: 'hashbytes', type: { buffer: { length: 32 } } },
                    { name: 'version', type: { buffer: { length: 1 } } },
                  ],
                },
              },
              { name: 'reward-cycle', type: 'uint128' },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          cycleIndex: TypedAbiArg<number | bigint, 'cycleIndex'>,
          params: TypedAbiArg<
            {
              amountUstx: number | bigint;
              numCycles: number | bigint;
              poxAddr: {
                hashbytes: Uint8Array;
                version: Uint8Array;
              };
              rewardCycle: number | bigint;
            },
            'params'
          >,
        ],
        {
          amountUstx: bigint;
          numCycles: bigint;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          rewardCycle: bigint;
        }
      >,
      appendRewardCyclePoxAddr: {
        name: 'append-reward-cycle-pox-addr',
        access: 'private',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'amount-ustx', type: 'uint128' },
          { name: 'stacker', type: { optional: 'principal' } },
          { name: 'signer', type: { buffer: { length: 33 } } },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          stacker: TypedAbiArg<string | null, 'stacker'>,
          signer: TypedAbiArg<Uint8Array, 'signer'>,
        ],
        bigint
      >,
      consumeSignerKeyAuthorization: {
        name: 'consume-signer-key-authorization',
        access: 'private',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'topic', type: { 'string-ascii': { length: 14 } } },
          { name: 'period', type: 'uint128' },
          {
            name: 'signer-sig-opt',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'amount', type: 'uint128' },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          topic: TypedAbiArg<string, 'topic'>,
          period: TypedAbiArg<number | bigint, 'period'>,
          signerSigOpt: TypedAbiArg<Uint8Array | null, 'signerSigOpt'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          amount: TypedAbiArg<number | bigint, 'amount'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<boolean, bigint>
      >,
      increaseRewardCycleEntry: {
        name: 'increase-reward-cycle-entry',
        access: 'private',
        args: [
          { name: 'reward-cycle-index', type: 'uint128' },
          {
            name: 'updates',
            type: {
              optional: {
                tuple: [
                  { name: 'add-amount', type: 'uint128' },
                  { name: 'first-cycle', type: 'uint128' },
                  { name: 'reward-cycle', type: 'uint128' },
                  { name: 'signer-key', type: { buffer: { length: 33 } } },
                  { name: 'stacker', type: 'principal' },
                ],
              },
            },
          },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'add-amount', type: 'uint128' },
                { name: 'first-cycle', type: 'uint128' },
                { name: 'reward-cycle', type: 'uint128' },
                { name: 'signer-key', type: { buffer: { length: 33 } } },
                { name: 'stacker', type: 'principal' },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [
          rewardCycleIndex: TypedAbiArg<number | bigint, 'rewardCycleIndex'>,
          updates: TypedAbiArg<
            {
              addAmount: number | bigint;
              firstCycle: number | bigint;
              rewardCycle: number | bigint;
              signerKey: Uint8Array;
              stacker: string;
            } | null,
            'updates'
          >,
        ],
        {
          addAmount: bigint;
          firstCycle: bigint;
          rewardCycle: bigint;
          signerKey: Uint8Array;
          stacker: string;
        } | null
      >,
      innerStackAggregationCommit: {
        name: 'inner-stack-aggregation-commit',
        access: 'private',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          {
            name: 'signer-sig',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          signerSig: TypedAbiArg<Uint8Array | null, 'signerSig'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<bigint, bigint>
      >,
      allowContractCaller: {
        name: 'allow-contract-caller',
        access: 'public',
        args: [
          { name: 'caller', type: 'principal' },
          { name: 'until-burn-ht', type: { optional: 'uint128' } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          caller: TypedAbiArg<string, 'caller'>,
          untilBurnHt: TypedAbiArg<number | bigint | null, 'untilBurnHt'>,
        ],
        Response<boolean, bigint>
      >,
      delegateStackExtend: {
        name: 'delegate-stack-extend',
        access: 'public',
        args: [
          { name: 'stacker', type: 'principal' },
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'extend-count', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'stacker', type: 'principal' },
                  { name: 'unlock-burn-height', type: 'uint128' },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          stacker: TypedAbiArg<string, 'stacker'>,
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          extendCount: TypedAbiArg<number | bigint, 'extendCount'>,
        ],
        Response<
          {
            stacker: string;
            unlockBurnHeight: bigint;
          },
          bigint
        >
      >,
      delegateStackIncrease: {
        name: 'delegate-stack-increase',
        access: 'public',
        args: [
          { name: 'stacker', type: 'principal' },
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'increase-by', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'stacker', type: 'principal' },
                  { name: 'total-locked', type: 'uint128' },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          stacker: TypedAbiArg<string, 'stacker'>,
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          increaseBy: TypedAbiArg<number | bigint, 'increaseBy'>,
        ],
        Response<
          {
            stacker: string;
            totalLocked: bigint;
          },
          bigint
        >
      >,
      delegateStackStx: {
        name: 'delegate-stack-stx',
        access: 'public',
        args: [
          { name: 'stacker', type: 'principal' },
          { name: 'amount-ustx', type: 'uint128' },
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'start-burn-ht', type: 'uint128' },
          { name: 'lock-period', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'lock-amount', type: 'uint128' },
                  { name: 'stacker', type: 'principal' },
                  { name: 'unlock-burn-height', type: 'uint128' },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          stacker: TypedAbiArg<string, 'stacker'>,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          startBurnHt: TypedAbiArg<number | bigint, 'startBurnHt'>,
          lockPeriod: TypedAbiArg<number | bigint, 'lockPeriod'>,
        ],
        Response<
          {
            lockAmount: bigint;
            stacker: string;
            unlockBurnHeight: bigint;
          },
          bigint
        >
      >,
      delegateStx: {
        name: 'delegate-stx',
        access: 'public',
        args: [
          { name: 'amount-ustx', type: 'uint128' },
          { name: 'delegate-to', type: 'principal' },
          { name: 'until-burn-ht', type: { optional: 'uint128' } },
          {
            name: 'pox-addr',
            type: {
              optional: {
                tuple: [
                  { name: 'hashbytes', type: { buffer: { length: 32 } } },
                  { name: 'version', type: { buffer: { length: 1 } } },
                ],
              },
            },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          delegateTo: TypedAbiArg<string, 'delegateTo'>,
          untilBurnHt: TypedAbiArg<number | bigint | null, 'untilBurnHt'>,
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            } | null,
            'poxAddr'
          >,
        ],
        Response<boolean, bigint>
      >,
      disallowContractCaller: {
        name: 'disallow-contract-caller',
        access: 'public',
        args: [{ name: 'caller', type: 'principal' }],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [caller: TypedAbiArg<string, 'caller'>],
        Response<boolean, bigint>
      >,
      revokeDelegateStx: {
        name: 'revoke-delegate-stx',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: {
              ok: {
                optional: {
                  tuple: [
                    { name: 'amount-ustx', type: 'uint128' },
                    { name: 'delegated-to', type: 'principal' },
                    {
                      name: 'pox-addr',
                      type: {
                        optional: {
                          tuple: [
                            {
                              name: 'hashbytes',
                              type: { buffer: { length: 32 } },
                            },
                            {
                              name: 'version',
                              type: { buffer: { length: 1 } },
                            },
                          ],
                        },
                      },
                    },
                    { name: 'until-burn-ht', type: { optional: 'uint128' } },
                  ],
                },
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [],
        Response<
          {
            amountUstx: bigint;
            delegatedTo: string;
            poxAddr: {
              hashbytes: Uint8Array;
              version: Uint8Array;
            } | null;
            untilBurnHt: bigint | null;
          } | null,
          bigint
        >
      >,
      setBurnchainParameters: {
        name: 'set-burnchain-parameters',
        access: 'public',
        args: [
          { name: 'first-burn-height', type: 'uint128' },
          { name: 'prepare-cycle-length', type: 'uint128' },
          { name: 'reward-cycle-length', type: 'uint128' },
          { name: 'begin-pox-4-reward-cycle', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          firstBurnHeight: TypedAbiArg<number | bigint, 'firstBurnHeight'>,
          prepareCycleLength: TypedAbiArg<
            number | bigint,
            'prepareCycleLength'
          >,
          rewardCycleLength: TypedAbiArg<number | bigint, 'rewardCycleLength'>,
          beginPox4RewardCycle: TypedAbiArg<
            number | bigint,
            'beginPox4RewardCycle'
          >,
        ],
        Response<boolean, bigint>
      >,
      setSignerKeyAuthorization: {
        name: 'set-signer-key-authorization',
        access: 'public',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'period', type: 'uint128' },
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'topic', type: { 'string-ascii': { length: 14 } } },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'allowed', type: 'bool' },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          period: TypedAbiArg<number | bigint, 'period'>,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          topic: TypedAbiArg<string, 'topic'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          allowed: TypedAbiArg<boolean, 'allowed'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<boolean, bigint>
      >,
      stackAggregationCommit: {
        name: 'stack-aggregation-commit',
        access: 'public',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          {
            name: 'signer-sig',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          signerSig: TypedAbiArg<Uint8Array | null, 'signerSig'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<boolean, bigint>
      >,
      stackAggregationCommitIndexed: {
        name: 'stack-aggregation-commit-indexed',
        access: 'public',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          {
            name: 'signer-sig',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          signerSig: TypedAbiArg<Uint8Array | null, 'signerSig'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<bigint, bigint>
      >,
      stackAggregationIncrease: {
        name: 'stack-aggregation-increase',
        access: 'public',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'reward-cycle-index', type: 'uint128' },
          {
            name: 'signer-sig',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          rewardCycleIndex: TypedAbiArg<number | bigint, 'rewardCycleIndex'>,
          signerSig: TypedAbiArg<Uint8Array | null, 'signerSig'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<boolean, bigint>
      >,
      stackExtend: {
        name: 'stack-extend',
        access: 'public',
        args: [
          { name: 'extend-count', type: 'uint128' },
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          {
            name: 'signer-sig',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'stacker', type: 'principal' },
                  { name: 'unlock-burn-height', type: 'uint128' },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          extendCount: TypedAbiArg<number | bigint, 'extendCount'>,
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          signerSig: TypedAbiArg<Uint8Array | null, 'signerSig'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<
          {
            stacker: string;
            unlockBurnHeight: bigint;
          },
          bigint
        >
      >,
      stackIncrease: {
        name: 'stack-increase',
        access: 'public',
        args: [
          { name: 'increase-by', type: 'uint128' },
          {
            name: 'signer-sig',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'stacker', type: 'principal' },
                  { name: 'total-locked', type: 'uint128' },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          increaseBy: TypedAbiArg<number | bigint, 'increaseBy'>,
          signerSig: TypedAbiArg<Uint8Array | null, 'signerSig'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<
          {
            stacker: string;
            totalLocked: bigint;
          },
          bigint
        >
      >,
      stackStx: {
        name: 'stack-stx',
        access: 'public',
        args: [
          { name: 'amount-ustx', type: 'uint128' },
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'start-burn-ht', type: 'uint128' },
          { name: 'lock-period', type: 'uint128' },
          {
            name: 'signer-sig',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'lock-amount', type: 'uint128' },
                  { name: 'signer-key', type: { buffer: { length: 33 } } },
                  { name: 'stacker', type: 'principal' },
                  { name: 'unlock-burn-height', type: 'uint128' },
                ],
              },
              error: 'int128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          startBurnHt: TypedAbiArg<number | bigint, 'startBurnHt'>,
          lockPeriod: TypedAbiArg<number | bigint, 'lockPeriod'>,
          signerSig: TypedAbiArg<Uint8Array | null, 'signerSig'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<
          {
            lockAmount: bigint;
            signerKey: Uint8Array;
            stacker: string;
            unlockBurnHeight: bigint;
          },
          bigint
        >
      >,
      burnHeightToRewardCycle: {
        name: 'burn-height-to-reward-cycle',
        access: 'read_only',
        args: [{ name: 'height', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, 'height'>],
        bigint
      >,
      canStackStx: {
        name: 'can-stack-stx',
        access: 'read_only',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'amount-ustx', type: 'uint128' },
          { name: 'first-reward-cycle', type: 'uint128' },
          { name: 'num-cycles', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          firstRewardCycle: TypedAbiArg<number | bigint, 'firstRewardCycle'>,
          numCycles: TypedAbiArg<number | bigint, 'numCycles'>,
        ],
        Response<boolean, bigint>
      >,
      checkCallerAllowed: {
        name: 'check-caller-allowed',
        access: 'read_only',
        args: [],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[], boolean>,
      checkPoxAddrHashbytes: {
        name: 'check-pox-addr-hashbytes',
        access: 'read_only',
        args: [
          { name: 'version', type: { buffer: { length: 1 } } },
          { name: 'hashbytes', type: { buffer: { length: 32 } } },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          version: TypedAbiArg<Uint8Array, 'version'>,
          hashbytes: TypedAbiArg<Uint8Array, 'hashbytes'>,
        ],
        boolean
      >,
      checkPoxAddrVersion: {
        name: 'check-pox-addr-version',
        access: 'read_only',
        args: [{ name: 'version', type: { buffer: { length: 1 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [version: TypedAbiArg<Uint8Array, 'version'>],
        boolean
      >,
      checkPoxLockPeriod: {
        name: 'check-pox-lock-period',
        access: 'read_only',
        args: [{ name: 'lock-period', type: 'uint128' }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [lockPeriod: TypedAbiArg<number | bigint, 'lockPeriod'>],
        boolean
      >,
      currentPoxRewardCycle: {
        name: 'current-pox-reward-cycle',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getAllowanceContractCallers: {
        name: 'get-allowance-contract-callers',
        access: 'read_only',
        args: [
          { name: 'sender', type: 'principal' },
          { name: 'calling-contract', type: 'principal' },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [{ name: 'until-burn-ht', type: { optional: 'uint128' } }],
            },
          },
        },
      } as TypedAbiFunction<
        [
          sender: TypedAbiArg<string, 'sender'>,
          callingContract: TypedAbiArg<string, 'callingContract'>,
        ],
        {
          untilBurnHt: bigint | null;
        } | null
      >,
      getCheckDelegation: {
        name: 'get-check-delegation',
        access: 'read_only',
        args: [{ name: 'stacker', type: 'principal' }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'amount-ustx', type: 'uint128' },
                { name: 'delegated-to', type: 'principal' },
                {
                  name: 'pox-addr',
                  type: {
                    optional: {
                      tuple: [
                        { name: 'hashbytes', type: { buffer: { length: 32 } } },
                        { name: 'version', type: { buffer: { length: 1 } } },
                      ],
                    },
                  },
                },
                { name: 'until-burn-ht', type: { optional: 'uint128' } },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [stacker: TypedAbiArg<string, 'stacker'>],
        {
          amountUstx: bigint;
          delegatedTo: string;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          } | null;
          untilBurnHt: bigint | null;
        } | null
      >,
      getDelegationInfo: {
        name: 'get-delegation-info',
        access: 'read_only',
        args: [{ name: 'stacker', type: 'principal' }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'amount-ustx', type: 'uint128' },
                { name: 'delegated-to', type: 'principal' },
                {
                  name: 'pox-addr',
                  type: {
                    optional: {
                      tuple: [
                        { name: 'hashbytes', type: { buffer: { length: 32 } } },
                        { name: 'version', type: { buffer: { length: 1 } } },
                      ],
                    },
                  },
                },
                { name: 'until-burn-ht', type: { optional: 'uint128' } },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [stacker: TypedAbiArg<string, 'stacker'>],
        {
          amountUstx: bigint;
          delegatedTo: string;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          } | null;
          untilBurnHt: bigint | null;
        } | null
      >,
      getNumRewardSetPoxAddresses: {
        name: 'get-num-reward-set-pox-addresses',
        access: 'read_only',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        bigint
      >,
      getPartialStackedByCycle: {
        name: 'get-partial-stacked-by-cycle',
        access: 'read_only',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'sender', type: 'principal' },
        ],
        outputs: {
          type: {
            optional: { tuple: [{ name: 'stacked-amount', type: 'uint128' }] },
          },
        },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          sender: TypedAbiArg<string, 'sender'>,
        ],
        {
          stackedAmount: bigint;
        } | null
      >,
      getPoxInfo: {
        name: 'get-pox-info',
        access: 'read_only',
        args: [],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'first-burnchain-block-height', type: 'uint128' },
                  { name: 'min-amount-ustx', type: 'uint128' },
                  { name: 'prepare-cycle-length', type: 'uint128' },
                  { name: 'reward-cycle-id', type: 'uint128' },
                  { name: 'reward-cycle-length', type: 'uint128' },
                  { name: 'total-liquid-supply-ustx', type: 'uint128' },
                ],
              },
              error: 'none',
            },
          },
        },
      } as TypedAbiFunction<
        [],
        Response<
          {
            firstBurnchainBlockHeight: bigint;
            minAmountUstx: bigint;
            prepareCycleLength: bigint;
            rewardCycleId: bigint;
            rewardCycleLength: bigint;
            totalLiquidSupplyUstx: bigint;
          },
          null
        >
      >,
      getRewardSetPoxAddress: {
        name: 'get-reward-set-pox-address',
        access: 'read_only',
        args: [
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'index', type: 'uint128' },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [
                {
                  name: 'pox-addr',
                  type: {
                    tuple: [
                      { name: 'hashbytes', type: { buffer: { length: 32 } } },
                      { name: 'version', type: { buffer: { length: 1 } } },
                    ],
                  },
                },
                { name: 'signer', type: { buffer: { length: 33 } } },
                { name: 'stacker', type: { optional: 'principal' } },
                { name: 'total-ustx', type: 'uint128' },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          index: TypedAbiArg<number | bigint, 'index'>,
        ],
        {
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          signer: Uint8Array;
          stacker: string | null;
          totalUstx: bigint;
        } | null
      >,
      getRewardSetSize: {
        name: 'get-reward-set-size',
        access: 'read_only',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        bigint
      >,
      getSignerKeyMessageHash: {
        name: 'get-signer-key-message-hash',
        access: 'read_only',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'topic', type: { 'string-ascii': { length: 14 } } },
          { name: 'period', type: 'uint128' },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { buffer: { length: 32 } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          topic: TypedAbiArg<string, 'topic'>,
          period: TypedAbiArg<number | bigint, 'period'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Uint8Array
      >,
      getStackerInfo: {
        name: 'get-stacker-info',
        access: 'read_only',
        args: [{ name: 'stacker', type: 'principal' }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'delegated-to', type: { optional: 'principal' } },
                { name: 'first-reward-cycle', type: 'uint128' },
                { name: 'lock-period', type: 'uint128' },
                {
                  name: 'pox-addr',
                  type: {
                    tuple: [
                      { name: 'hashbytes', type: { buffer: { length: 32 } } },
                      { name: 'version', type: { buffer: { length: 1 } } },
                    ],
                  },
                },
                {
                  name: 'reward-set-indexes',
                  type: { list: { type: 'uint128', length: 12 } },
                },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [stacker: TypedAbiArg<string, 'stacker'>],
        {
          delegatedTo: string | null;
          firstRewardCycle: bigint;
          lockPeriod: bigint;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          rewardSetIndexes: bigint[];
        } | null
      >,
      getStackingMinimum: {
        name: 'get-stacking-minimum',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getTotalUstxStacked: {
        name: 'get-total-ustx-stacked',
        access: 'read_only',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        bigint
      >,
      minimalCanStackStx: {
        name: 'minimal-can-stack-stx',
        access: 'read_only',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'amount-ustx', type: 'uint128' },
          { name: 'first-reward-cycle', type: 'uint128' },
          { name: 'num-cycles', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          firstRewardCycle: TypedAbiArg<number | bigint, 'firstRewardCycle'>,
          numCycles: TypedAbiArg<number | bigint, 'numCycles'>,
        ],
        Response<boolean, bigint>
      >,
      rewardCycleToBurnHeight: {
        name: 'reward-cycle-to-burn-height',
        access: 'read_only',
        args: [{ name: 'cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [cycle: TypedAbiArg<number | bigint, 'cycle'>],
        bigint
      >,
      verifySignerKeySig: {
        name: 'verify-signer-key-sig',
        access: 'read_only',
        args: [
          {
            name: 'pox-addr',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'topic', type: { 'string-ascii': { length: 14 } } },
          { name: 'period', type: 'uint128' },
          {
            name: 'signer-sig-opt',
            type: { optional: { buffer: { length: 65 } } },
          },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'amount', type: 'uint128' },
          { name: 'max-amount', type: 'uint128' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'int128' } } },
      } as TypedAbiFunction<
        [
          poxAddr: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'poxAddr'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          topic: TypedAbiArg<string, 'topic'>,
          period: TypedAbiArg<number | bigint, 'period'>,
          signerSigOpt: TypedAbiArg<Uint8Array | null, 'signerSigOpt'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          amount: TypedAbiArg<number | bigint, 'amount'>,
          maxAmount: TypedAbiArg<number | bigint, 'maxAmount'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Response<boolean, bigint>
      >,
    },
    maps: {
      allowanceContractCallers: {
        name: 'allowance-contract-callers',
        key: {
          tuple: [
            { name: 'contract-caller', type: 'principal' },
            { name: 'sender', type: 'principal' },
          ],
        },
        value: {
          tuple: [{ name: 'until-burn-ht', type: { optional: 'uint128' } }],
        },
      } as TypedAbiMap<
        {
          contractCaller: string;
          sender: string;
        },
        {
          untilBurnHt: bigint | null;
        }
      >,
      delegationState: {
        name: 'delegation-state',
        key: { tuple: [{ name: 'stacker', type: 'principal' }] },
        value: {
          tuple: [
            { name: 'amount-ustx', type: 'uint128' },
            { name: 'delegated-to', type: 'principal' },
            {
              name: 'pox-addr',
              type: {
                optional: {
                  tuple: [
                    { name: 'hashbytes', type: { buffer: { length: 32 } } },
                    { name: 'version', type: { buffer: { length: 1 } } },
                  ],
                },
              },
            },
            { name: 'until-burn-ht', type: { optional: 'uint128' } },
          ],
        },
      } as TypedAbiMap<
        {
          stacker: string;
        },
        {
          amountUstx: bigint;
          delegatedTo: string;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          } | null;
          untilBurnHt: bigint | null;
        }
      >,
      loggedPartialStackedByCycle: {
        name: 'logged-partial-stacked-by-cycle',
        key: {
          tuple: [
            {
              name: 'pox-addr',
              type: {
                tuple: [
                  { name: 'hashbytes', type: { buffer: { length: 32 } } },
                  { name: 'version', type: { buffer: { length: 1 } } },
                ],
              },
            },
            { name: 'reward-cycle', type: 'uint128' },
            { name: 'sender', type: 'principal' },
          ],
        },
        value: { tuple: [{ name: 'stacked-amount', type: 'uint128' }] },
      } as TypedAbiMap<
        {
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          rewardCycle: number | bigint;
          sender: string;
        },
        {
          stackedAmount: bigint;
        }
      >,
      partialStackedByCycle: {
        name: 'partial-stacked-by-cycle',
        key: {
          tuple: [
            {
              name: 'pox-addr',
              type: {
                tuple: [
                  { name: 'hashbytes', type: { buffer: { length: 32 } } },
                  { name: 'version', type: { buffer: { length: 1 } } },
                ],
              },
            },
            { name: 'reward-cycle', type: 'uint128' },
            { name: 'sender', type: 'principal' },
          ],
        },
        value: { tuple: [{ name: 'stacked-amount', type: 'uint128' }] },
      } as TypedAbiMap<
        {
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          rewardCycle: number | bigint;
          sender: string;
        },
        {
          stackedAmount: bigint;
        }
      >,
      rewardCyclePoxAddressList: {
        name: 'reward-cycle-pox-address-list',
        key: {
          tuple: [
            { name: 'index', type: 'uint128' },
            { name: 'reward-cycle', type: 'uint128' },
          ],
        },
        value: {
          tuple: [
            {
              name: 'pox-addr',
              type: {
                tuple: [
                  { name: 'hashbytes', type: { buffer: { length: 32 } } },
                  { name: 'version', type: { buffer: { length: 1 } } },
                ],
              },
            },
            { name: 'signer', type: { buffer: { length: 33 } } },
            { name: 'stacker', type: { optional: 'principal' } },
            { name: 'total-ustx', type: 'uint128' },
          ],
        },
      } as TypedAbiMap<
        {
          index: number | bigint;
          rewardCycle: number | bigint;
        },
        {
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          signer: Uint8Array;
          stacker: string | null;
          totalUstx: bigint;
        }
      >,
      rewardCyclePoxAddressListLen: {
        name: 'reward-cycle-pox-address-list-len',
        key: { tuple: [{ name: 'reward-cycle', type: 'uint128' }] },
        value: { tuple: [{ name: 'len', type: 'uint128' }] },
      } as TypedAbiMap<
        {
          rewardCycle: number | bigint;
        },
        {
          len: bigint;
        }
      >,
      rewardCycleTotalStacked: {
        name: 'reward-cycle-total-stacked',
        key: { tuple: [{ name: 'reward-cycle', type: 'uint128' }] },
        value: { tuple: [{ name: 'total-ustx', type: 'uint128' }] },
      } as TypedAbiMap<
        {
          rewardCycle: number | bigint;
        },
        {
          totalUstx: bigint;
        }
      >,
      signerKeyAuthorizations: {
        name: 'signer-key-authorizations',
        key: {
          tuple: [
            { name: 'auth-id', type: 'uint128' },
            { name: 'max-amount', type: 'uint128' },
            { name: 'period', type: 'uint128' },
            {
              name: 'pox-addr',
              type: {
                tuple: [
                  { name: 'hashbytes', type: { buffer: { length: 32 } } },
                  { name: 'version', type: { buffer: { length: 1 } } },
                ],
              },
            },
            { name: 'reward-cycle', type: 'uint128' },
            { name: 'signer-key', type: { buffer: { length: 33 } } },
            { name: 'topic', type: { 'string-ascii': { length: 14 } } },
          ],
        },
        value: 'bool',
      } as TypedAbiMap<
        {
          authId: number | bigint;
          maxAmount: number | bigint;
          period: number | bigint;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          rewardCycle: number | bigint;
          signerKey: Uint8Array;
          topic: string;
        },
        boolean
      >,
      stackingState: {
        name: 'stacking-state',
        key: { tuple: [{ name: 'stacker', type: 'principal' }] },
        value: {
          tuple: [
            { name: 'delegated-to', type: { optional: 'principal' } },
            { name: 'first-reward-cycle', type: 'uint128' },
            { name: 'lock-period', type: 'uint128' },
            {
              name: 'pox-addr',
              type: {
                tuple: [
                  { name: 'hashbytes', type: { buffer: { length: 32 } } },
                  { name: 'version', type: { buffer: { length: 1 } } },
                ],
              },
            },
            {
              name: 'reward-set-indexes',
              type: { list: { type: 'uint128', length: 12 } },
            },
          ],
        },
      } as TypedAbiMap<
        {
          stacker: string;
        },
        {
          delegatedTo: string | null;
          firstRewardCycle: bigint;
          lockPeriod: bigint;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          rewardSetIndexes: bigint[];
        }
      >,
      usedSignerKeyAuthorizations: {
        name: 'used-signer-key-authorizations',
        key: {
          tuple: [
            { name: 'auth-id', type: 'uint128' },
            { name: 'max-amount', type: 'uint128' },
            { name: 'period', type: 'uint128' },
            {
              name: 'pox-addr',
              type: {
                tuple: [
                  { name: 'hashbytes', type: { buffer: { length: 32 } } },
                  { name: 'version', type: { buffer: { length: 1 } } },
                ],
              },
            },
            { name: 'reward-cycle', type: 'uint128' },
            { name: 'signer-key', type: { buffer: { length: 33 } } },
            { name: 'topic', type: { 'string-ascii': { length: 14 } } },
          ],
        },
        value: 'bool',
      } as TypedAbiMap<
        {
          authId: number | bigint;
          maxAmount: number | bigint;
          period: number | bigint;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          rewardCycle: number | bigint;
          signerKey: Uint8Array;
          topic: string;
        },
        boolean
      >,
    },
    variables: {
      aDDRESS_VERSION_NATIVE_P2TR: {
        name: 'ADDRESS_VERSION_NATIVE_P2TR',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      aDDRESS_VERSION_NATIVE_P2WPKH: {
        name: 'ADDRESS_VERSION_NATIVE_P2WPKH',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      aDDRESS_VERSION_NATIVE_P2WSH: {
        name: 'ADDRESS_VERSION_NATIVE_P2WSH',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      aDDRESS_VERSION_P2PKH: {
        name: 'ADDRESS_VERSION_P2PKH',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      aDDRESS_VERSION_P2SH: {
        name: 'ADDRESS_VERSION_P2SH',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      aDDRESS_VERSION_P2WPKH: {
        name: 'ADDRESS_VERSION_P2WPKH',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      aDDRESS_VERSION_P2WSH: {
        name: 'ADDRESS_VERSION_P2WSH',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      ERR_DELEGATION_ALREADY_REVOKED: {
        name: 'ERR_DELEGATION_ALREADY_REVOKED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_DELEGATION_EXPIRES_DURING_LOCK: {
        name: 'ERR_DELEGATION_EXPIRES_DURING_LOCK',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_DELEGATION_NO_REWARD_SLOT: {
        name: 'ERR_DELEGATION_NO_REWARD_SLOT',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_DELEGATION_POX_ADDR_REQUIRED: {
        name: 'ERR_DELEGATION_POX_ADDR_REQUIRED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_DELEGATION_TOO_MUCH_LOCKED: {
        name: 'ERR_DELEGATION_TOO_MUCH_LOCKED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_DELEGATION_WRONG_REWARD_SLOT: {
        name: 'ERR_DELEGATION_WRONG_REWARD_SLOT',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_INCREASE: {
        name: 'ERR_INVALID_INCREASE',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_REWARD_CYCLE: {
        name: 'ERR_INVALID_REWARD_CYCLE',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_SIGNATURE_PUBKEY: {
        name: 'ERR_INVALID_SIGNATURE_PUBKEY',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_SIGNATURE_RECOVER: {
        name: 'ERR_INVALID_SIGNATURE_RECOVER',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_SIGNER_KEY: {
        name: 'ERR_INVALID_SIGNER_KEY',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_START_BURN_HEIGHT: {
        name: 'ERR_INVALID_START_BURN_HEIGHT',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NOT_ALLOWED: {
        name: 'ERR_NOT_ALLOWED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NOT_CURRENT_STACKER: {
        name: 'ERR_NOT_CURRENT_STACKER',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_REUSED_SIGNER_KEY: {
        name: 'ERR_REUSED_SIGNER_KEY',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH: {
        name: 'ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_SIGNER_AUTH_USED: {
        name: 'ERR_SIGNER_AUTH_USED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_ALREADY_DELEGATED: {
        name: 'ERR_STACKING_ALREADY_DELEGATED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_ALREADY_STACKED: {
        name: 'ERR_STACKING_ALREADY_STACKED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_CORRUPTED_STATE: {
        name: 'ERR_STACKING_CORRUPTED_STATE',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_EXPIRED: {
        name: 'ERR_STACKING_EXPIRED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_INSUFFICIENT_FUNDS: {
        name: 'ERR_STACKING_INSUFFICIENT_FUNDS',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_INVALID_AMOUNT: {
        name: 'ERR_STACKING_INVALID_AMOUNT',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_INVALID_LOCK_PERIOD: {
        name: 'ERR_STACKING_INVALID_LOCK_PERIOD',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_INVALID_POX_ADDRESS: {
        name: 'ERR_STACKING_INVALID_POX_ADDRESS',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_IS_DELEGATED: {
        name: 'ERR_STACKING_IS_DELEGATED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_NOT_DELEGATED: {
        name: 'ERR_STACKING_NOT_DELEGATED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_NO_SUCH_PRINCIPAL: {
        name: 'ERR_STACKING_NO_SUCH_PRINCIPAL',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_PERMISSION_DENIED: {
        name: 'ERR_STACKING_PERMISSION_DENIED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_POX_ADDRESS_IN_USE: {
        name: 'ERR_STACKING_POX_ADDRESS_IN_USE',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_STX_LOCKED: {
        name: 'ERR_STACKING_STX_LOCKED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_THRESHOLD_NOT_MET: {
        name: 'ERR_STACKING_THRESHOLD_NOT_MET',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACKING_UNREACHABLE: {
        name: 'ERR_STACKING_UNREACHABLE',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACK_EXTEND_NOT_LOCKED: {
        name: 'ERR_STACK_EXTEND_NOT_LOCKED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_STACK_INCREASE_NOT_LOCKED: {
        name: 'ERR_STACK_INCREASE_NOT_LOCKED',
        type: 'int128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      MAX_ADDRESS_VERSION: {
        name: 'MAX_ADDRESS_VERSION',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      mAX_ADDRESS_VERSION_BUFF_20: {
        name: 'MAX_ADDRESS_VERSION_BUFF_20',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      mAX_ADDRESS_VERSION_BUFF_32: {
        name: 'MAX_ADDRESS_VERSION_BUFF_32',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      MAX_POX_REWARD_CYCLES: {
        name: 'MAX_POX_REWARD_CYCLES',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      MIN_POX_REWARD_CYCLES: {
        name: 'MIN_POX_REWARD_CYCLES',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      PREPARE_CYCLE_LENGTH: {
        name: 'PREPARE_CYCLE_LENGTH',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      REWARD_CYCLE_LENGTH: {
        name: 'REWARD_CYCLE_LENGTH',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      sIP018_MSG_PREFIX: {
        name: 'SIP018_MSG_PREFIX',
        type: {
          buffer: {
            length: 6,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      sTACKING_THRESHOLD_25: {
        name: 'STACKING_THRESHOLD_25',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      STACKS_ADDR_VERSION_MAINNET: {
        name: 'STACKS_ADDR_VERSION_MAINNET',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      STACKS_ADDR_VERSION_TESTNET: {
        name: 'STACKS_ADDR_VERSION_TESTNET',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      configured: {
        name: 'configured',
        type: 'bool',
        access: 'variable',
      } as TypedAbiVariable<boolean>,
      firstBurnchainBlockHeight: {
        name: 'first-burnchain-block-height',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      firstPox4RewardCycle: {
        name: 'first-pox-4-reward-cycle',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      poxPrepareCycleLength: {
        name: 'pox-prepare-cycle-length',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      poxRewardCycleLength: {
        name: 'pox-reward-cycle-length',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      aDDRESS_VERSION_NATIVE_P2TR: Uint8Array.from([6]),
      aDDRESS_VERSION_NATIVE_P2WPKH: Uint8Array.from([4]),
      aDDRESS_VERSION_NATIVE_P2WSH: Uint8Array.from([5]),
      aDDRESS_VERSION_P2PKH: Uint8Array.from([0]),
      aDDRESS_VERSION_P2SH: Uint8Array.from([1]),
      aDDRESS_VERSION_P2WPKH: Uint8Array.from([2]),
      aDDRESS_VERSION_P2WSH: Uint8Array.from([3]),
      ERR_DELEGATION_ALREADY_REVOKED: 34n,
      ERR_DELEGATION_EXPIRES_DURING_LOCK: 21n,
      ERR_DELEGATION_NO_REWARD_SLOT: 28n,
      ERR_DELEGATION_POX_ADDR_REQUIRED: 23n,
      ERR_DELEGATION_TOO_MUCH_LOCKED: 22n,
      ERR_DELEGATION_WRONG_REWARD_SLOT: 29n,
      ERR_INVALID_INCREASE: 40n,
      ERR_INVALID_REWARD_CYCLE: 37n,
      ERR_INVALID_SIGNATURE_PUBKEY: 35n,
      ERR_INVALID_SIGNATURE_RECOVER: 36n,
      ERR_INVALID_SIGNER_KEY: 32n,
      ERR_INVALID_START_BURN_HEIGHT: 24n,
      ERR_NOT_ALLOWED: 19n,
      ERR_NOT_CURRENT_STACKER: 25n,
      ERR_REUSED_SIGNER_KEY: 33n,
      ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH: 38n,
      ERR_SIGNER_AUTH_USED: 39n,
      ERR_STACKING_ALREADY_DELEGATED: 20n,
      ERR_STACKING_ALREADY_STACKED: 3n,
      ERR_STACKING_CORRUPTED_STATE: 254n,
      ERR_STACKING_EXPIRED: 5n,
      ERR_STACKING_INSUFFICIENT_FUNDS: 1n,
      ERR_STACKING_INVALID_AMOUNT: 18n,
      ERR_STACKING_INVALID_LOCK_PERIOD: 2n,
      ERR_STACKING_INVALID_POX_ADDRESS: 13n,
      ERR_STACKING_IS_DELEGATED: 30n,
      ERR_STACKING_NOT_DELEGATED: 31n,
      ERR_STACKING_NO_SUCH_PRINCIPAL: 4n,
      ERR_STACKING_PERMISSION_DENIED: 9n,
      ERR_STACKING_POX_ADDRESS_IN_USE: 12n,
      ERR_STACKING_STX_LOCKED: 6n,
      ERR_STACKING_THRESHOLD_NOT_MET: 11n,
      ERR_STACKING_UNREACHABLE: 255n,
      ERR_STACK_EXTEND_NOT_LOCKED: 26n,
      ERR_STACK_INCREASE_NOT_LOCKED: 27n,
      MAX_ADDRESS_VERSION: 6n,
      mAX_ADDRESS_VERSION_BUFF_20: 4n,
      mAX_ADDRESS_VERSION_BUFF_32: 6n,
      MAX_POX_REWARD_CYCLES: 12n,
      MIN_POX_REWARD_CYCLES: 1n,
      PREPARE_CYCLE_LENGTH: 50n,
      REWARD_CYCLE_LENGTH: 1_050n,
      sIP018_MSG_PREFIX: Uint8Array.from([83, 73, 80, 48, 49, 56]),
      sTACKING_THRESHOLD_25: 8_000n,
      STACKS_ADDR_VERSION_MAINNET: Uint8Array.from([22]),
      STACKS_ADDR_VERSION_TESTNET: Uint8Array.from([26]),
      configured: false,
      firstBurnchainBlockHeight: 0n,
      firstPox4RewardCycle: 0n,
      poxPrepareCycleLength: 50n,
      poxRewardCycleLength: 1_050n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch24',
    clarity_version: 'Clarity2',
    contractName: 'pox-4',
  },
  pox5: {
    functions: {
      addStakerToBond: {
        name: 'add-staker-to-bond',
        access: 'private',
        args: [
          {
            name: 'staker-item',
            type: {
              tuple: [
                { name: 'max-sats', type: 'uint128' },
                { name: 'staker', type: 'principal' },
              ],
            },
          },
          {
            name: 'accumulator-res',
            type: {
              response: {
                ok: {
                  tuple: [
                    { name: 'bond-index', type: 'uint128' },
                    { name: 'sum-max-sats', type: 'uint128' },
                  ],
                },
                error: 'uint128',
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'bond-index', type: 'uint128' },
                  { name: 'sum-max-sats', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          stakerItem: TypedAbiArg<
            {
              maxSats: number | bigint;
              staker: string;
            },
            'stakerItem'
          >,
          accumulatorRes: TypedAbiArg<
            Response<
              {
                bondIndex: number | bigint;
                sumMaxSats: number | bigint;
              },
              number | bigint
            >,
            'accumulatorRes'
          >,
        ],
        Response<
          {
            bondIndex: bigint;
            sumMaxSats: bigint;
          },
          bigint
        >
      >,
      addStakerToSetForCycle: {
        name: 'add-staker-to-set-for-cycle',
        access: 'private',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        Response<boolean, bigint>
      >,
      addStakerToSignerCycles: {
        name: 'add-staker-to-signer-cycles',
        access: 'private',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'signer', type: 'principal' },
          { name: 'first-reward-cycle', type: 'uint128' },
          { name: 'num-cycles', type: 'uint128' },
          { name: 'amount-ustx', type: 'uint128' },
          { name: 'is-stx-staking', type: 'bool' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'amount-ustx', type: 'uint128' },
                  { name: 'first-reward-cycle', type: 'uint128' },
                  { name: 'is-stx-staking', type: 'bool' },
                  { name: 'signer', type: 'principal' },
                  { name: 'staker', type: 'principal' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          signer: TypedAbiArg<string, 'signer'>,
          firstRewardCycle: TypedAbiArg<number | bigint, 'firstRewardCycle'>,
          numCycles: TypedAbiArg<number | bigint, 'numCycles'>,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          isStxStaking: TypedAbiArg<boolean, 'isStxStaking'>,
        ],
        Response<
          {
            amountUstx: bigint;
            firstRewardCycle: bigint;
            isStxStaking: boolean;
            signer: string;
            staker: string;
          },
          bigint
        >
      >,
      addStakerToSignerForCycle: {
        name: 'add-staker-to-signer-for-cycle',
        access: 'private',
        args: [
          { name: 'cycle-index', type: 'uint128' },
          {
            name: 'accumulator-res',
            type: {
              response: {
                ok: {
                  tuple: [
                    { name: 'amount-ustx', type: 'uint128' },
                    { name: 'first-reward-cycle', type: 'uint128' },
                    { name: 'is-stx-staking', type: 'bool' },
                    { name: 'signer', type: 'principal' },
                    { name: 'staker', type: 'principal' },
                  ],
                },
                error: 'uint128',
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'amount-ustx', type: 'uint128' },
                  { name: 'first-reward-cycle', type: 'uint128' },
                  { name: 'is-stx-staking', type: 'bool' },
                  { name: 'signer', type: 'principal' },
                  { name: 'staker', type: 'principal' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          cycleIndex: TypedAbiArg<number | bigint, 'cycleIndex'>,
          accumulatorRes: TypedAbiArg<
            Response<
              {
                amountUstx: number | bigint;
                firstRewardCycle: number | bigint;
                isStxStaking: boolean;
                signer: string;
                staker: string;
              },
              number | bigint
            >,
            'accumulatorRes'
          >,
        ],
        Response<
          {
            amountUstx: bigint;
            firstRewardCycle: bigint;
            isStxStaking: boolean;
            signer: string;
            staker: string;
          },
          bigint
        >
      >,
      assertActiveBondIncluded: {
        name: 'assert-active-bond-included',
        access: 'private',
        args: [
          { name: 'offset', type: 'uint128' },
          {
            name: 'acc-res',
            type: {
              response: {
                ok: {
                  tuple: [
                    {
                      name: 'bond-periods',
                      type: { list: { type: 'uint128', length: 6 } },
                    },
                    { name: 'calculation-height', type: 'uint128' },
                    { name: 'latest-bond-index', type: 'uint128' },
                  ],
                },
                error: 'uint128',
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  {
                    name: 'bond-periods',
                    type: { list: { type: 'uint128', length: 6 } },
                  },
                  { name: 'calculation-height', type: 'uint128' },
                  { name: 'latest-bond-index', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          offset: TypedAbiArg<number | bigint, 'offset'>,
          accRes: TypedAbiArg<
            Response<
              {
                bondPeriods: number | bigint[];
                calculationHeight: number | bigint;
                latestBondIndex: number | bigint;
              },
              number | bigint
            >,
            'accRes'
          >,
        ],
        Response<
          {
            bondPeriods: bigint[];
            calculationHeight: bigint;
            latestBondIndex: bigint;
          },
          bigint
        >
      >,
      calculateBondRewards: {
        name: 'calculate-bond-rewards',
        access: 'private',
        args: [
          { name: 'bond-index', type: 'uint128' },
          {
            name: 'accumulator-res',
            type: {
              response: {
                ok: {
                  tuple: [
                    { name: 'available-rewards', type: 'uint128' },
                    { name: 'calculation-height', type: 'uint128' },
                    { name: 'last-bond-index', type: { optional: 'uint128' } },
                    {
                      name: 'last-bond-stx-value-ratio',
                      type: { optional: 'uint128' },
                    },
                  ],
                },
                error: 'uint128',
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'available-rewards', type: 'uint128' },
                  { name: 'calculation-height', type: 'uint128' },
                  { name: 'last-bond-index', type: { optional: 'uint128' } },
                  {
                    name: 'last-bond-stx-value-ratio',
                    type: { optional: 'uint128' },
                  },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>,
          accumulatorRes: TypedAbiArg<
            Response<
              {
                availableRewards: number | bigint;
                calculationHeight: number | bigint;
                lastBondIndex: number | bigint | null;
                lastBondStxValueRatio: number | bigint | null;
              },
              number | bigint
            >,
            'accumulatorRes'
          >,
        ],
        Response<
          {
            availableRewards: bigint;
            calculationHeight: bigint;
            lastBondIndex: bigint | null;
            lastBondStxValueRatio: bigint | null;
          },
          bigint
        >
      >,
      lockSbtc: {
        name: 'lock-sbtc',
        access: 'private',
        args: [{ name: 'amount', type: 'uint128' }],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [amount: TypedAbiArg<number | bigint, 'amount'>],
        Response<bigint, bigint>
      >,
      matchUintInList: {
        name: 'match-uint-in-list',
        access: 'private',
        args: [
          { name: 'item', type: 'uint128' },
          {
            name: 'acc',
            type: {
              tuple: [
                { name: 'found', type: 'bool' },
                { name: 'needle', type: 'uint128' },
              ],
            },
          },
        ],
        outputs: {
          type: {
            tuple: [
              { name: 'found', type: 'bool' },
              { name: 'needle', type: 'uint128' },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          item: TypedAbiArg<number | bigint, 'item'>,
          acc: TypedAbiArg<
            {
              found: boolean;
              needle: number | bigint;
            },
            'acc'
          >,
        ],
        {
          found: boolean;
          needle: bigint;
        }
      >,
      removeStakerFromCycles: {
        name: 'remove-staker-from-cycles',
        access: 'private',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'first-reward-cycle', type: 'uint128' },
          { name: 'num-cycles', type: 'uint128' },
          { name: 'is-stx-staking', type: 'bool' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'first-reward-cycle', type: 'uint128' },
                  { name: 'is-stx-staking', type: 'bool' },
                  { name: 'staker', type: 'principal' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          firstRewardCycle: TypedAbiArg<number | bigint, 'firstRewardCycle'>,
          numCycles: TypedAbiArg<number | bigint, 'numCycles'>,
          isStxStaking: TypedAbiArg<boolean, 'isStxStaking'>,
        ],
        Response<
          {
            firstRewardCycle: bigint;
            isStxStaking: boolean;
            staker: string;
          },
          bigint
        >
      >,
      removeStakerFromSetForCycle: {
        name: 'remove-staker-from-set-for-cycle',
        access: 'private',
        args: [
          { name: 'stacker', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          stacker: TypedAbiArg<string, 'stacker'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        Response<boolean, bigint>
      >,
      removeStakerFromSignerForCycle: {
        name: 'remove-staker-from-signer-for-cycle',
        access: 'private',
        args: [
          { name: 'cycle-index', type: 'uint128' },
          {
            name: 'accumulator-res',
            type: {
              response: {
                ok: {
                  tuple: [
                    { name: 'first-reward-cycle', type: 'uint128' },
                    { name: 'is-stx-staking', type: 'bool' },
                    { name: 'staker', type: 'principal' },
                  ],
                },
                error: 'uint128',
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'first-reward-cycle', type: 'uint128' },
                  { name: 'is-stx-staking', type: 'bool' },
                  { name: 'staker', type: 'principal' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          cycleIndex: TypedAbiArg<number | bigint, 'cycleIndex'>,
          accumulatorRes: TypedAbiArg<
            Response<
              {
                firstRewardCycle: number | bigint;
                isStxStaking: boolean;
                staker: string;
              },
              number | bigint
            >,
            'accumulatorRes'
          >,
        ],
        Response<
          {
            firstRewardCycle: bigint;
            isStxStaking: boolean;
            staker: string;
          },
          bigint
        >
      >,
      updateClaimableBondRewards: {
        name: 'update-claimable-bond-rewards',
        access: 'private',
        args: [
          { name: 'bond-index', type: 'uint128' },
          {
            name: 'accumulator',
            type: {
              tuple: [
                {
                  name: 'bond-rewards',
                  type: {
                    list: {
                      type: {
                        tuple: [
                          { name: 'bond-index', type: 'uint128' },
                          { name: 'rewards-paid', type: 'uint128' },
                          { name: 'rewards-pending', type: 'uint128' },
                          { name: 'rewards-per-share', type: 'uint128' },
                          { name: 'shares-staked', type: 'uint128' },
                        ],
                      },
                      length: 6,
                    },
                  },
                },
                { name: 'signer', type: 'principal' },
                { name: 'total', type: 'uint128' },
              ],
            },
          },
        ],
        outputs: {
          type: {
            tuple: [
              {
                name: 'bond-rewards',
                type: {
                  list: {
                    type: {
                      tuple: [
                        { name: 'bond-index', type: 'uint128' },
                        { name: 'rewards-paid', type: 'uint128' },
                        { name: 'rewards-pending', type: 'uint128' },
                        { name: 'rewards-per-share', type: 'uint128' },
                        { name: 'shares-staked', type: 'uint128' },
                      ],
                    },
                    length: 6,
                  },
                },
              },
              { name: 'signer', type: 'principal' },
              { name: 'total', type: 'uint128' },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>,
          accumulator: TypedAbiArg<
            {
              bondRewards: {
                bondIndex: number | bigint;
                rewardsPaid: number | bigint;
                rewardsPending: number | bigint;
                rewardsPerShare: number | bigint;
                sharesStaked: number | bigint;
              }[];
              signer: string;
              total: number | bigint;
            },
            'accumulator'
          >,
        ],
        {
          bondRewards: {
            bondIndex: bigint;
            rewardsPaid: bigint;
            rewardsPending: bigint;
            rewardsPerShare: bigint;
            sharesStaked: bigint;
          }[];
          signer: string;
          total: bigint;
        }
      >,
      updateClaimableRewards: {
        name: 'update-claimable-rewards',
        access: 'private',
        args: [
          { name: 'signer', type: 'principal' },
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: {
          type: {
            tuple: [
              { name: 'rewards-paid', type: 'uint128' },
              { name: 'rewards-pending', type: 'uint128' },
              { name: 'rewards-per-share', type: 'uint128' },
              { name: 'shares-staked', type: 'uint128' },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          signer: TypedAbiArg<string, 'signer'>,
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        {
          rewardsPaid: bigint;
          rewardsPending: bigint;
          rewardsPerShare: bigint;
          sharesStaked: bigint;
        }
      >,
      validateL1Lockup: {
        name: 'validate-l1-lockup',
        access: 'private',
        args: [
          {
            name: 'lockup',
            type: {
              tuple: [
                { name: 'amount', type: 'uint128' },
                { name: 'output-index', type: 'uint128' },
                { name: 'txid', type: { buffer: { length: 32 } } },
              ],
            },
          },
          {
            name: 'accumulator-res',
            type: {
              response: {
                ok: {
                  tuple: [
                    {
                      name: 'expected-script-hash',
                      type: { buffer: { length: 32 } },
                    },
                    { name: 'sum', type: 'uint128' },
                  ],
                },
                error: 'uint128',
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  {
                    name: 'expected-script-hash',
                    type: { buffer: { length: 32 } },
                  },
                  { name: 'sum', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          lockup: TypedAbiArg<
            {
              amount: number | bigint;
              outputIndex: number | bigint;
              txid: Uint8Array;
            },
            'lockup'
          >,
          accumulatorRes: TypedAbiArg<
            Response<
              {
                expectedScriptHash: Uint8Array;
                sum: number | bigint;
              },
              number | bigint
            >,
            'accumulatorRes'
          >,
        ],
        Response<
          {
            expectedScriptHash: Uint8Array;
            sum: bigint;
          },
          bigint
        >
      >,
      validateP2wshExists_q: {
        name: 'validate-p2wsh-exists?',
        access: 'private',
        args: [
          { name: 'script-hash', type: { buffer: { length: 32 } } },
          { name: 'amount', type: 'uint128' },
          { name: 'txid', type: { buffer: { length: 32 } } },
          { name: 'output-index', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          scriptHash: TypedAbiArg<Uint8Array, 'scriptHash'>,
          amount: TypedAbiArg<number | bigint, 'amount'>,
          txid: TypedAbiArg<Uint8Array, 'txid'>,
          outputIndex: TypedAbiArg<number | bigint, 'outputIndex'>,
        ],
        Response<bigint, bigint>
      >,
      verifyL1Lockups: {
        name: 'verify-l1-lockups',
        access: 'private',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'bond-index', type: 'uint128' },
          {
            name: 'lockups',
            type: {
              tuple: [
                {
                  name: 'outputs',
                  type: {
                    list: {
                      type: {
                        tuple: [
                          { name: 'amount', type: 'uint128' },
                          { name: 'output-index', type: 'uint128' },
                          { name: 'txid', type: { buffer: { length: 32 } } },
                        ],
                      },
                      length: 10,
                    },
                  },
                },
                { name: 'unlock-bytes', type: { buffer: { length: 683 } } },
              ],
            },
          },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>,
          lockups: TypedAbiArg<
            {
              outputs: {
                amount: number | bigint;
                outputIndex: number | bigint;
                txid: Uint8Array;
              }[];
              unlockBytes: Uint8Array;
            },
            'lockups'
          >,
        ],
        Response<bigint, bigint>
      >,
      allowContractCaller: {
        name: 'allow-contract-caller',
        access: 'public',
        args: [
          { name: 'caller', type: 'principal' },
          { name: 'until-burn-ht', type: { optional: 'uint128' } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          caller: TypedAbiArg<string, 'caller'>,
          untilBurnHt: TypedAbiArg<number | bigint | null, 'untilBurnHt'>,
        ],
        Response<boolean, bigint>
      >,
      announceL1EarlyExit: {
        name: 'announce-l1-early-exit',
        access: 'public',
        args: [{ name: 'staker', type: 'principal' }],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [staker: TypedAbiArg<string, 'staker'>],
        Response<boolean, bigint>
      >,
      calculateRewards: {
        name: 'calculate-rewards',
        access: 'public',
        args: [
          {
            name: 'bond-periods',
            type: { list: { type: 'uint128', length: 6 } },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [bondPeriods: TypedAbiArg<number | bigint[], 'bondPeriods'>],
        Response<boolean, bigint>
      >,
      claimRewards: {
        name: 'claim-rewards',
        access: 'public',
        args: [
          {
            name: 'bond-periods',
            type: { list: { type: 'uint128', length: 6 } },
          },
          { name: 'reward-cycle', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  {
                    name: 'bond-rewards',
                    type: {
                      list: {
                        type: {
                          tuple: [
                            { name: 'bond-index', type: 'uint128' },
                            { name: 'rewards-paid', type: 'uint128' },
                            { name: 'rewards-pending', type: 'uint128' },
                            { name: 'rewards-per-share', type: 'uint128' },
                            { name: 'shares-staked', type: 'uint128' },
                          ],
                        },
                        length: 6,
                      },
                    },
                  },
                  { name: 'bond-totals', type: 'uint128' },
                  {
                    name: 'stx-rewards',
                    type: {
                      tuple: [
                        { name: 'rewards-paid', type: 'uint128' },
                        { name: 'rewards-pending', type: 'uint128' },
                        { name: 'rewards-per-share', type: 'uint128' },
                        { name: 'shares-staked', type: 'uint128' },
                      ],
                    },
                  },
                  { name: 'total-rewards', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          bondPeriods: TypedAbiArg<number | bigint[], 'bondPeriods'>,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
        ],
        Response<
          {
            bondRewards: {
              bondIndex: bigint;
              rewardsPaid: bigint;
              rewardsPending: bigint;
              rewardsPerShare: bigint;
              sharesStaked: bigint;
            }[];
            bondTotals: bigint;
            stxRewards: {
              rewardsPaid: bigint;
              rewardsPending: bigint;
              rewardsPerShare: bigint;
              sharesStaked: bigint;
            };
            totalRewards: bigint;
          },
          bigint
        >
      >,
      disallowContractCaller: {
        name: 'disallow-contract-caller',
        access: 'public',
        args: [{ name: 'caller', type: 'principal' }],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [caller: TypedAbiArg<string, 'caller'>],
        Response<boolean, bigint>
      >,
      grantSignerKey: {
        name: 'grant-signer-key',
        access: 'public',
        args: [
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'signer-manager', type: 'principal' },
          { name: 'auth-id', type: 'uint128' },
          { name: 'signer-sig', type: { buffer: { length: 65 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          signerManager: TypedAbiArg<string, 'signerManager'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
          signerSig: TypedAbiArg<Uint8Array, 'signerSig'>,
        ],
        Response<boolean, bigint>
      >,
      registerForBond: {
        name: 'register-for-bond',
        access: 'public',
        args: [
          { name: 'bond-index', type: 'uint128' },
          { name: 'signer-manager', type: 'trait_reference' },
          { name: 'amount-ustx', type: 'uint128' },
          {
            name: 'btc-lockup',
            type: {
              response: {
                ok: {
                  tuple: [
                    {
                      name: 'outputs',
                      type: {
                        list: {
                          type: {
                            tuple: [
                              { name: 'amount', type: 'uint128' },
                              { name: 'output-index', type: 'uint128' },
                              {
                                name: 'txid',
                                type: { buffer: { length: 32 } },
                              },
                            ],
                          },
                          length: 10,
                        },
                      },
                    },
                    { name: 'unlock-bytes', type: { buffer: { length: 683 } } },
                  ],
                },
                error: 'uint128',
              },
            },
          },
          {
            name: 'signer-calldata',
            type: { optional: { buffer: { length: 500 } } },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>,
          signerManager: TypedAbiArg<string, 'signerManager'>,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          btcLockup: TypedAbiArg<
            Response<
              {
                outputs: {
                  amount: number | bigint;
                  outputIndex: number | bigint;
                  txid: Uint8Array;
                }[];
                unlockBytes: Uint8Array;
              },
              number | bigint
            >,
            'btcLockup'
          >,
          signerCalldata: TypedAbiArg<Uint8Array | null, 'signerCalldata'>,
        ],
        Response<boolean, bigint>
      >,
      registerSigner: {
        name: 'register-signer',
        access: 'public',
        args: [
          { name: 'signer-manager', type: 'trait_reference' },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'signer', type: 'principal' },
                  { name: 'signer-key', type: { buffer: { length: 33 } } },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          signerManager: TypedAbiArg<string, 'signerManager'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
        ],
        Response<
          {
            signer: string;
            signerKey: Uint8Array;
          },
          bigint
        >
      >,
      revokeSignerGrant: {
        name: 'revoke-signer-grant',
        access: 'public',
        args: [
          { name: 'signer-manager', type: 'principal' },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          signerManager: TypedAbiArg<string, 'signerManager'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
        ],
        Response<boolean, bigint>
      >,
      setBurnchainParameters: {
        name: 'set-burnchain-parameters',
        access: 'public',
        args: [
          { name: 'first-burn-height', type: 'uint128' },
          { name: 'prepare-cycle-length', type: 'uint128' },
          { name: 'reward-cycle-length', type: 'uint128' },
          { name: 'begin-pox5-reward-cycle', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'none' } } },
      } as TypedAbiFunction<
        [
          firstBurnHeight: TypedAbiArg<number | bigint, 'firstBurnHeight'>,
          prepareCycleLength: TypedAbiArg<
            number | bigint,
            'prepareCycleLength'
          >,
          rewardCycleLength: TypedAbiArg<number | bigint, 'rewardCycleLength'>,
          beginPox5RewardCycle: TypedAbiArg<
            number | bigint,
            'beginPox5RewardCycle'
          >,
        ],
        Response<boolean, null>
      >,
      setupBond: {
        name: 'setup-bond',
        access: 'public',
        args: [
          { name: 'bond-index', type: 'uint128' },
          { name: 'target-rate', type: 'uint128' },
          { name: 'stx-value-ratio', type: 'uint128' },
          { name: 'min-ustx-ratio', type: 'uint128' },
          { name: 'early-unlock-signers', type: { buffer: { length: 683 } } },
          { name: 'early-unlock-admin', type: 'principal' },
          {
            name: 'allowlist',
            type: {
              list: {
                type: {
                  tuple: [
                    { name: 'max-sats', type: 'uint128' },
                    { name: 'staker', type: 'principal' },
                  ],
                },
                length: 1000,
              },
            },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'bond-index', type: 'uint128' },
                  {
                    name: 'early-unlock-signers',
                    type: { buffer: { length: 683 } },
                  },
                  { name: 'max-allocation-sats', type: 'uint128' },
                  { name: 'min-ustx-ratio', type: 'uint128' },
                  { name: 'stx-value-ratio', type: 'uint128' },
                  { name: 'target-rate', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>,
          targetRate: TypedAbiArg<number | bigint, 'targetRate'>,
          stxValueRatio: TypedAbiArg<number | bigint, 'stxValueRatio'>,
          minUstxRatio: TypedAbiArg<number | bigint, 'minUstxRatio'>,
          earlyUnlockSigners: TypedAbiArg<Uint8Array, 'earlyUnlockSigners'>,
          earlyUnlockAdmin: TypedAbiArg<string, 'earlyUnlockAdmin'>,
          allowlist: TypedAbiArg<
            {
              maxSats: number | bigint;
              staker: string;
            }[],
            'allowlist'
          >,
        ],
        Response<
          {
            bondIndex: bigint;
            earlyUnlockSigners: Uint8Array;
            maxAllocationSats: bigint;
            minUstxRatio: bigint;
            stxValueRatio: bigint;
            targetRate: bigint;
          },
          bigint
        >
      >,
      stake: {
        name: 'stake',
        access: 'public',
        args: [
          { name: 'signer-manager', type: 'trait_reference' },
          { name: 'amount-ustx', type: 'uint128' },
          { name: 'num-cycles', type: 'uint128' },
          { name: 'start-burn-ht', type: 'uint128' },
          {
            name: 'signer-calldata',
            type: { optional: { buffer: { length: 500 } } },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'amount-ustx', type: 'uint128' },
                  { name: 'first-reward-cycle', type: 'uint128' },
                  { name: 'num-cycle', type: 'uint128' },
                  { name: 'signer', type: 'principal' },
                  { name: 'staker', type: 'principal' },
                  { name: 'unlock-burn-height', type: 'uint128' },
                  { name: 'unlock-cycle', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          signerManager: TypedAbiArg<string, 'signerManager'>,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          numCycles: TypedAbiArg<number | bigint, 'numCycles'>,
          startBurnHt: TypedAbiArg<number | bigint, 'startBurnHt'>,
          signerCalldata: TypedAbiArg<Uint8Array | null, 'signerCalldata'>,
        ],
        Response<
          {
            amountUstx: bigint;
            firstRewardCycle: bigint;
            numCycle: bigint;
            signer: string;
            staker: string;
            unlockBurnHeight: bigint;
            unlockCycle: bigint;
          },
          bigint
        >
      >,
      stakeUpdate: {
        name: 'stake-update',
        access: 'public',
        args: [
          { name: 'signer-manager', type: 'trait_reference' },
          { name: 'cycles-to-extend', type: 'uint128' },
          { name: 'amount-increase', type: 'uint128' },
          {
            name: 'signer-calldata',
            type: { optional: { buffer: { length: 500 } } },
          },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'amount-ustx', type: 'uint128' },
                  { name: 'num-cycles', type: 'uint128' },
                  { name: 'prev-unlock-height', type: 'uint128' },
                  { name: 'signer', type: 'principal' },
                  { name: 'staker', type: 'principal' },
                  { name: 'unlock-burn-height', type: 'uint128' },
                  { name: 'unlock-cycle', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          signerManager: TypedAbiArg<string, 'signerManager'>,
          cyclesToExtend: TypedAbiArg<number | bigint, 'cyclesToExtend'>,
          amountIncrease: TypedAbiArg<number | bigint, 'amountIncrease'>,
          signerCalldata: TypedAbiArg<Uint8Array | null, 'signerCalldata'>,
        ],
        Response<
          {
            amountUstx: bigint;
            numCycles: bigint;
            prevUnlockHeight: bigint;
            signer: string;
            staker: string;
            unlockBurnHeight: bigint;
            unlockCycle: bigint;
          },
          bigint
        >
      >,
      unstake: {
        name: 'unstake',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'amount-ustx', type: 'uint128' },
                  { name: 'first-reward-cycle', type: 'uint128' },
                  { name: 'staker', type: 'principal' },
                  { name: 'unlock-burn-height', type: 'uint128' },
                  { name: 'unlock-cycle', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [],
        Response<
          {
            amountUstx: bigint;
            firstRewardCycle: bigint;
            staker: string;
            unlockBurnHeight: bigint;
            unlockCycle: bigint;
          },
          bigint
        >
      >,
      updateBondRegistration: {
        name: 'update-bond-registration',
        access: 'public',
        args: [
          { name: 'signer-manager', type: 'trait_reference' },
          {
            name: 'signer-calldata',
            type: { optional: { buffer: { length: 500 } } },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          signerManager: TypedAbiArg<string, 'signerManager'>,
          signerCalldata: TypedAbiArg<Uint8Array | null, 'signerCalldata'>,
        ],
        Response<boolean, bigint>
      >,
      assertAllActiveBondsIncluded: {
        name: 'assert-all-active-bonds-included',
        access: 'read_only',
        args: [
          {
            name: 'bond-periods',
            type: { list: { type: 'uint128', length: 6 } },
          },
          { name: 'calculation-height', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          bondPeriods: TypedAbiArg<number | bigint[], 'bondPeriods'>,
          calculationHeight: TypedAbiArg<number | bigint, 'calculationHeight'>,
        ],
        Response<boolean, bigint>
      >,
      bondPeriodToBurnHeight: {
        name: 'bond-period-to-burn-height',
        access: 'read_only',
        args: [{ name: 'bond-index', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>],
        bigint
      >,
      bondPeriodToRewardCycle: {
        name: 'bond-period-to-reward-cycle',
        access: 'read_only',
        args: [{ name: 'bond-index', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>],
        bigint
      >,
      burnHeightToDistributionIndex: {
        name: 'burn-height-to-distribution-index',
        access: 'read_only',
        args: [{ name: 'height', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, 'height'>],
        bigint
      >,
      burnHeightToRewardCycle: {
        name: 'burn-height-to-reward-cycle',
        access: 'read_only',
        args: [{ name: 'height', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, 'height'>],
        bigint
      >,
      checkCallerAllowed: {
        name: 'check-caller-allowed',
        access: 'read_only',
        args: [],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<[], Response<boolean, bigint>>,
      checkPoxLockPeriod: {
        name: 'check-pox-lock-period',
        access: 'read_only',
        args: [{ name: 'lock-period', type: 'uint128' }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [lockPeriod: TypedAbiArg<number | bigint, 'lockPeriod'>],
        boolean
      >,
      currentDistributionCycle: {
        name: 'current-distribution-cycle',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      currentPoxRewardCycle: {
        name: 'current-pox-reward-cycle',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      distributionCycleToBurnHeight: {
        name: 'distribution-cycle-to-burn-height',
        access: 'read_only',
        args: [{ name: 'cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [cycle: TypedAbiArg<number | bigint, 'cycle'>],
        bigint
      >,
      getAmountDelegatedForSigner: {
        name: 'get-amount-delegated-for-signer',
        access: 'read_only',
        args: [
          { name: 'signer', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          signer: TypedAbiArg<string, 'signer'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        bigint
      >,
      getBondAllowance: {
        name: 'get-bond-allowance',
        access: 'read_only',
        args: [
          { name: 'bond-index', type: 'uint128' },
          { name: 'staker', type: 'principal' },
        ],
        outputs: { type: { optional: 'uint128' } },
      } as TypedAbiFunction<
        [
          bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>,
          staker: TypedAbiArg<string, 'staker'>,
        ],
        bigint | null
      >,
      getBondMembership: {
        name: 'get-bond-membership',
        access: 'read_only',
        args: [{ name: 'staker', type: 'principal' }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'amount-ustx', type: 'uint128' },
                { name: 'bond-index', type: 'uint128' },
                { name: 'is-l1-lock', type: 'bool' },
                { name: 'signer', type: 'principal' },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [staker: TypedAbiArg<string, 'staker'>],
        {
          amountUstx: bigint;
          bondIndex: bigint;
          isL1Lock: boolean;
          signer: string;
        } | null
      >,
      getClaimableRewards: {
        name: 'get-claimable-rewards',
        access: 'read_only',
        args: [
          { name: 'signer', type: 'principal' },
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: {
          type: {
            tuple: [
              { name: 'rewards-paid', type: 'uint128' },
              { name: 'rewards-pending', type: 'uint128' },
              { name: 'rewards-per-share', type: 'uint128' },
              { name: 'shares-staked', type: 'uint128' },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          signer: TypedAbiArg<string, 'signer'>,
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        {
          rewardsPaid: bigint;
          rewardsPending: bigint;
          rewardsPerShare: bigint;
          sharesStaked: bigint;
        }
      >,
      getLastAccountedRewardsOnly: {
        name: 'get-last-accounted-rewards-only',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getLastRewardComputeHeight: {
        name: 'get-last-reward-compute-height',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getNewRewards: {
        name: 'get-new-rewards',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getPoxInfo: {
        name: 'get-pox-info',
        access: 'read_only',
        args: [],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'first-burnchain-block-height', type: 'uint128' },
                  { name: 'min-amount-ustx', type: 'uint128' },
                  { name: 'prepare-cycle-length', type: 'uint128' },
                  { name: 'reward-cycle-id', type: 'uint128' },
                  { name: 'reward-cycle-length', type: 'uint128' },
                  { name: 'total-liquid-supply-ustx', type: 'uint128' },
                ],
              },
              error: 'none',
            },
          },
        },
      } as TypedAbiFunction<
        [],
        Response<
          {
            firstBurnchainBlockHeight: bigint;
            minAmountUstx: bigint;
            prepareCycleLength: bigint;
            rewardCycleId: bigint;
            rewardCycleLength: bigint;
            totalLiquidSupplyUstx: bigint;
          },
          null
        >
      >,
      getProtocolBond: {
        name: 'get-protocol-bond',
        access: 'read_only',
        args: [{ name: 'bond-index', type: 'uint128' }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'early-unlock-admin', type: 'principal' },
                {
                  name: 'early-unlock-signers',
                  type: { buffer: { length: 683 } },
                },
                { name: 'min-ustx-ratio', type: 'uint128' },
                { name: 'stx-value-ratio', type: 'uint128' },
                { name: 'target-rate', type: 'uint128' },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>],
        {
          earlyUnlockAdmin: string;
          earlyUnlockSigners: Uint8Array;
          minUstxRatio: bigint;
          stxValueRatio: bigint;
          targetRate: bigint;
        } | null
      >,
      getReserveBalance: {
        name: 'get-reserve-balance',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getRewards: {
        name: 'get-rewards',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getRewardsPerTokenForCycle: {
        name: 'get-rewards-per-token-for-cycle',
        access: 'read_only',
        args: [
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        bigint
      >,
      getSignerCycleMembership: {
        name: 'get-signer-cycle-membership',
        access: 'read_only',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'amount-ustx', type: 'uint128' },
                { name: 'signer', type: 'principal' },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        {
          amountUstx: bigint;
          signer: string;
        } | null
      >,
      getSignerGrantMessageHash: {
        name: 'get-signer-grant-message-hash',
        access: 'read_only',
        args: [
          { name: 'signer-manager', type: 'principal' },
          { name: 'auth-id', type: 'uint128' },
        ],
        outputs: { type: { buffer: { length: 32 } } },
      } as TypedAbiFunction<
        [
          signerManager: TypedAbiArg<string, 'signerManager'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
        ],
        Uint8Array
      >,
      getSignerInfo: {
        name: 'get-signer-info',
        access: 'read_only',
        args: [{ name: 'signer', type: 'principal' }],
        outputs: { type: { optional: { buffer: { length: 33 } } } },
      } as TypedAbiFunction<
        [signer: TypedAbiArg<string, 'signer'>],
        Uint8Array | null
      >,
      getSignerKey: {
        name: 'get-signer-key',
        access: 'read_only',
        args: [{ name: 'staker', type: 'principal' }],
        outputs: { type: { optional: { buffer: { length: 33 } } } },
      } as TypedAbiFunction<
        [staker: TypedAbiArg<string, 'staker'>],
        Uint8Array | null
      >,
      getSignerPendingStakedUstxPerCycle: {
        name: 'get-signer-pending-staked-ustx-per-cycle',
        access: 'read_only',
        args: [
          { name: 'signer', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          signer: TypedAbiArg<string, 'signer'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        bigint
      >,
      getSignerRewardsPaidForCycle: {
        name: 'get-signer-rewards-paid-for-cycle',
        access: 'read_only',
        args: [
          { name: 'signer', type: 'principal' },
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          signer: TypedAbiArg<string, 'signer'>,
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        bigint
      >,
      getSignerSharesStakedForCycle: {
        name: 'get-signer-shares-staked-for-cycle',
        access: 'read_only',
        args: [
          { name: 'signer', type: 'principal' },
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          signer: TypedAbiArg<string, 'signer'>,
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        bigint
      >,
      getStakerInfo: {
        name: 'get-staker-info',
        access: 'read_only',
        args: [{ name: 'staker', type: 'principal' }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'amount-ustx', type: 'uint128' },
                { name: 'first-reward-cycle', type: 'uint128' },
                { name: 'num-cycles', type: 'uint128' },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [staker: TypedAbiArg<string, 'staker'>],
        {
          amountUstx: bigint;
          firstRewardCycle: bigint;
          numCycles: bigint;
        } | null
      >,
      getStakerSetFirstItemForCycle: {
        name: 'get-staker-set-first-item-for-cycle',
        access: 'read_only',
        args: [{ name: 'cycle', type: 'uint128' }],
        outputs: { type: { optional: 'principal' } },
      } as TypedAbiFunction<
        [cycle: TypedAbiArg<number | bigint, 'cycle'>],
        string | null
      >,
      getStakerSetItemForCycle: {
        name: 'get-staker-set-item-for-cycle',
        access: 'read_only',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'next', type: { optional: 'principal' } },
                { name: 'prev', type: { optional: 'principal' } },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        {
          next: string | null;
          prev: string | null;
        } | null
      >,
      getStakerSetLastItemForCycle: {
        name: 'get-staker-set-last-item-for-cycle',
        access: 'read_only',
        args: [{ name: 'cycle', type: 'uint128' }],
        outputs: { type: { optional: 'principal' } },
      } as TypedAbiFunction<
        [cycle: TypedAbiArg<number | bigint, 'cycle'>],
        string | null
      >,
      getStakerSetNextItemForCycle: {
        name: 'get-staker-set-next-item-for-cycle',
        access: 'read_only',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: { type: { optional: 'principal' } },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        string | null
      >,
      getStakerSetPrevItemForCycle: {
        name: 'get-staker-set-prev-item-for-cycle',
        access: 'read_only',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: { type: { optional: 'principal' } },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        string | null
      >,
      getStakerSharesStakedForCycle: {
        name: 'get-staker-shares-staked-for-cycle',
        access: 'read_only',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
          { name: 'signer', type: 'principal' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
          signer: TypedAbiArg<string, 'signer'>,
        ],
        bigint
      >,
      getTotalSatsStaked: {
        name: 'get-total-sats-staked',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getTotalSatsStakedForBond: {
        name: 'get-total-sats-staked-for-bond',
        access: 'read_only',
        args: [{ name: 'bond-index', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>],
        bigint
      >,
      getTotalSharesStakedForCycle: {
        name: 'get-total-shares-staked-for-cycle',
        access: 'read_only',
        args: [
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        bigint
      >,
      getUstxDelegatedForCycle: {
        name: 'get-ustx-delegated-for-cycle',
        access: 'read_only',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        bigint
      >,
      isBondActiveAtHeight: {
        name: 'is-bond-active-at-height',
        access: 'read_only',
        args: [
          { name: 'bond-index', type: 'uint128' },
          { name: 'calculation-height', type: 'uint128' },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          bondIndex: TypedAbiArg<number | bigint, 'bondIndex'>,
          calculationHeight: TypedAbiArg<number | bigint, 'calculationHeight'>,
        ],
        boolean
      >,
      isInPreparePhase: {
        name: 'is-in-prepare-phase',
        access: 'read_only',
        args: [{ name: 'current-cycle', type: 'uint128' }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [currentCycle: TypedAbiArg<number | bigint, 'currentCycle'>],
        boolean
      >,
      minUstxForSatsAmount: {
        name: 'min-ustx-for-sats-amount',
        access: 'read_only',
        args: [
          { name: 'sats-amount', type: 'uint128' },
          { name: 'stx-value-ratio', type: 'uint128' },
          { name: 'min-ustx-ratio', type: 'uint128' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          satsAmount: TypedAbiArg<number | bigint, 'satsAmount'>,
          stxValueRatio: TypedAbiArg<number | bigint, 'stxValueRatio'>,
          minUstxRatio: TypedAbiArg<number | bigint, 'minUstxRatio'>,
        ],
        bigint
      >,
      rewardCycleToBurnHeight: {
        name: 'reward-cycle-to-burn-height',
        access: 'read_only',
        args: [{ name: 'cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [cycle: TypedAbiArg<number | bigint, 'cycle'>],
        bigint
      >,
      rewardCycleToUnlockHeight: {
        name: 'reward-cycle-to-unlock-height',
        access: 'read_only',
        args: [{ name: 'cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [cycle: TypedAbiArg<number | bigint, 'cycle'>],
        bigint
      >,
      stakerSetContainsForCycle: {
        name: 'staker-set-contains-for-cycle',
        access: 'read_only',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'cycle', type: 'uint128' },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
        ],
        boolean
      >,
      verifySignerKeyGrant: {
        name: 'verify-signer-key-grant',
        access: 'read_only',
        args: [
          { name: 'signer-manager', type: 'principal' },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          signerManager: TypedAbiArg<string, 'signerManager'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
        ],
        Response<boolean, bigint>
      >,
    },
    maps: {
      allowanceContractCallers: {
        name: 'allowance-contract-callers',
        key: {
          tuple: [
            { name: 'contract-caller', type: 'principal' },
            { name: 'sender', type: 'principal' },
          ],
        },
        value: { optional: 'uint128' },
      } as TypedAbiMap<
        {
          contractCaller: string;
          sender: string;
        },
        bigint | null
      >,
      protocolBondAllowances: {
        name: 'protocol-bond-allowances',
        key: {
          tuple: [
            { name: 'bond-index', type: 'uint128' },
            { name: 'staker', type: 'principal' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          bondIndex: number | bigint;
          staker: string;
        },
        bigint
      >,
      protocolBondMemberships: {
        name: 'protocol-bond-memberships',
        key: 'principal',
        value: {
          tuple: [
            { name: 'amount-ustx', type: 'uint128' },
            { name: 'bond-index', type: 'uint128' },
            { name: 'is-l1-lock', type: 'bool' },
            { name: 'signer', type: 'principal' },
          ],
        },
      } as TypedAbiMap<
        string,
        {
          amountUstx: bigint;
          bondIndex: bigint;
          isL1Lock: boolean;
          signer: string;
        }
      >,
      protocolBonds: {
        name: 'protocol-bonds',
        key: 'uint128',
        value: {
          tuple: [
            { name: 'early-unlock-admin', type: 'principal' },
            { name: 'early-unlock-signers', type: { buffer: { length: 683 } } },
            { name: 'min-ustx-ratio', type: 'uint128' },
            { name: 'stx-value-ratio', type: 'uint128' },
            { name: 'target-rate', type: 'uint128' },
          ],
        },
      } as TypedAbiMap<
        number | bigint,
        {
          earlyUnlockAdmin: string;
          earlyUnlockSigners: Uint8Array;
          minUstxRatio: bigint;
          stxValueRatio: bigint;
          targetRate: bigint;
        }
      >,
      protocolBondsTotalStaked: {
        name: 'protocol-bonds-total-staked',
        key: 'uint128',
        value: 'uint128',
      } as TypedAbiMap<number | bigint, bigint>,
      rewardsPerTokenForCycle: {
        name: 'rewards-per-token-for-cycle',
        key: {
          tuple: [
            { name: 'index', type: 'uint128' },
            { name: 'is-bond', type: 'bool' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          index: number | bigint;
          isBond: boolean;
        },
        bigint
      >,
      signerDelegatedPerCycle: {
        name: 'signer-delegated-per-cycle',
        key: {
          tuple: [
            { name: 'cycle', type: 'uint128' },
            { name: 'signer', type: 'principal' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          cycle: number | bigint;
          signer: string;
        },
        bigint
      >,
      signerKeyGrants: {
        name: 'signer-key-grants',
        key: {
          tuple: [
            { name: 'signer-key', type: { buffer: { length: 33 } } },
            { name: 'signer-manager', type: 'principal' },
          ],
        },
        value: 'bool',
      } as TypedAbiMap<
        {
          signerKey: Uint8Array;
          signerManager: string;
        },
        boolean
      >,
      signerPendingStakedUstxPerCycle: {
        name: 'signer-pending-staked-ustx-per-cycle',
        key: {
          tuple: [
            { name: 'cycle', type: 'uint128' },
            { name: 'signer', type: 'principal' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          cycle: number | bigint;
          signer: string;
        },
        bigint
      >,
      signerRewardsPaidForCycle: {
        name: 'signer-rewards-paid-for-cycle',
        key: {
          tuple: [
            { name: 'index', type: 'uint128' },
            { name: 'is-bond', type: 'bool' },
            { name: 'signer', type: 'principal' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          index: number | bigint;
          isBond: boolean;
          signer: string;
        },
        bigint
      >,
      signerSharesStakedForCycle: {
        name: 'signer-shares-staked-for-cycle',
        key: {
          tuple: [
            { name: 'index', type: 'uint128' },
            { name: 'is-bond', type: 'bool' },
            { name: 'signer', type: 'principal' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          index: number | bigint;
          isBond: boolean;
          signer: string;
        },
        bigint
      >,
      signers: {
        name: 'signers',
        key: 'principal',
        value: { buffer: { length: 33 } },
      } as TypedAbiMap<string, Uint8Array>,
      stakerInfo: {
        name: 'staker-info',
        key: 'principal',
        value: {
          tuple: [
            { name: 'amount-ustx', type: 'uint128' },
            { name: 'first-reward-cycle', type: 'uint128' },
            { name: 'num-cycles', type: 'uint128' },
          ],
        },
      } as TypedAbiMap<
        string,
        {
          amountUstx: bigint;
          firstRewardCycle: bigint;
          numCycles: bigint;
        }
      >,
      stakerSetLlFirstForCycle: {
        name: 'staker-set-ll-first-for-cycle',
        key: 'uint128',
        value: 'principal',
      } as TypedAbiMap<number | bigint, string>,
      stakerSetLlForCycle: {
        name: 'staker-set-ll-for-cycle',
        key: {
          tuple: [
            { name: 'cycle', type: 'uint128' },
            { name: 'staker', type: 'principal' },
          ],
        },
        value: {
          tuple: [
            { name: 'next', type: { optional: 'principal' } },
            { name: 'prev', type: { optional: 'principal' } },
          ],
        },
      } as TypedAbiMap<
        {
          cycle: number | bigint;
          staker: string;
        },
        {
          next: string | null;
          prev: string | null;
        }
      >,
      stakerSetLlLastForCycle: {
        name: 'staker-set-ll-last-for-cycle',
        key: 'uint128',
        value: 'principal',
      } as TypedAbiMap<number | bigint, string>,
      stakerSharesStakedForCycle: {
        name: 'staker-shares-staked-for-cycle',
        key: {
          tuple: [
            { name: 'index', type: 'uint128' },
            { name: 'is-bond', type: 'bool' },
            { name: 'signer', type: 'principal' },
            { name: 'staker', type: 'principal' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          index: number | bigint;
          isBond: boolean;
          signer: string;
          staker: string;
        },
        bigint
      >,
      stakerSignerCycleMemberships: {
        name: 'staker-signer-cycle-memberships',
        key: {
          tuple: [
            { name: 'cycle', type: 'uint128' },
            { name: 'staker', type: 'principal' },
          ],
        },
        value: {
          tuple: [
            { name: 'amount-ustx', type: 'uint128' },
            { name: 'signer', type: 'principal' },
          ],
        },
      } as TypedAbiMap<
        {
          cycle: number | bigint;
          staker: string;
        },
        {
          amountUstx: bigint;
          signer: string;
        }
      >,
      totalSharesStakedForCycle: {
        name: 'total-shares-staked-for-cycle',
        key: {
          tuple: [
            { name: 'index', type: 'uint128' },
            { name: 'is-bond', type: 'bool' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          index: number | bigint;
          isBond: boolean;
        },
        bigint
      >,
      usedSignerKeyAuthorizations: {
        name: 'used-signer-key-authorizations',
        key: {
          tuple: [
            { name: 'auth-id', type: 'uint128' },
            { name: 'max-amount', type: 'uint128' },
            { name: 'period', type: 'uint128' },
            {
              name: 'pox-addr',
              type: {
                optional: {
                  tuple: [
                    { name: 'hashbytes', type: { buffer: { length: 32 } } },
                    { name: 'version', type: { buffer: { length: 1 } } },
                  ],
                },
              },
            },
            { name: 'reward-cycle', type: 'uint128' },
            { name: 'signer-key', type: { buffer: { length: 33 } } },
            { name: 'topic', type: { 'string-ascii': { length: 14 } } },
          ],
        },
        value: 'bool',
      } as TypedAbiMap<
        {
          authId: number | bigint;
          maxAmount: number | bigint;
          period: number | bigint;
          poxAddr: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          } | null;
          rewardCycle: number | bigint;
          signerKey: Uint8Array;
          topic: string;
        },
        boolean
      >,
      usedSignerKeyGrants: {
        name: 'used-signer-key-grants',
        key: {
          tuple: [
            { name: 'auth-id', type: 'uint128' },
            { name: 'signer-key', type: { buffer: { length: 33 } } },
            { name: 'signer-manager', type: 'principal' },
          ],
        },
        value: 'bool',
      } as TypedAbiMap<
        {
          authId: number | bigint;
          signerKey: Uint8Array;
          signerManager: string;
        },
        boolean
      >,
      ustxDelegatedPerCycle: {
        name: 'ustx-delegated-per-cycle',
        key: 'uint128',
        value: 'uint128',
      } as TypedAbiMap<number | bigint, bigint>,
    },
    variables: {
      BOND_GAP_CYCLES: {
        name: 'BOND_GAP_CYCLES',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      BOND_LENGTH_CYCLES: {
        name: 'BOND_LENGTH_CYCLES',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_ACTIVE_BOND_NOT_INCLUDED: {
        name: 'ERR_ACTIVE_BOND_NOT_INCLUDED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_ALREADY_REGISTERED: {
        name: 'ERR_ALREADY_REGISTERED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_ALREADY_STAKED: {
        name: 'ERR_ALREADY_STAKED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_BOND_ALREADY_SETUP: {
        name: 'ERR_BOND_ALREADY_SETUP',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_BOND_NOT_ACTIVE: {
        name: 'ERR_BOND_NOT_ACTIVE',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_BOND_NOT_FOUND: {
        name: 'ERR_BOND_NOT_FOUND',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      eRR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK: {
        name: 'ERR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_CANNOT_SETUP_BOND_TOO_LATE: {
        name: 'ERR_CANNOT_SETUP_BOND_TOO_LATE',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_CANNOT_SETUP_BOND_TOO_SOON: {
        name: 'ERR_CANNOT_SETUP_BOND_TOO_SOON',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_DISTRIBUTION_ALREADY_COMPUTED: {
        name: 'ERR_DISTRIBUTION_ALREADY_COMPUTED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INSUFFICIENT_STX: {
        name: 'ERR_INSUFFICIENT_STX',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_BOND_PERIOD_ORDERING: {
        name: 'ERR_INVALID_BOND_PERIOD_ORDERING',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_NUM_CYCLES: {
        name: 'ERR_INVALID_NUM_CYCLES',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_POX_ADDRESS: {
        name: 'ERR_INVALID_POX_ADDRESS',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_SIGNATURE_PUBKEY: {
        name: 'ERR_INVALID_SIGNATURE_PUBKEY',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_SIGNATURE_RECOVER: {
        name: 'ERR_INVALID_SIGNATURE_RECOVER',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_START_BURN_HEIGHT: {
        name: 'ERR_INVALID_START_BURN_HEIGHT',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      eRR_L1_LOCKUP_NOT_FOUND: {
        name: 'ERR_L1_LOCKUP_NOT_FOUND',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_NOT_ALLOWLISTED: {
        name: 'ERR_NOT_ALLOWLISTED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_NOT_BOND_PARTICIPANT: {
        name: 'ERR_NOT_BOND_PARTICIPANT',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_NOT_STAKING: {
        name: 'ERR_NOT_STAKING',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_NO_CLAIMABLE_REWARDS: {
        name: 'ERR_NO_CLAIMABLE_REWARDS',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_NO_SBTC_BALANCE: {
        name: 'ERR_NO_SBTC_BALANCE',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH: {
        name: 'ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_SIGNER_AUTH_USED: {
        name: 'ERR_SIGNER_AUTH_USED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_SIGNER_KEY_GRANT_NOT_FOUND: {
        name: 'ERR_SIGNER_KEY_GRANT_NOT_FOUND',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH: {
        name: 'ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_SIGNER_KEY_GRANT_USED: {
        name: 'ERR_SIGNER_KEY_GRANT_USED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_SIGNER_NOT_FOUND: {
        name: 'ERR_SIGNER_NOT_FOUND',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_STAKER_ALREADY_ADDED: {
        name: 'ERR_STAKER_ALREADY_ADDED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_TOO_MUCH_SATS: {
        name: 'ERR_TOO_MUCH_SATS',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_UNAUTHORIZED: {
        name: 'ERR_UNAUTHORIZED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_UNAUTHORIZED_CALLER: {
        name: 'ERR_UNAUTHORIZED_CALLER',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_UNAUTHORIZED_SIGNER_REGISTRATION: {
        name: 'ERR_UNAUTHORIZED_SIGNER_REGISTRATION',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_UNSTAKE_IN_PREPARE_PHASE: {
        name: 'ERR_UNSTAKE_IN_PREPARE_PHASE',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      MAX_ADDRESS_VERSION: {
        name: 'MAX_ADDRESS_VERSION',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      mAX_ADDRESS_VERSION_BUFF_20: {
        name: 'MAX_ADDRESS_VERSION_BUFF_20',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      mAX_ADDRESS_VERSION_BUFF_32: {
        name: 'MAX_ADDRESS_VERSION_BUFF_32',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      MAX_NUM_CYCLES: {
        name: 'MAX_NUM_CYCLES',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      pOX_5_SIGNER_DOMAIN: {
        name: 'POX_5_SIGNER_DOMAIN',
        type: {
          tuple: [
            {
              name: 'chain-id',
              type: 'uint128',
            },
            {
              name: 'name',
              type: {
                'string-ascii': {
                  length: 12,
                },
              },
            },
            {
              name: 'version',
              type: {
                'string-ascii': {
                  length: 5,
                },
              },
            },
          ],
        },
        access: 'constant',
      } as TypedAbiVariable<{
        chainId: bigint;
        name: string;
        version: string;
      }>,
      PRECISION: {
        name: 'PRECISION',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      RESERVE_RATIO: {
        name: 'RESERVE_RATIO',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      SIGNER_SET_MIN_USTX: {
        name: 'SIGNER_SET_MIN_USTX',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      sIP018_MSG_PREFIX: {
        name: 'SIP018_MSG_PREFIX',
        type: {
          buffer: {
            length: 6,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      STACKS_ADDR_VERSION_MAINNET: {
        name: 'STACKS_ADDR_VERSION_MAINNET',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      STACKS_ADDR_VERSION_TESTNET: {
        name: 'STACKS_ADDR_VERSION_TESTNET',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      bondAdmin: {
        name: 'bond-admin',
        type: 'principal',
        access: 'variable',
      } as TypedAbiVariable<string>,
      configured: {
        name: 'configured',
        type: 'bool',
        access: 'variable',
      } as TypedAbiVariable<boolean>,
      firstBondPeriodCycle: {
        name: 'first-bond-period-cycle',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      firstBurnchainBlockHeight: {
        name: 'first-burnchain-block-height',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      firstPox5RewardCycle: {
        name: 'first-pox-5-reward-cycle',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      lastAccountedRewardsOnly: {
        name: 'last-accounted-rewards-only',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      lastRewardComputeHeight: {
        name: 'last-reward-compute-height',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      poxPrepareCycleLength: {
        name: 'pox-prepare-cycle-length',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      poxRewardCycleLength: {
        name: 'pox-reward-cycle-length',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      reserveBalance: {
        name: 'reserve-balance',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      totalSatsStaked: {
        name: 'total-sats-staked',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      BOND_GAP_CYCLES: 2n,
      BOND_LENGTH_CYCLES: 12n,
      ERR_ACTIVE_BOND_NOT_INCLUDED: {
        isOk: false,
        value: 33n,
      },
      ERR_ALREADY_REGISTERED: {
        isOk: false,
        value: 9n,
      },
      ERR_ALREADY_STAKED: {
        isOk: false,
        value: 19n,
      },
      ERR_BOND_ALREADY_SETUP: {
        isOk: false,
        value: 4n,
      },
      ERR_BOND_NOT_ACTIVE: {
        isOk: false,
        value: 31n,
      },
      ERR_BOND_NOT_FOUND: {
        isOk: false,
        value: 7n,
      },
      eRR_CANNOT_ANNOUNCE_L1_EARLY_UNLOCK: {
        isOk: false,
        value: 35n,
      },
      ERR_CANNOT_SETUP_BOND_TOO_LATE: {
        isOk: false,
        value: 3n,
      },
      ERR_CANNOT_SETUP_BOND_TOO_SOON: {
        isOk: false,
        value: 2n,
      },
      ERR_DISTRIBUTION_ALREADY_COMPUTED: {
        isOk: false,
        value: 30n,
      },
      ERR_INSUFFICIENT_STX: {
        isOk: false,
        value: 8n,
      },
      ERR_INVALID_BOND_PERIOD_ORDERING: {
        isOk: false,
        value: 29n,
      },
      ERR_INVALID_NUM_CYCLES: {
        isOk: false,
        value: 20n,
      },
      ERR_INVALID_POX_ADDRESS: {
        isOk: false,
        value: 21n,
      },
      ERR_INVALID_SIGNATURE_PUBKEY: {
        isOk: false,
        value: 14n,
      },
      ERR_INVALID_SIGNATURE_RECOVER: {
        isOk: false,
        value: 13n,
      },
      ERR_INVALID_START_BURN_HEIGHT: {
        isOk: false,
        value: 24n,
      },
      eRR_L1_LOCKUP_NOT_FOUND: {
        isOk: false,
        value: 6n,
      },
      ERR_NOT_ALLOWLISTED: {
        isOk: false,
        value: 11n,
      },
      ERR_NOT_BOND_PARTICIPANT: {
        isOk: false,
        value: 34n,
      },
      ERR_NOT_STAKING: {
        isOk: false,
        value: 27n,
      },
      ERR_NO_CLAIMABLE_REWARDS: {
        isOk: false,
        value: 32n,
      },
      ERR_NO_SBTC_BALANCE: {
        isOk: false,
        value: 25n,
      },
      ERR_SIGNER_AUTH_AMOUNT_TOO_HIGH: {
        isOk: false,
        value: 15n,
      },
      ERR_SIGNER_AUTH_USED: {
        isOk: false,
        value: 16n,
      },
      ERR_SIGNER_KEY_GRANT_NOT_FOUND: {
        isOk: false,
        value: 17n,
      },
      ERR_SIGNER_KEY_GRANT_POX_ADDR_MISMATCH: {
        isOk: false,
        value: 18n,
      },
      ERR_SIGNER_KEY_GRANT_USED: {
        isOk: false,
        value: 12n,
      },
      ERR_SIGNER_NOT_FOUND: {
        isOk: false,
        value: 23n,
      },
      ERR_STAKER_ALREADY_ADDED: {
        isOk: false,
        value: 5n,
      },
      ERR_TOO_MUCH_SATS: {
        isOk: false,
        value: 10n,
      },
      ERR_UNAUTHORIZED: {
        isOk: false,
        value: 1n,
      },
      ERR_UNAUTHORIZED_CALLER: {
        isOk: false,
        value: 22n,
      },
      ERR_UNAUTHORIZED_SIGNER_REGISTRATION: {
        isOk: false,
        value: 26n,
      },
      ERR_UNSTAKE_IN_PREPARE_PHASE: {
        isOk: false,
        value: 28n,
      },
      MAX_ADDRESS_VERSION: 6n,
      mAX_ADDRESS_VERSION_BUFF_20: 4n,
      mAX_ADDRESS_VERSION_BUFF_32: 6n,
      MAX_NUM_CYCLES: 96n,
      pOX_5_SIGNER_DOMAIN: {
        chainId: 2_147_483_648n,
        name: 'pox-5-signer',
        version: '1.0.0',
      },
      PRECISION: 1_000_000_000_000_000_000n,
      RESERVE_RATIO: 1_500n,
      SIGNER_SET_MIN_USTX: 50_000_000_000n,
      sIP018_MSG_PREFIX: Uint8Array.from([83, 73, 80, 48, 49, 56]),
      STACKS_ADDR_VERSION_MAINNET: Uint8Array.from([22]),
      STACKS_ADDR_VERSION_TESTNET: Uint8Array.from([26]),
      bondAdmin: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
      configured: false,
      firstBondPeriodCycle: 0n,
      firstBurnchainBlockHeight: 0n,
      firstPox5RewardCycle: 0n,
      lastAccountedRewardsOnly: 0n,
      lastRewardComputeHeight: 0n,
      poxPrepareCycleLength: 50n,
      poxRewardCycleLength: 1_050n,
      reserveBalance: 0n,
      totalSatsStaked: 0n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch33',
    clarity_version: 'Clarity4',
    contractName: 'pox-5',
  },
  pox_4_test: {
    functions: {
      checkPoxAddrHashbytesIter: {
        name: 'check-pox-addr-hashbytes-iter',
        access: 'private',
        args: [
          { name: 'test-length', type: 'uint128' },
          { name: 'version', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          testLength: TypedAbiArg<number | bigint, 'testLength'>,
          version: TypedAbiArg<Uint8Array, 'version'>,
        ],
        boolean
      >,
      checkPoxAddrVersionIter: {
        name: 'check-pox-addr-version-iter',
        access: 'private',
        args: [{ name: 'input', type: { buffer: { length: 1 } } }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<[input: TypedAbiArg<Uint8Array, 'input'>], boolean>,
      checkPoxLockPeriodIter: {
        name: 'check-pox-lock-period-iter',
        access: 'private',
        args: [{ name: 'period', type: 'uint128' }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [period: TypedAbiArg<number | bigint, 'period'>],
        boolean
      >,
      repeatIter: {
        name: 'repeat-iter',
        access: 'private',
        args: [
          { name: 'a', type: { buffer: { length: 1 } } },
          {
            name: 'repeat',
            type: {
              tuple: [
                { name: 'i', type: { buffer: { length: 1 } } },
                { name: 'o', type: { buffer: { length: 33 } } },
              ],
            },
          },
        ],
        outputs: {
          type: {
            tuple: [
              { name: 'i', type: { buffer: { length: 1 } } },
              { name: 'o', type: { buffer: { length: 33 } } },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          a: TypedAbiArg<Uint8Array, 'a'>,
          repeat: TypedAbiArg<
            {
              i: Uint8Array;
              o: Uint8Array;
            },
            'repeat'
          >,
        ],
        {
          i: Uint8Array;
          o: Uint8Array;
        }
      >,
      testBurnHeightToRewardCycle: {
        name: 'test-burn-height-to-reward-cycle',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: { ok: 'bool', error: { 'string-ascii': { length: 48 } } },
          },
        },
      } as TypedAbiFunction<[], Response<boolean, string>>,
      testCheckPoxAddrVersion: {
        name: 'test-check-pox-addr-version',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: { ok: 'bool', error: { 'string-ascii': { length: 41 } } },
          },
        },
      } as TypedAbiFunction<[], Response<boolean, string>>,
      testCheckPoxLockPeriod: {
        name: 'test-check-pox-lock-period',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: {
              ok: 'bool',
              error: {
                tuple: [
                  {
                    name: 'actual',
                    type: { list: { type: 'bool', length: 14 } },
                  },
                  { name: 'err', type: { 'string-ascii': { length: 46 } } },
                ],
              },
            },
          },
        },
      } as TypedAbiFunction<
        [],
        Response<
          boolean,
          {
            actual: boolean[];
            err: string;
          }
        >
      >,
      testGetStackerInfoNone: {
        name: 'test-get-stacker-info-none',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: { ok: 'bool', error: { 'string-ascii': { length: 50 } } },
          },
        },
      } as TypedAbiFunction<[], Response<boolean, string>>,
      testGetTotalUstxStacked: {
        name: 'test-get-total-ustx-stacked',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: { ok: 'bool', error: { 'string-ascii': { length: 30 } } },
          },
        },
      } as TypedAbiFunction<[], Response<boolean, string>>,
      testInvalidPoxAddrHashbytesLength: {
        name: 'test-invalid-pox-addr-hashbytes-length',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: { ok: 'bool', error: { 'string-ascii': { length: 47 } } },
          },
        },
      } as TypedAbiFunction<[], Response<boolean, string>>,
      testRewardCycleToBurnHeight: {
        name: 'test-reward-cycle-to-burn-height',
        access: 'public',
        args: [],
        outputs: {
          type: {
            response: { ok: 'bool', error: { 'string-ascii': { length: 53 } } },
          },
        },
      } as TypedAbiFunction<[], Response<boolean, string>>,
      buffRepeat: {
        name: 'buff-repeat',
        access: 'read_only',
        args: [
          { name: 'repeat', type: { buffer: { length: 1 } } },
          { name: 'times', type: 'uint128' },
        ],
        outputs: { type: { buffer: { length: 33 } } },
      } as TypedAbiFunction<
        [
          repeat: TypedAbiArg<Uint8Array, 'repeat'>,
          times: TypedAbiArg<number | bigint, 'times'>,
        ],
        Uint8Array
      >,
    },
    maps: {},
    variables: {
      byteList: {
        name: 'byte-list',
        type: {
          buffer: {
            length: 256,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
    },
    constants: {
      byteList: Uint8Array.from([
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37,
        38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
        74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91,
        92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
        108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
        122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135,
        136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149,
        150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163,
        164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177,
        178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
        192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205,
        206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219,
        220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233,
        234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247,
        248, 249, 250, 251, 252, 253, 254, 255,
      ]),
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch24',
    clarity_version: 'Clarity2',
    contractName: 'pox_4_test',
  },
  sbtcDeposit: {
    functions: {
      completeIndividualDepositsHelper: {
        name: 'complete-individual-deposits-helper',
        access: 'private',
        args: [
          {
            name: 'deposit',
            type: {
              tuple: [
                { name: 'amount', type: 'uint128' },
                { name: 'burn-hash', type: { buffer: { length: 32 } } },
                { name: 'burn-height', type: 'uint128' },
                { name: 'recipient', type: 'principal' },
                { name: 'sweep-txid', type: { buffer: { length: 32 } } },
                { name: 'txid', type: { buffer: { length: 32 } } },
                { name: 'vout-index', type: 'uint128' },
              ],
            },
          },
          {
            name: 'helper-response',
            type: { response: { ok: 'uint128', error: 'uint128' } },
          },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          deposit: TypedAbiArg<
            {
              amount: number | bigint;
              burnHash: Uint8Array;
              burnHeight: number | bigint;
              recipient: string;
              sweepTxid: Uint8Array;
              txid: Uint8Array;
              voutIndex: number | bigint;
            },
            'deposit'
          >,
          helperResponse: TypedAbiArg<
            Response<number | bigint, number | bigint>,
            'helperResponse'
          >,
        ],
        Response<bigint, bigint>
      >,
      completeDepositWrapper: {
        name: 'complete-deposit-wrapper',
        access: 'public',
        args: [
          { name: 'txid', type: { buffer: { length: 32 } } },
          { name: 'vout-index', type: 'uint128' },
          { name: 'amount', type: 'uint128' },
          { name: 'recipient', type: 'principal' },
          { name: 'burn-hash', type: { buffer: { length: 32 } } },
          { name: 'burn-height', type: 'uint128' },
          { name: 'sweep-txid', type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, 'txid'>,
          voutIndex: TypedAbiArg<number | bigint, 'voutIndex'>,
          amount: TypedAbiArg<number | bigint, 'amount'>,
          recipient: TypedAbiArg<string, 'recipient'>,
          burnHash: TypedAbiArg<Uint8Array, 'burnHash'>,
          burnHeight: TypedAbiArg<number | bigint, 'burnHeight'>,
          sweepTxid: TypedAbiArg<Uint8Array, 'sweepTxid'>,
        ],
        Response<boolean, bigint>
      >,
      completeDepositsWrapper: {
        name: 'complete-deposits-wrapper',
        access: 'public',
        args: [
          {
            name: 'deposits',
            type: {
              list: {
                type: {
                  tuple: [
                    { name: 'amount', type: 'uint128' },
                    { name: 'burn-hash', type: { buffer: { length: 32 } } },
                    { name: 'burn-height', type: 'uint128' },
                    { name: 'recipient', type: 'principal' },
                    { name: 'sweep-txid', type: { buffer: { length: 32 } } },
                    { name: 'txid', type: { buffer: { length: 32 } } },
                    { name: 'vout-index', type: 'uint128' },
                  ],
                },
                length: 500,
              },
            },
          },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          deposits: TypedAbiArg<
            {
              amount: number | bigint;
              burnHash: Uint8Array;
              burnHeight: number | bigint;
              recipient: string;
              sweepTxid: Uint8Array;
              txid: Uint8Array;
              voutIndex: number | bigint;
            }[],
            'deposits'
          >,
        ],
        Response<bigint, bigint>
      >,
      getBurnHeader: {
        name: 'get-burn-header',
        access: 'read_only',
        args: [{ name: 'height', type: 'uint128' }],
        outputs: { type: { optional: { buffer: { length: 32 } } } },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, 'height'>],
        Uint8Array | null
      >,
    },
    maps: {},
    variables: {
      ERR_DEPOSIT: {
        name: 'ERR_DEPOSIT',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_DEPOSIT_INDEX_PREFIX: {
        name: 'ERR_DEPOSIT_INDEX_PREFIX',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_DEPOSIT_REPLAY: {
        name: 'ERR_DEPOSIT_REPLAY',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_BURN_HASH: {
        name: 'ERR_INVALID_BURN_HASH',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_CALLER: {
        name: 'ERR_INVALID_CALLER',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_LOWER_THAN_DUST: {
        name: 'ERR_LOWER_THAN_DUST',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_TXID_LEN: {
        name: 'ERR_TXID_LEN',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      depositRole: {
        name: 'deposit-role',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      dustLimit: {
        name: 'dust-limit',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      txidLength: {
        name: 'txid-length',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
    },
    constants: {},
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch30',
    clarity_version: 'Clarity3',
    contractName: 'sbtc-deposit',
  },
  sbtcRegistry: {
    functions: {
      incrementLastWithdrawalRequestId: {
        name: 'increment-last-withdrawal-request-id',
        access: 'private',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      completeDeposit: {
        name: 'complete-deposit',
        access: 'public',
        args: [
          { name: 'txid', type: { buffer: { length: 32 } } },
          { name: 'vout-index', type: 'uint128' },
          { name: 'amount', type: 'uint128' },
          { name: 'recipient', type: 'principal' },
          { name: 'burn-hash', type: { buffer: { length: 32 } } },
          { name: 'burn-height', type: 'uint128' },
          { name: 'sweep-txid', type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, 'txid'>,
          voutIndex: TypedAbiArg<number | bigint, 'voutIndex'>,
          amount: TypedAbiArg<number | bigint, 'amount'>,
          recipient: TypedAbiArg<string, 'recipient'>,
          burnHash: TypedAbiArg<Uint8Array, 'burnHash'>,
          burnHeight: TypedAbiArg<number | bigint, 'burnHeight'>,
          sweepTxid: TypedAbiArg<Uint8Array, 'sweepTxid'>,
        ],
        Response<boolean, bigint>
      >,
      completeWithdrawalAccept: {
        name: 'complete-withdrawal-accept',
        access: 'public',
        args: [
          { name: 'request-id', type: 'uint128' },
          { name: 'bitcoin-txid', type: { buffer: { length: 32 } } },
          { name: 'output-index', type: 'uint128' },
          { name: 'signer-bitmap', type: 'uint128' },
          { name: 'fee', type: 'uint128' },
          { name: 'burn-hash', type: { buffer: { length: 32 } } },
          { name: 'burn-height', type: 'uint128' },
          { name: 'sweep-txid', type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          requestId: TypedAbiArg<number | bigint, 'requestId'>,
          bitcoinTxid: TypedAbiArg<Uint8Array, 'bitcoinTxid'>,
          outputIndex: TypedAbiArg<number | bigint, 'outputIndex'>,
          signerBitmap: TypedAbiArg<number | bigint, 'signerBitmap'>,
          fee: TypedAbiArg<number | bigint, 'fee'>,
          burnHash: TypedAbiArg<Uint8Array, 'burnHash'>,
          burnHeight: TypedAbiArg<number | bigint, 'burnHeight'>,
          sweepTxid: TypedAbiArg<Uint8Array, 'sweepTxid'>,
        ],
        Response<boolean, bigint>
      >,
      completeWithdrawalReject: {
        name: 'complete-withdrawal-reject',
        access: 'public',
        args: [
          { name: 'request-id', type: 'uint128' },
          { name: 'signer-bitmap', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          requestId: TypedAbiArg<number | bigint, 'requestId'>,
          signerBitmap: TypedAbiArg<number | bigint, 'signerBitmap'>,
        ],
        Response<boolean, bigint>
      >,
      createWithdrawalRequest: {
        name: 'create-withdrawal-request',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          { name: 'max-fee', type: 'uint128' },
          { name: 'sender', type: 'principal' },
          {
            name: 'recipient',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'height', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          maxFee: TypedAbiArg<number | bigint, 'maxFee'>,
          sender: TypedAbiArg<string, 'sender'>,
          recipient: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'recipient'
          >,
          height: TypedAbiArg<number | bigint, 'height'>,
        ],
        Response<bigint, bigint>
      >,
      rotateKeys: {
        name: 'rotate-keys',
        access: 'public',
        args: [
          {
            name: 'new-keys',
            type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
          },
          { name: 'new-address', type: 'principal' },
          { name: 'new-aggregate-pubkey', type: { buffer: { length: 33 } } },
          { name: 'new-signature-threshold', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          newKeys: TypedAbiArg<Uint8Array[], 'newKeys'>,
          newAddress: TypedAbiArg<string, 'newAddress'>,
          newAggregatePubkey: TypedAbiArg<Uint8Array, 'newAggregatePubkey'>,
          newSignatureThreshold: TypedAbiArg<
            number | bigint,
            'newSignatureThreshold'
          >,
        ],
        Response<boolean, bigint>
      >,
      updateProtocolContract: {
        name: 'update-protocol-contract',
        access: 'public',
        args: [
          { name: 'contract-type', type: { buffer: { length: 1 } } },
          { name: 'new-contract', type: 'principal' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          contractType: TypedAbiArg<Uint8Array, 'contractType'>,
          newContract: TypedAbiArg<string, 'newContract'>,
        ],
        Response<boolean, bigint>
      >,
      getActiveProtocol: {
        name: 'get-active-protocol',
        access: 'read_only',
        args: [{ name: 'contract-flag', type: { buffer: { length: 1 } } }],
        outputs: { type: { optional: 'principal' } },
      } as TypedAbiFunction<
        [contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>],
        string | null
      >,
      getCompletedDeposit: {
        name: 'get-completed-deposit',
        access: 'read_only',
        args: [
          { name: 'txid', type: { buffer: { length: 32 } } },
          { name: 'vout-index', type: 'uint128' },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'amount', type: 'uint128' },
                { name: 'recipient', type: 'principal' },
                { name: 'sweep-burn-hash', type: { buffer: { length: 32 } } },
                { name: 'sweep-burn-height', type: 'uint128' },
                { name: 'sweep-txid', type: { buffer: { length: 32 } } },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, 'txid'>,
          voutIndex: TypedAbiArg<number | bigint, 'voutIndex'>,
        ],
        {
          amount: bigint;
          recipient: string;
          sweepBurnHash: Uint8Array;
          sweepBurnHeight: bigint;
          sweepTxid: Uint8Array;
        } | null
      >,
      getCompletedWithdrawalSweepData: {
        name: 'get-completed-withdrawal-sweep-data',
        access: 'read_only',
        args: [{ name: 'id', type: 'uint128' }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'sweep-burn-hash', type: { buffer: { length: 32 } } },
                { name: 'sweep-burn-height', type: 'uint128' },
                { name: 'sweep-txid', type: { buffer: { length: 32 } } },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [id: TypedAbiArg<number | bigint, 'id'>],
        {
          sweepBurnHash: Uint8Array;
          sweepBurnHeight: bigint;
          sweepTxid: Uint8Array;
        } | null
      >,
      getCurrentAggregatePubkey: {
        name: 'get-current-aggregate-pubkey',
        access: 'read_only',
        args: [],
        outputs: { type: { buffer: { length: 33 } } },
      } as TypedAbiFunction<[], Uint8Array>,
      getCurrentSignerData: {
        name: 'get-current-signer-data',
        access: 'read_only',
        args: [],
        outputs: {
          type: {
            tuple: [
              {
                name: 'current-aggregate-pubkey',
                type: { buffer: { length: 33 } },
              },
              { name: 'current-signature-threshold', type: 'uint128' },
              { name: 'current-signer-principal', type: 'principal' },
              {
                name: 'current-signer-set',
                type: {
                  list: { type: { buffer: { length: 33 } }, length: 128 },
                },
              },
            ],
          },
        },
      } as TypedAbiFunction<
        [],
        {
          currentAggregatePubkey: Uint8Array;
          currentSignatureThreshold: bigint;
          currentSignerPrincipal: string;
          currentSignerSet: Uint8Array[];
        }
      >,
      getCurrentSignerPrincipal: {
        name: 'get-current-signer-principal',
        access: 'read_only',
        args: [],
        outputs: { type: 'principal' },
      } as TypedAbiFunction<[], string>,
      getCurrentSignerSet: {
        name: 'get-current-signer-set',
        access: 'read_only',
        args: [],
        outputs: {
          type: { list: { type: { buffer: { length: 33 } }, length: 128 } },
        },
      } as TypedAbiFunction<[], Uint8Array[]>,
      getDepositStatus: {
        name: 'get-deposit-status',
        access: 'read_only',
        args: [
          { name: 'txid', type: { buffer: { length: 32 } } },
          { name: 'vout-index', type: 'uint128' },
        ],
        outputs: { type: { optional: 'bool' } },
      } as TypedAbiFunction<
        [
          txid: TypedAbiArg<Uint8Array, 'txid'>,
          voutIndex: TypedAbiArg<number | bigint, 'voutIndex'>,
        ],
        boolean | null
      >,
      getWithdrawalRequest: {
        name: 'get-withdrawal-request',
        access: 'read_only',
        args: [{ name: 'id', type: 'uint128' }],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'amount', type: 'uint128' },
                { name: 'block-height', type: 'uint128' },
                { name: 'max-fee', type: 'uint128' },
                {
                  name: 'recipient',
                  type: {
                    tuple: [
                      { name: 'hashbytes', type: { buffer: { length: 32 } } },
                      { name: 'version', type: { buffer: { length: 1 } } },
                    ],
                  },
                },
                { name: 'sender', type: 'principal' },
                { name: 'status', type: { optional: 'bool' } },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [id: TypedAbiArg<number | bigint, 'id'>],
        {
          amount: bigint;
          blockHeight: bigint;
          maxFee: bigint;
          recipient: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          sender: string;
          status: boolean | null;
        } | null
      >,
      isProtocolCaller: {
        name: 'is-protocol-caller',
        access: 'read_only',
        args: [
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
          { name: 'contract', type: 'principal' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
          contract: TypedAbiArg<string, 'contract'>,
        ],
        Response<boolean, bigint>
      >,
    },
    maps: {
      activeProtocolContracts: {
        name: 'active-protocol-contracts',
        key: { buffer: { length: 1 } },
        value: 'principal',
      } as TypedAbiMap<Uint8Array, string>,
      activeProtocolRoles: {
        name: 'active-protocol-roles',
        key: 'principal',
        value: { buffer: { length: 1 } },
      } as TypedAbiMap<string, Uint8Array>,
      aggregatePubkeys: {
        name: 'aggregate-pubkeys',
        key: { buffer: { length: 33 } },
        value: 'bool',
      } as TypedAbiMap<Uint8Array, boolean>,
      completedDeposits: {
        name: 'completed-deposits',
        key: {
          tuple: [
            { name: 'txid', type: { buffer: { length: 32 } } },
            { name: 'vout-index', type: 'uint128' },
          ],
        },
        value: {
          tuple: [
            { name: 'amount', type: 'uint128' },
            { name: 'recipient', type: 'principal' },
            { name: 'sweep-burn-hash', type: { buffer: { length: 32 } } },
            { name: 'sweep-burn-height', type: 'uint128' },
            { name: 'sweep-txid', type: { buffer: { length: 32 } } },
          ],
        },
      } as TypedAbiMap<
        {
          txid: Uint8Array;
          voutIndex: number | bigint;
        },
        {
          amount: bigint;
          recipient: string;
          sweepBurnHash: Uint8Array;
          sweepBurnHeight: bigint;
          sweepTxid: Uint8Array;
        }
      >,
      completedWithdrawalSweep: {
        name: 'completed-withdrawal-sweep',
        key: 'uint128',
        value: {
          tuple: [
            { name: 'sweep-burn-hash', type: { buffer: { length: 32 } } },
            { name: 'sweep-burn-height', type: 'uint128' },
            { name: 'sweep-txid', type: { buffer: { length: 32 } } },
          ],
        },
      } as TypedAbiMap<
        number | bigint,
        {
          sweepBurnHash: Uint8Array;
          sweepBurnHeight: bigint;
          sweepTxid: Uint8Array;
        }
      >,
      depositStatus: {
        name: 'deposit-status',
        key: {
          tuple: [
            { name: 'txid', type: { buffer: { length: 32 } } },
            { name: 'vout-index', type: 'uint128' },
          ],
        },
        value: 'bool',
      } as TypedAbiMap<
        {
          txid: Uint8Array;
          voutIndex: number | bigint;
        },
        boolean
      >,
      withdrawalRequests: {
        name: 'withdrawal-requests',
        key: 'uint128',
        value: {
          tuple: [
            { name: 'amount', type: 'uint128' },
            { name: 'block-height', type: 'uint128' },
            { name: 'max-fee', type: 'uint128' },
            {
              name: 'recipient',
              type: {
                tuple: [
                  { name: 'hashbytes', type: { buffer: { length: 32 } } },
                  { name: 'version', type: { buffer: { length: 1 } } },
                ],
              },
            },
            { name: 'sender', type: 'principal' },
          ],
        },
      } as TypedAbiMap<
        number | bigint,
        {
          amount: bigint;
          blockHeight: bigint;
          maxFee: bigint;
          recipient: {
            hashbytes: Uint8Array;
            version: Uint8Array;
          };
          sender: string;
        }
      >,
      withdrawalStatus: {
        name: 'withdrawal-status',
        key: 'uint128',
        value: 'bool',
      } as TypedAbiMap<number | bigint, boolean>,
    },
    variables: {
      ERR_AGG_PUBKEY_REPLAY: {
        name: 'ERR_AGG_PUBKEY_REPLAY',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_REQUEST_ID: {
        name: 'ERR_INVALID_REQUEST_ID',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_UNAUTHORIZED: {
        name: 'ERR_UNAUTHORIZED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      depositRole: {
        name: 'deposit-role',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      governanceRole: {
        name: 'governance-role',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      withdrawalRole: {
        name: 'withdrawal-role',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
      currentAggregatePubkey: {
        name: 'current-aggregate-pubkey',
        type: {
          buffer: {
            length: 33,
          },
        },
        access: 'variable',
      } as TypedAbiVariable<Uint8Array>,
      currentSignatureThreshold: {
        name: 'current-signature-threshold',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      currentSignerPrincipal: {
        name: 'current-signer-principal',
        type: 'principal',
        access: 'variable',
      } as TypedAbiVariable<string>,
      currentSignerSet: {
        name: 'current-signer-set',
        type: {
          list: {
            type: {
              buffer: {
                length: 33,
              },
            },
            length: 128,
          },
        },
        access: 'variable',
      } as TypedAbiVariable<Uint8Array[]>,
      lastWithdrawalRequestId: {
        name: 'last-withdrawal-request-id',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
    },
    constants: {},
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch30',
    clarity_version: 'Clarity3',
    contractName: 'sbtc-registry',
  },
  sbtcToken: {
    functions: {
      protocolMintManyIter: {
        name: 'protocol-mint-many-iter',
        access: 'private',
        args: [
          {
            name: 'item',
            type: {
              tuple: [
                { name: 'amount', type: 'uint128' },
                { name: 'recipient', type: 'principal' },
              ],
            },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          item: TypedAbiArg<
            {
              amount: number | bigint;
              recipient: string;
            },
            'item'
          >,
        ],
        Response<boolean, bigint>
      >,
      transferManyIter: {
        name: 'transfer-many-iter',
        access: 'private',
        args: [
          {
            name: 'individual-transfer',
            type: {
              tuple: [
                { name: 'amount', type: 'uint128' },
                {
                  name: 'memo',
                  type: { optional: { buffer: { length: 34 } } },
                },
                { name: 'sender', type: 'principal' },
                { name: 'to', type: 'principal' },
              ],
            },
          },
          {
            name: 'result',
            type: { response: { ok: 'uint128', error: 'uint128' } },
          },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          individualTransfer: TypedAbiArg<
            {
              amount: number | bigint;
              memo: Uint8Array | null;
              sender: string;
              to: string;
            },
            'individualTransfer'
          >,
          result: TypedAbiArg<
            Response<number | bigint, number | bigint>,
            'result'
          >,
        ],
        Response<bigint, bigint>
      >,
      protocolBurn: {
        name: 'protocol-burn',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          { name: 'owner', type: 'principal' },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          owner: TypedAbiArg<string, 'owner'>,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<boolean, bigint>
      >,
      protocolBurnLocked: {
        name: 'protocol-burn-locked',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          { name: 'owner', type: 'principal' },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          owner: TypedAbiArg<string, 'owner'>,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<boolean, bigint>
      >,
      protocolLock: {
        name: 'protocol-lock',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          { name: 'owner', type: 'principal' },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          owner: TypedAbiArg<string, 'owner'>,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<boolean, bigint>
      >,
      protocolMint: {
        name: 'protocol-mint',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          { name: 'recipient', type: 'principal' },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          recipient: TypedAbiArg<string, 'recipient'>,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<boolean, bigint>
      >,
      protocolMintMany: {
        name: 'protocol-mint-many',
        access: 'public',
        args: [
          {
            name: 'recipients',
            type: {
              list: {
                type: {
                  tuple: [
                    { name: 'amount', type: 'uint128' },
                    { name: 'recipient', type: 'principal' },
                  ],
                },
                length: 200,
              },
            },
          },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                list: {
                  type: { response: { ok: 'bool', error: 'uint128' } },
                  length: 200,
                },
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          recipients: TypedAbiArg<
            {
              amount: number | bigint;
              recipient: string;
            }[],
            'recipients'
          >,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<Response<boolean, bigint>[], bigint>
      >,
      protocolSetName: {
        name: 'protocol-set-name',
        access: 'public',
        args: [
          { name: 'new-name', type: { 'string-ascii': { length: 32 } } },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          newName: TypedAbiArg<string, 'newName'>,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<boolean, bigint>
      >,
      protocolSetSymbol: {
        name: 'protocol-set-symbol',
        access: 'public',
        args: [
          { name: 'new-symbol', type: { 'string-ascii': { length: 10 } } },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          newSymbol: TypedAbiArg<string, 'newSymbol'>,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<boolean, bigint>
      >,
      protocolSetTokenUri: {
        name: 'protocol-set-token-uri',
        access: 'public',
        args: [
          {
            name: 'new-uri',
            type: { optional: { 'string-utf8': { length: 256 } } },
          },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          newUri: TypedAbiArg<string | null, 'newUri'>,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<boolean, bigint>
      >,
      protocolUnlock: {
        name: 'protocol-unlock',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          { name: 'owner', type: 'principal' },
          { name: 'contract-flag', type: { buffer: { length: 1 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          owner: TypedAbiArg<string, 'owner'>,
          contractFlag: TypedAbiArg<Uint8Array, 'contractFlag'>,
        ],
        Response<boolean, bigint>
      >,
      transfer: {
        name: 'transfer',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          { name: 'sender', type: 'principal' },
          { name: 'recipient', type: 'principal' },
          { name: 'memo', type: { optional: { buffer: { length: 34 } } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          sender: TypedAbiArg<string, 'sender'>,
          recipient: TypedAbiArg<string, 'recipient'>,
          memo: TypedAbiArg<Uint8Array | null, 'memo'>,
        ],
        Response<boolean, bigint>
      >,
      transferMany: {
        name: 'transfer-many',
        access: 'public',
        args: [
          {
            name: 'recipients',
            type: {
              list: {
                type: {
                  tuple: [
                    { name: 'amount', type: 'uint128' },
                    {
                      name: 'memo',
                      type: { optional: { buffer: { length: 34 } } },
                    },
                    { name: 'sender', type: 'principal' },
                    { name: 'to', type: 'principal' },
                  ],
                },
                length: 200,
              },
            },
          },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          recipients: TypedAbiArg<
            {
              amount: number | bigint;
              memo: Uint8Array | null;
              sender: string;
              to: string;
            }[],
            'recipients'
          >,
        ],
        Response<bigint, bigint>
      >,
      getBalance: {
        name: 'get-balance',
        access: 'read_only',
        args: [{ name: 'who', type: 'principal' }],
        outputs: { type: { response: { ok: 'uint128', error: 'none' } } },
      } as TypedAbiFunction<
        [who: TypedAbiArg<string, 'who'>],
        Response<bigint, null>
      >,
      getBalanceAvailable: {
        name: 'get-balance-available',
        access: 'read_only',
        args: [{ name: 'who', type: 'principal' }],
        outputs: { type: { response: { ok: 'uint128', error: 'none' } } },
      } as TypedAbiFunction<
        [who: TypedAbiArg<string, 'who'>],
        Response<bigint, null>
      >,
      getBalanceLocked: {
        name: 'get-balance-locked',
        access: 'read_only',
        args: [{ name: 'who', type: 'principal' }],
        outputs: { type: { response: { ok: 'uint128', error: 'none' } } },
      } as TypedAbiFunction<
        [who: TypedAbiArg<string, 'who'>],
        Response<bigint, null>
      >,
      getDecimals: {
        name: 'get-decimals',
        access: 'read_only',
        args: [],
        outputs: { type: { response: { ok: 'uint128', error: 'none' } } },
      } as TypedAbiFunction<[], Response<bigint, null>>,
      getName: {
        name: 'get-name',
        access: 'read_only',
        args: [],
        outputs: {
          type: {
            response: { ok: { 'string-ascii': { length: 32 } }, error: 'none' },
          },
        },
      } as TypedAbiFunction<[], Response<string, null>>,
      getSymbol: {
        name: 'get-symbol',
        access: 'read_only',
        args: [],
        outputs: {
          type: {
            response: { ok: { 'string-ascii': { length: 10 } }, error: 'none' },
          },
        },
      } as TypedAbiFunction<[], Response<string, null>>,
      getTokenUri: {
        name: 'get-token-uri',
        access: 'read_only',
        args: [],
        outputs: {
          type: {
            response: {
              ok: { optional: { 'string-utf8': { length: 256 } } },
              error: 'none',
            },
          },
        },
      } as TypedAbiFunction<[], Response<string | null, null>>,
      getTotalSupply: {
        name: 'get-total-supply',
        access: 'read_only',
        args: [],
        outputs: { type: { response: { ok: 'uint128', error: 'none' } } },
      } as TypedAbiFunction<[], Response<bigint, null>>,
    },
    maps: {},
    variables: {
      ERR_NOT_OWNER: {
        name: 'ERR_NOT_OWNER',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_TRANSFER_INDEX_PREFIX: {
        name: 'ERR_TRANSFER_INDEX_PREFIX',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      tokenDecimals: {
        name: 'token-decimals',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      tokenName: {
        name: 'token-name',
        type: {
          'string-ascii': {
            length: 32,
          },
        },
        access: 'variable',
      } as TypedAbiVariable<string>,
      tokenSymbol: {
        name: 'token-symbol',
        type: {
          'string-ascii': {
            length: 10,
          },
        },
        access: 'variable',
      } as TypedAbiVariable<string>,
      tokenUri: {
        name: 'token-uri',
        type: {
          optional: {
            'string-utf8': {
              length: 256,
            },
          },
        },
        access: 'variable',
      } as TypedAbiVariable<string | null>,
    },
    constants: {},
    non_fungible_tokens: [],
    fungible_tokens: [{ name: 'sbtc-token' }, { name: 'sbtc-token-locked' }],
    epoch: 'Epoch30',
    clarity_version: 'Clarity3',
    contractName: 'sbtc-token',
  },
  sbtcWithdrawal: {
    functions: {
      completeIndividualWithdrawalHelper: {
        name: 'complete-individual-withdrawal-helper',
        access: 'private',
        args: [
          {
            name: 'withdrawal',
            type: {
              tuple: [
                {
                  name: 'bitcoin-txid',
                  type: { optional: { buffer: { length: 32 } } },
                },
                { name: 'burn-hash', type: { buffer: { length: 32 } } },
                { name: 'burn-height', type: 'uint128' },
                { name: 'fee', type: { optional: 'uint128' } },
                { name: 'output-index', type: { optional: 'uint128' } },
                { name: 'request-id', type: 'uint128' },
                { name: 'signer-bitmap', type: 'uint128' },
                { name: 'status', type: 'bool' },
                {
                  name: 'sweep-txid',
                  type: { optional: { buffer: { length: 32 } } },
                },
              ],
            },
          },
          {
            name: 'helper-response',
            type: { response: { ok: 'uint128', error: 'uint128' } },
          },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          withdrawal: TypedAbiArg<
            {
              bitcoinTxid: Uint8Array | null;
              burnHash: Uint8Array;
              burnHeight: number | bigint;
              fee: number | bigint | null;
              outputIndex: number | bigint | null;
              requestId: number | bigint;
              signerBitmap: number | bigint;
              status: boolean;
              sweepTxid: Uint8Array | null;
            },
            'withdrawal'
          >,
          helperResponse: TypedAbiArg<
            Response<number | bigint, number | bigint>,
            'helperResponse'
          >,
        ],
        Response<bigint, bigint>
      >,
      acceptWithdrawalRequest: {
        name: 'accept-withdrawal-request',
        access: 'public',
        args: [
          { name: 'request-id', type: 'uint128' },
          { name: 'bitcoin-txid', type: { buffer: { length: 32 } } },
          { name: 'signer-bitmap', type: 'uint128' },
          { name: 'output-index', type: 'uint128' },
          { name: 'fee', type: 'uint128' },
          { name: 'burn-hash', type: { buffer: { length: 32 } } },
          { name: 'burn-height', type: 'uint128' },
          { name: 'sweep-txid', type: { buffer: { length: 32 } } },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          requestId: TypedAbiArg<number | bigint, 'requestId'>,
          bitcoinTxid: TypedAbiArg<Uint8Array, 'bitcoinTxid'>,
          signerBitmap: TypedAbiArg<number | bigint, 'signerBitmap'>,
          outputIndex: TypedAbiArg<number | bigint, 'outputIndex'>,
          fee: TypedAbiArg<number | bigint, 'fee'>,
          burnHash: TypedAbiArg<Uint8Array, 'burnHash'>,
          burnHeight: TypedAbiArg<number | bigint, 'burnHeight'>,
          sweepTxid: TypedAbiArg<Uint8Array, 'sweepTxid'>,
        ],
        Response<boolean, bigint>
      >,
      completeWithdrawals: {
        name: 'complete-withdrawals',
        access: 'public',
        args: [
          {
            name: 'withdrawals',
            type: {
              list: {
                type: {
                  tuple: [
                    {
                      name: 'bitcoin-txid',
                      type: { optional: { buffer: { length: 32 } } },
                    },
                    { name: 'burn-hash', type: { buffer: { length: 32 } } },
                    { name: 'burn-height', type: 'uint128' },
                    { name: 'fee', type: { optional: 'uint128' } },
                    { name: 'output-index', type: { optional: 'uint128' } },
                    { name: 'request-id', type: 'uint128' },
                    { name: 'signer-bitmap', type: 'uint128' },
                    { name: 'status', type: 'bool' },
                    {
                      name: 'sweep-txid',
                      type: { optional: { buffer: { length: 32 } } },
                    },
                  ],
                },
                length: 600,
              },
            },
          },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          withdrawals: TypedAbiArg<
            {
              bitcoinTxid: Uint8Array | null;
              burnHash: Uint8Array;
              burnHeight: number | bigint;
              fee: number | bigint | null;
              outputIndex: number | bigint | null;
              requestId: number | bigint;
              signerBitmap: number | bigint;
              status: boolean;
              sweepTxid: Uint8Array | null;
            }[],
            'withdrawals'
          >,
        ],
        Response<bigint, bigint>
      >,
      initiateWithdrawalRequest: {
        name: 'initiate-withdrawal-request',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          {
            name: 'recipient',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
          { name: 'max-fee', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          recipient: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'recipient'
          >,
          maxFee: TypedAbiArg<number | bigint, 'maxFee'>,
        ],
        Response<bigint, bigint>
      >,
      rejectWithdrawalRequest: {
        name: 'reject-withdrawal-request',
        access: 'public',
        args: [
          { name: 'request-id', type: 'uint128' },
          { name: 'signer-bitmap', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          requestId: TypedAbiArg<number | bigint, 'requestId'>,
          signerBitmap: TypedAbiArg<number | bigint, 'signerBitmap'>,
        ],
        Response<boolean, bigint>
      >,
      getBurnHeader: {
        name: 'get-burn-header',
        access: 'read_only',
        args: [{ name: 'height', type: 'uint128' }],
        outputs: { type: { optional: { buffer: { length: 32 } } } },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, 'height'>],
        Uint8Array | null
      >,
      validateRecipient: {
        name: 'validate-recipient',
        access: 'read_only',
        args: [
          {
            name: 'recipient',
            type: {
              tuple: [
                { name: 'hashbytes', type: { buffer: { length: 32 } } },
                { name: 'version', type: { buffer: { length: 1 } } },
              ],
            },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          recipient: TypedAbiArg<
            {
              hashbytes: Uint8Array;
              version: Uint8Array;
            },
            'recipient'
          >,
        ],
        Response<boolean, bigint>
      >,
    },
    maps: {},
    variables: {
      DUST_LIMIT: {
        name: 'DUST_LIMIT',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_ALREADY_PROCESSED: {
        name: 'ERR_ALREADY_PROCESSED',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_DUST_LIMIT: {
        name: 'ERR_DUST_LIMIT',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_FEE_TOO_HIGH: {
        name: 'ERR_FEE_TOO_HIGH',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_ADDR_HASHBYTES: {
        name: 'ERR_INVALID_ADDR_HASHBYTES',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_ADDR_VERSION: {
        name: 'ERR_INVALID_ADDR_VERSION',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_BURN_HASH: {
        name: 'ERR_INVALID_BURN_HASH',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_CALLER: {
        name: 'ERR_INVALID_CALLER',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_INVALID_REQUEST: {
        name: 'ERR_INVALID_REQUEST',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_WITHDRAWAL_INDEX: {
        name: 'ERR_WITHDRAWAL_INDEX',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      ERR_WITHDRAWAL_INDEX_PREFIX: {
        name: 'ERR_WITHDRAWAL_INDEX_PREFIX',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      MAX_ADDRESS_VERSION: {
        name: 'MAX_ADDRESS_VERSION',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      mAX_ADDRESS_VERSION_BUFF_20: {
        name: 'MAX_ADDRESS_VERSION_BUFF_20',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      mAX_ADDRESS_VERSION_BUFF_32: {
        name: 'MAX_ADDRESS_VERSION_BUFF_32',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      withdrawRole: {
        name: 'withdraw-role',
        type: {
          buffer: {
            length: 1,
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Uint8Array>,
    },
    constants: {},
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch30',
    clarity_version: 'Clarity3',
    contractName: 'sbtc-withdrawal',
  },
  signers: {
    functions: {
      setSigners: {
        name: 'set-signers',
        access: 'private',
        args: [
          { name: 'reward-cycle', type: 'uint128' },
          {
            name: 'signers',
            type: {
              list: {
                type: {
                  tuple: [
                    { name: 'signer', type: 'principal' },
                    { name: 'weight', type: 'uint128' },
                  ],
                },
                length: 4000,
              },
            },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          signers: TypedAbiArg<
            {
              signer: string;
              weight: number | bigint;
            }[],
            'signers'
          >,
        ],
        Response<boolean, bigint>
      >,
      stackerdbSetSignerSlots: {
        name: 'stackerdb-set-signer-slots',
        access: 'private',
        args: [
          {
            name: 'signer-slots',
            type: {
              list: {
                type: {
                  tuple: [
                    { name: 'num-slots', type: 'uint128' },
                    { name: 'signer', type: 'principal' },
                  ],
                },
                length: 4000,
              },
            },
          },
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'set-at-height', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'none' } } },
      } as TypedAbiFunction<
        [
          signerSlots: TypedAbiArg<
            {
              numSlots: number | bigint;
              signer: string;
            }[],
            'signerSlots'
          >,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          setAtHeight: TypedAbiArg<number | bigint, 'setAtHeight'>,
        ],
        Response<boolean, null>
      >,
      getLastSetCycle: {
        name: 'get-last-set-cycle',
        access: 'read_only',
        args: [],
        outputs: { type: { response: { ok: 'uint128', error: 'none' } } },
      } as TypedAbiFunction<[], Response<bigint, null>>,
      getSignerByIndex: {
        name: 'get-signer-by-index',
        access: 'read_only',
        args: [
          { name: 'cycle', type: 'uint128' },
          { name: 'signer-index', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                optional: {
                  tuple: [
                    { name: 'signer', type: 'principal' },
                    { name: 'weight', type: 'uint128' },
                  ],
                },
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          cycle: TypedAbiArg<number | bigint, 'cycle'>,
          signerIndex: TypedAbiArg<number | bigint, 'signerIndex'>,
        ],
        Response<
          {
            signer: string;
            weight: bigint;
          } | null,
          bigint
        >
      >,
      getSigners: {
        name: 'get-signers',
        access: 'read_only',
        args: [{ name: 'cycle', type: 'uint128' }],
        outputs: {
          type: {
            optional: {
              list: {
                type: {
                  tuple: [
                    { name: 'signer', type: 'principal' },
                    { name: 'weight', type: 'uint128' },
                  ],
                },
                length: 4000,
              },
            },
          },
        },
      } as TypedAbiFunction<
        [cycle: TypedAbiArg<number | bigint, 'cycle'>],
        | {
            signer: string;
            weight: bigint;
          }[]
        | null
      >,
      stackerdbGetConfig: {
        name: 'stackerdb-get-config',
        access: 'read_only',
        args: [],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'chunk-size', type: 'uint128' },
                  {
                    name: 'hint-replicas',
                    type: { list: { type: 'none', length: 0 } },
                  },
                  { name: 'max-neighbors', type: 'uint128' },
                  { name: 'max-writes', type: 'uint128' },
                  { name: 'write-freq', type: 'uint128' },
                ],
              },
              error: 'none',
            },
          },
        },
      } as TypedAbiFunction<
        [],
        Response<
          {
            chunkSize: bigint;
            hintReplicas: null[];
            maxNeighbors: bigint;
            maxWrites: bigint;
            writeFreq: bigint;
          },
          null
        >
      >,
      stackerdbGetSignerSlotsPage: {
        name: 'stackerdb-get-signer-slots-page',
        access: 'read_only',
        args: [{ name: 'page', type: 'uint128' }],
        outputs: {
          type: {
            response: {
              ok: {
                list: {
                  type: {
                    tuple: [
                      { name: 'num-slots', type: 'uint128' },
                      { name: 'signer', type: 'principal' },
                    ],
                  },
                  length: 4000,
                },
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [page: TypedAbiArg<number | bigint, 'page'>],
        Response<
          {
            numSlots: bigint;
            signer: string;
          }[],
          bigint
        >
      >,
    },
    maps: {
      cycleSetHeight: {
        name: 'cycle-set-height',
        key: 'uint128',
        value: 'uint128',
      } as TypedAbiMap<number | bigint, bigint>,
      cycleSignerSet: {
        name: 'cycle-signer-set',
        key: 'uint128',
        value: {
          list: {
            type: {
              tuple: [
                { name: 'signer', type: 'principal' },
                { name: 'weight', type: 'uint128' },
              ],
            },
            length: 4000,
          },
        },
      } as TypedAbiMap<
        number | bigint,
        {
          signer: string;
          weight: bigint;
        }[]
      >,
    },
    variables: {
      CHUNK_SIZE: {
        name: 'CHUNK_SIZE',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_CYCLE_NOT_SET: {
        name: 'ERR_CYCLE_NOT_SET',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NO_SUCH_PAGE: {
        name: 'ERR_NO_SUCH_PAGE',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      MAX_WRITES: {
        name: 'MAX_WRITES',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      lastSetCycle: {
        name: 'last-set-cycle',
        type: 'uint128',
        access: 'variable',
      } as TypedAbiVariable<bigint>,
      stackerdbSignerSlots0: {
        name: 'stackerdb-signer-slots-0',
        type: {
          list: {
            type: {
              tuple: [
                {
                  name: 'num-slots',
                  type: 'uint128',
                },
                {
                  name: 'signer',
                  type: 'principal',
                },
              ],
            },
            length: 4_000,
          },
        },
        access: 'variable',
      } as TypedAbiVariable<
        {
          numSlots: bigint;
          signer: string;
        }[]
      >,
      stackerdbSignerSlots1: {
        name: 'stackerdb-signer-slots-1',
        type: {
          list: {
            type: {
              tuple: [
                {
                  name: 'num-slots',
                  type: 'uint128',
                },
                {
                  name: 'signer',
                  type: 'principal',
                },
              ],
            },
            length: 4_000,
          },
        },
        access: 'variable',
      } as TypedAbiVariable<
        {
          numSlots: bigint;
          signer: string;
        }[]
      >,
    },
    constants: {},
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch24',
    clarity_version: 'Clarity2',
    contractName: 'signers',
  },
  signersVoting: {
    functions: {
      getAndCacheTotalWeight: {
        name: 'get-and-cache-total-weight',
        access: 'private',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        Response<bigint, bigint>
      >,
      isInVotingWindow: {
        name: 'is-in-voting-window',
        access: 'private',
        args: [
          { name: 'height', type: 'uint128' },
          { name: 'reward-cycle', type: 'uint128' },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          height: TypedAbiArg<number | bigint, 'height'>,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
        ],
        boolean
      >,
      sumWeights: {
        name: 'sum-weights',
        access: 'private',
        args: [
          {
            name: 'signer',
            type: {
              tuple: [
                { name: 'signer', type: 'principal' },
                { name: 'weight', type: 'uint128' },
              ],
            },
          },
          { name: 'acc', type: 'uint128' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          signer: TypedAbiArg<
            {
              signer: string;
              weight: number | bigint;
            },
            'signer'
          >,
          acc: TypedAbiArg<number | bigint, 'acc'>,
        ],
        bigint
      >,
      updateLastRound: {
        name: 'update-last-round',
        access: 'private',
        args: [
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'round', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          round: TypedAbiArg<number | bigint, 'round'>,
        ],
        Response<boolean, bigint>
      >,
      voteForAggregatePublicKey: {
        name: 'vote-for-aggregate-public-key',
        access: 'public',
        args: [
          { name: 'signer-index', type: 'uint128' },
          { name: 'key', type: { buffer: { length: 33 } } },
          { name: 'round', type: 'uint128' },
          { name: 'reward-cycle', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          signerIndex: TypedAbiArg<number | bigint, 'signerIndex'>,
          key: TypedAbiArg<Uint8Array, 'key'>,
          round: TypedAbiArg<number | bigint, 'round'>,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
        ],
        Response<boolean, bigint>
      >,
      burnHeightToRewardCycle: {
        name: 'burn-height-to-reward-cycle',
        access: 'read_only',
        args: [{ name: 'height', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, 'height'>],
        bigint
      >,
      currentRewardCycle: {
        name: 'current-reward-cycle',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getApprovedAggregateKey: {
        name: 'get-approved-aggregate-key',
        access: 'read_only',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: { optional: { buffer: { length: 33 } } } },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        Uint8Array | null
      >,
      getCandidateInfo: {
        name: 'get-candidate-info',
        access: 'read_only',
        args: [
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'round', type: 'uint128' },
          { name: 'candidate', type: { buffer: { length: 33 } } },
        ],
        outputs: {
          type: {
            tuple: [
              { name: 'candidate-weight', type: 'uint128' },
              { name: 'total-weight', type: { optional: 'uint128' } },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          round: TypedAbiArg<number | bigint, 'round'>,
          candidate: TypedAbiArg<Uint8Array, 'candidate'>,
        ],
        {
          candidateWeight: bigint;
          totalWeight: bigint | null;
        }
      >,
      getLastRound: {
        name: 'get-last-round',
        access: 'read_only',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: { optional: 'uint128' } },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        bigint | null
      >,
      getRoundInfo: {
        name: 'get-round-info',
        access: 'read_only',
        args: [
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'round', type: 'uint128' },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [
                { name: 'votes-count', type: 'uint128' },
                { name: 'votes-weight', type: 'uint128' },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          round: TypedAbiArg<number | bigint, 'round'>,
        ],
        {
          votesCount: bigint;
          votesWeight: bigint;
        } | null
      >,
      getSignerWeight: {
        name: 'get-signer-weight',
        access: 'read_only',
        args: [
          { name: 'signer-index', type: 'uint128' },
          { name: 'reward-cycle', type: 'uint128' },
        ],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          signerIndex: TypedAbiArg<number | bigint, 'signerIndex'>,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
        ],
        Response<bigint, bigint>
      >,
      getTally: {
        name: 'get-tally',
        access: 'read_only',
        args: [
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'round', type: 'uint128' },
          { name: 'aggregate-public-key', type: { buffer: { length: 33 } } },
        ],
        outputs: { type: { optional: 'uint128' } },
      } as TypedAbiFunction<
        [
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          round: TypedAbiArg<number | bigint, 'round'>,
          aggregatePublicKey: TypedAbiArg<Uint8Array, 'aggregatePublicKey'>,
        ],
        bigint | null
      >,
      getThresholdWeight: {
        name: 'get-threshold-weight',
        access: 'read_only',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        bigint
      >,
      getVote: {
        name: 'get-vote',
        access: 'read_only',
        args: [
          { name: 'reward-cycle', type: 'uint128' },
          { name: 'round', type: 'uint128' },
          { name: 'signer', type: 'principal' },
        ],
        outputs: {
          type: {
            optional: {
              tuple: [
                {
                  name: 'aggregate-public-key',
                  type: { buffer: { length: 33 } },
                },
                { name: 'signer-weight', type: 'uint128' },
              ],
            },
          },
        },
      } as TypedAbiFunction<
        [
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
          round: TypedAbiArg<number | bigint, 'round'>,
          signer: TypedAbiArg<string, 'signer'>,
        ],
        {
          aggregatePublicKey: Uint8Array;
          signerWeight: bigint;
        } | null
      >,
      isInPreparePhase: {
        name: 'is-in-prepare-phase',
        access: 'read_only',
        args: [{ name: 'height', type: 'uint128' }],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [height: TypedAbiArg<number | bigint, 'height'>],
        boolean
      >,
      isNovelAggregatePublicKey: {
        name: 'is-novel-aggregate-public-key',
        access: 'read_only',
        args: [
          { name: 'key', type: { buffer: { length: 33 } } },
          { name: 'reward-cycle', type: 'uint128' },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          key: TypedAbiArg<Uint8Array, 'key'>,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
        ],
        boolean
      >,
      rewardCycleToBurnHeight: {
        name: 'reward-cycle-to-burn-height',
        access: 'read_only',
        args: [{ name: 'reward-cycle', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>],
        bigint
      >,
    },
    maps: {
      aggregatePublicKeys: {
        name: 'aggregate-public-keys',
        key: 'uint128',
        value: { buffer: { length: 33 } },
      } as TypedAbiMap<number | bigint, Uint8Array>,
      cycleTotalWeight: {
        name: 'cycle-total-weight',
        key: 'uint128',
        value: 'uint128',
      } as TypedAbiMap<number | bigint, bigint>,
      roundData: {
        name: 'round-data',
        key: {
          tuple: [
            { name: 'reward-cycle', type: 'uint128' },
            { name: 'round', type: 'uint128' },
          ],
        },
        value: {
          tuple: [
            { name: 'votes-count', type: 'uint128' },
            { name: 'votes-weight', type: 'uint128' },
          ],
        },
      } as TypedAbiMap<
        {
          rewardCycle: number | bigint;
          round: number | bigint;
        },
        {
          votesCount: bigint;
          votesWeight: bigint;
        }
      >,
      rounds: {
        name: 'rounds',
        key: 'uint128',
        value: 'uint128',
      } as TypedAbiMap<number | bigint, bigint>,
      tally: {
        name: 'tally',
        key: {
          tuple: [
            { name: 'aggregate-public-key', type: { buffer: { length: 33 } } },
            { name: 'reward-cycle', type: 'uint128' },
            { name: 'round', type: 'uint128' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          aggregatePublicKey: Uint8Array;
          rewardCycle: number | bigint;
          round: number | bigint;
        },
        bigint
      >,
      usedAggregatePublicKeys: {
        name: 'used-aggregate-public-keys',
        key: { buffer: { length: 33 } },
        value: 'uint128',
      } as TypedAbiMap<Uint8Array, bigint>,
      votes: {
        name: 'votes',
        key: {
          tuple: [
            { name: 'reward-cycle', type: 'uint128' },
            { name: 'round', type: 'uint128' },
            { name: 'signer', type: 'principal' },
          ],
        },
        value: {
          tuple: [
            { name: 'aggregate-public-key', type: { buffer: { length: 33 } } },
            { name: 'signer-weight', type: 'uint128' },
          ],
        },
      } as TypedAbiMap<
        {
          rewardCycle: number | bigint;
          round: number | bigint;
          signer: string;
        },
        {
          aggregatePublicKey: Uint8Array;
          signerWeight: bigint;
        }
      >,
    },
    variables: {
      ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY: {
        name: 'ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_DUPLICATE_VOTE: {
        name: 'ERR_DUPLICATE_VOTE',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_FAILED_TO_RETRIEVE_SIGNERS: {
        name: 'ERR_FAILED_TO_RETRIEVE_SIGNERS',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY: {
        name: 'ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_ROUND: {
        name: 'ERR_INVALID_ROUND',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_SIGNER_INDEX: {
        name: 'ERR_INVALID_SIGNER_INDEX',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_OUT_OF_VOTING_WINDOW: {
        name: 'ERR_OUT_OF_VOTING_WINDOW',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_SIGNER_INDEX_MISMATCH: {
        name: 'ERR_SIGNER_INDEX_MISMATCH',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      poxInfo: {
        name: 'pox-info',
        type: {
          tuple: [
            {
              name: 'first-burnchain-block-height',
              type: 'uint128',
            },
            {
              name: 'min-amount-ustx',
              type: 'uint128',
            },
            {
              name: 'prepare-cycle-length',
              type: 'uint128',
            },
            {
              name: 'reward-cycle-id',
              type: 'uint128',
            },
            {
              name: 'reward-cycle-length',
              type: 'uint128',
            },
            {
              name: 'total-liquid-supply-ustx',
              type: 'uint128',
            },
          ],
        },
        access: 'constant',
      } as TypedAbiVariable<{
        firstBurnchainBlockHeight: bigint;
        minAmountUstx: bigint;
        prepareCycleLength: bigint;
        rewardCycleId: bigint;
        rewardCycleLength: bigint;
        totalLiquidSupplyUstx: bigint;
      }>,
      thresholdConsensus: {
        name: 'threshold-consensus',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
    },
    constants: {
      ERR_DUPLICATE_AGGREGATE_PUBLIC_KEY: 14n,
      ERR_DUPLICATE_VOTE: 15n,
      ERR_FAILED_TO_RETRIEVE_SIGNERS: 16n,
      ERR_ILL_FORMED_AGGREGATE_PUBLIC_KEY: 13n,
      ERR_INVALID_ROUND: 17n,
      ERR_INVALID_SIGNER_INDEX: 11n,
      ERR_OUT_OF_VOTING_WINDOW: 12n,
      ERR_SIGNER_INDEX_MISMATCH: 10n,
      poxInfo: {
        firstBurnchainBlockHeight: 0n,
        minAmountUstx: 150_000_000_000n,
        prepareCycleLength: 50n,
        rewardCycleId: 0n,
        rewardCycleLength: 1_050n,
        totalLiquidSupplyUstx: 1_200_000_000_000_000n,
      },
      thresholdConsensus: 70n,
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch24',
    clarity_version: 'Clarity2',
    contractName: 'signers-voting',
  },
  sip031: {
    functions: {
      calcTotalVested: {
        name: 'calc-total-vested',
        access: 'private',
        args: [{ name: 'burn-height', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [burnHeight: TypedAbiArg<number | bigint, 'burnHeight'>],
        bigint
      >,
      validateCaller: {
        name: 'validate-caller',
        access: 'private',
        args: [],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<[], Response<boolean, bigint>>,
      claim: {
        name: 'claim',
        access: 'public',
        args: [],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<[], Response<bigint, bigint>>,
      updateRecipient: {
        name: 'update-recipient',
        access: 'public',
        args: [{ name: 'new-recipient', type: 'principal' }],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [newRecipient: TypedAbiArg<string, 'newRecipient'>],
        Response<boolean, bigint>
      >,
      calcClaimableAmount: {
        name: 'calc-claimable-amount',
        access: 'read_only',
        args: [{ name: 'burn-height', type: 'uint128' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [burnHeight: TypedAbiArg<number | bigint, 'burnHeight'>],
        bigint
      >,
      getDeployBlockHeight: {
        name: 'get-deploy-block-height',
        access: 'read_only',
        args: [],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[], bigint>,
      getRecipient: {
        name: 'get-recipient',
        access: 'read_only',
        args: [],
        outputs: { type: 'principal' },
      } as TypedAbiFunction<[], string>,
    },
    maps: {},
    variables: {
      DEPLOY_BLOCK_HEIGHT: {
        name: 'DEPLOY_BLOCK_HEIGHT',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_INVALID_RECIPIENT: {
        name: 'ERR_INVALID_RECIPIENT',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NOTHING_TO_CLAIM: {
        name: 'ERR_NOTHING_TO_CLAIM',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      ERR_NOT_ALLOWED: {
        name: 'ERR_NOT_ALLOWED',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      INITIAL_MINT_AMOUNT: {
        name: 'INITIAL_MINT_AMOUNT',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      INITIAL_MINT_IMMEDIATE_AMOUNT: {
        name: 'INITIAL_MINT_IMMEDIATE_AMOUNT',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      INITIAL_MINT_VESTING_AMOUNT: {
        name: 'INITIAL_MINT_VESTING_AMOUNT',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      INITIAL_MINT_VESTING_ITERATIONS: {
        name: 'INITIAL_MINT_VESTING_ITERATIONS',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      INITIAL_MINT_VESTING_ITERATION_BLOCKS: {
        name: 'INITIAL_MINT_VESTING_ITERATION_BLOCKS',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      STX_PER_ITERATION: {
        name: 'STX_PER_ITERATION',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      recipient: {
        name: 'recipient',
        type: 'principal',
        access: 'variable',
      } as TypedAbiVariable<string>,
    },
    constants: {
      DEPLOY_BLOCK_HEIGHT: 5n,
      ERR_INVALID_RECIPIENT: 103n,
      ERR_NOTHING_TO_CLAIM: 102n,
      ERR_NOT_ALLOWED: 101n,
      INITIAL_MINT_AMOUNT: 200_000_000_000_000n,
      INITIAL_MINT_IMMEDIATE_AMOUNT: 100_000_000_000_000n,
      INITIAL_MINT_VESTING_AMOUNT: 100_000_000_000_000n,
      INITIAL_MINT_VESTING_ITERATIONS: 24n,
      INITIAL_MINT_VESTING_ITERATION_BLOCKS: 4_383n,
      STX_PER_ITERATION: 4_166_666_666_666n,
      recipient: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch31',
    clarity_version: 'Clarity3',
    contractName: 'sip-031',
  },
  sip031Indirect: {
    functions: {
      claimAsContract: {
        name: 'claim-as-contract',
        access: 'public',
        args: [],
        outputs: { type: { response: { ok: 'uint128', error: 'uint128' } } },
      } as TypedAbiFunction<[], Response<bigint, bigint>>,
      transferStx: {
        name: 'transfer-stx',
        access: 'public',
        args: [
          { name: 'amount', type: 'uint128' },
          { name: 'recipient', type: 'principal' },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [
          amount: TypedAbiArg<number | bigint, 'amount'>,
          recipient: TypedAbiArg<string, 'recipient'>,
        ],
        Response<boolean, bigint>
      >,
      updateRecipient: {
        name: 'update-recipient',
        access: 'public',
        args: [{ name: 'new-recipient', type: 'principal' }],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [newRecipient: TypedAbiArg<string, 'newRecipient'>],
        Response<boolean, bigint>
      >,
      updateRecipientAsContract: {
        name: 'update-recipient-as-contract',
        access: 'public',
        args: [{ name: 'new-recipient', type: 'principal' }],
        outputs: { type: { response: { ok: 'bool', error: 'uint128' } } },
      } as TypedAbiFunction<
        [newRecipient: TypedAbiArg<string, 'newRecipient'>],
        Response<boolean, bigint>
      >,
      getBalance: {
        name: 'get-balance',
        access: 'read_only',
        args: [{ name: 'addr', type: 'principal' }],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<[addr: TypedAbiArg<string, 'addr'>], bigint>,
    },
    maps: {},
    variables: {},
    constants: {},
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch31',
    clarity_version: 'Clarity3',
    contractName: 'sip-031-indirect',
  },
  testPox5Signer: {
    functions: {
      updateBondRewardsInfo: {
        name: 'update-bond-rewards-info',
        access: 'private',
        args: [
          {
            name: 'bond-info',
            type: {
              tuple: [
                { name: 'bond-index', type: 'uint128' },
                { name: 'rewards-paid', type: 'uint128' },
                { name: 'rewards-pending', type: 'uint128' },
                { name: 'rewards-per-share', type: 'uint128' },
                { name: 'shares-staked', type: 'uint128' },
              ],
            },
          },
          { name: 'acc', type: 'bool' },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          bondInfo: TypedAbiArg<
            {
              bondIndex: number | bigint;
              rewardsPaid: number | bigint;
              rewardsPending: number | bigint;
              rewardsPerShare: number | bigint;
              sharesStaked: number | bigint;
            },
            'bondInfo'
          >,
          acc: TypedAbiArg<boolean, 'acc'>,
        ],
        boolean
      >,
      updateRewardsInfo: {
        name: 'update-rewards-info',
        access: 'private',
        args: [
          { name: 'rewards-per-share', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
          { name: 'index', type: 'uint128' },
        ],
        outputs: { type: 'bool' },
      } as TypedAbiFunction<
        [
          rewardsPerShare: TypedAbiArg<number | bigint, 'rewardsPerShare'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
          index: TypedAbiArg<number | bigint, 'index'>,
        ],
        boolean
      >,
      claimRewards: {
        name: 'claim-rewards',
        access: 'public',
        args: [
          {
            name: 'bond-periods',
            type: { list: { type: 'uint128', length: 6 } },
          },
          { name: 'reward-cycle', type: 'uint128' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  {
                    name: 'bond-rewards',
                    type: {
                      list: {
                        type: {
                          tuple: [
                            { name: 'bond-index', type: 'uint128' },
                            { name: 'rewards-paid', type: 'uint128' },
                            { name: 'rewards-pending', type: 'uint128' },
                            { name: 'rewards-per-share', type: 'uint128' },
                            { name: 'shares-staked', type: 'uint128' },
                          ],
                        },
                        length: 6,
                      },
                    },
                  },
                  { name: 'bond-totals', type: 'uint128' },
                  {
                    name: 'stx-rewards',
                    type: {
                      tuple: [
                        { name: 'rewards-paid', type: 'uint128' },
                        { name: 'rewards-pending', type: 'uint128' },
                        { name: 'rewards-per-share', type: 'uint128' },
                        { name: 'shares-staked', type: 'uint128' },
                      ],
                    },
                  },
                  { name: 'total-rewards', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          bondPeriods: TypedAbiArg<number | bigint[], 'bondPeriods'>,
          rewardCycle: TypedAbiArg<number | bigint, 'rewardCycle'>,
        ],
        Response<
          {
            bondRewards: {
              bondIndex: bigint;
              rewardsPaid: bigint;
              rewardsPending: bigint;
              rewardsPerShare: bigint;
              sharesStaked: bigint;
            }[];
            bondTotals: bigint;
            stxRewards: {
              rewardsPaid: bigint;
              rewardsPending: bigint;
              rewardsPerShare: bigint;
              sharesStaked: bigint;
            };
            totalRewards: bigint;
          },
          bigint
        >
      >,
      claimStakerRewards: {
        name: 'claim-staker-rewards',
        access: 'public',
        args: [
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'rewards-paid', type: 'uint128' },
                  { name: 'rewards-pending', type: 'uint128' },
                  { name: 'rewards-per-share', type: 'uint128' },
                  { name: 'shares-staked', type: 'uint128' },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        Response<
          {
            rewardsPaid: bigint;
            rewardsPending: bigint;
            rewardsPerShare: bigint;
            sharesStaked: bigint;
          },
          bigint
        >
      >,
      registerSelf: {
        name: 'register-self',
        access: 'public',
        args: [
          { name: 'signer-manager', type: 'trait_reference' },
          { name: 'signer-key', type: { buffer: { length: 33 } } },
          { name: 'auth-id', type: 'uint128' },
          { name: 'signer-sig', type: { buffer: { length: 65 } } },
        ],
        outputs: {
          type: {
            response: {
              ok: {
                tuple: [
                  { name: 'signer', type: 'principal' },
                  { name: 'signer-key', type: { buffer: { length: 33 } } },
                ],
              },
              error: 'uint128',
            },
          },
        },
      } as TypedAbiFunction<
        [
          signerManager: TypedAbiArg<string, 'signerManager'>,
          signerKey: TypedAbiArg<Uint8Array, 'signerKey'>,
          authId: TypedAbiArg<number | bigint, 'authId'>,
          signerSig: TypedAbiArg<Uint8Array, 'signerSig'>,
        ],
        Response<
          {
            signer: string;
            signerKey: Uint8Array;
          },
          bigint
        >
      >,
      updateAllowedCaller: {
        name: 'update-allowed-caller',
        access: 'public',
        args: [{ name: 'new-allowed-caller', type: 'principal' }],
        outputs: { type: { response: { ok: 'bool', error: 'none' } } },
      } as TypedAbiFunction<
        [newAllowedCaller: TypedAbiArg<string, 'newAllowedCaller'>],
        Response<boolean, null>
      >,
      validateStake_x: {
        name: 'validate-stake!',
        access: 'public',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'amount-ustx', type: 'uint128' },
          { name: 'amount-sats', type: 'uint128' },
          { name: 'num-cycles', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
          {
            name: 'signer-calldata',
            type: { optional: { buffer: { length: 500 } } },
          },
        ],
        outputs: { type: { response: { ok: 'bool', error: 'none' } } },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          amountUstx: TypedAbiArg<number | bigint, 'amountUstx'>,
          amountSats: TypedAbiArg<number | bigint, 'amountSats'>,
          numCycles: TypedAbiArg<number | bigint, 'numCycles'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
          signerCalldata: TypedAbiArg<Uint8Array | null, 'signerCalldata'>,
        ],
        Response<boolean, null>
      >,
      getClaimableRewards: {
        name: 'get-claimable-rewards',
        access: 'read_only',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: {
          type: {
            tuple: [
              { name: 'rewards-paid', type: 'uint128' },
              { name: 'rewards-pending', type: 'uint128' },
              { name: 'rewards-per-share', type: 'uint128' },
              { name: 'shares-staked', type: 'uint128' },
            ],
          },
        },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        {
          rewardsPaid: bigint;
          rewardsPending: bigint;
          rewardsPerShare: bigint;
          sharesStaked: bigint;
        }
      >,
      getRewardsPerTokenForCycle: {
        name: 'get-rewards-per-token-for-cycle',
        access: 'read_only',
        args: [
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        bigint
      >,
      getStakerRewardsPaidForCycle: {
        name: 'get-staker-rewards-paid-for-cycle',
        access: 'read_only',
        args: [
          { name: 'staker', type: 'principal' },
          { name: 'index', type: 'uint128' },
          { name: 'is-bond', type: 'bool' },
        ],
        outputs: { type: 'uint128' },
      } as TypedAbiFunction<
        [
          staker: TypedAbiArg<string, 'staker'>,
          index: TypedAbiArg<number | bigint, 'index'>,
          isBond: TypedAbiArg<boolean, 'isBond'>,
        ],
        bigint
      >,
    },
    maps: {
      rewardsPerTokenForCycle: {
        name: 'rewards-per-token-for-cycle',
        key: {
          tuple: [
            { name: 'index', type: 'uint128' },
            { name: 'is-bond', type: 'bool' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          index: number | bigint;
          isBond: boolean;
        },
        bigint
      >,
      stakerRewardsPaidForCycle: {
        name: 'staker-rewards-paid-for-cycle',
        key: {
          tuple: [
            { name: 'index', type: 'uint128' },
            { name: 'is-bond', type: 'bool' },
            { name: 'staker', type: 'principal' },
          ],
        },
        value: 'uint128',
      } as TypedAbiMap<
        {
          index: number | bigint;
          isBond: boolean;
          staker: string;
        },
        bigint
      >,
    },
    variables: {
      ERR_NO_CLAIMABLE_REWARDS: {
        name: 'ERR_NO_CLAIMABLE_REWARDS',
        type: {
          response: {
            ok: 'none',
            error: 'uint128',
          },
        },
        access: 'constant',
      } as TypedAbiVariable<Response<null, bigint>>,
      PRECISION: {
        name: 'PRECISION',
        type: 'uint128',
        access: 'constant',
      } as TypedAbiVariable<bigint>,
      allowedCaller: {
        name: 'allowed-caller',
        type: 'principal',
        access: 'variable',
      } as TypedAbiVariable<string>,
    },
    constants: {
      ERR_NO_CLAIMABLE_REWARDS: {
        isOk: false,
        value: 1_001n,
      },
      PRECISION: 1_000_000_000_000_000_000n,
      allowedCaller: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
    },
    non_fungible_tokens: [],
    fungible_tokens: [],
    epoch: 'Epoch33',
    clarity_version: 'Clarity4',
    contractName: 'test-pox-5-signer',
  },
} as const;

export const accounts = {
  deployer: {
    address: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM',
    balance: '100000000000000',
  },
  wallet_1: {
    address: 'ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5',
    balance: '100000000000000',
  },
  wallet_10: {
    address: 'ST3FFKYTTB975A3JC3F99MM7TXZJ406R3GKE6JV56',
    balance: '200000000000000',
  },
  wallet_2: {
    address: 'ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG',
    balance: '100000000000000',
  },
  wallet_3: {
    address: 'ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC',
    balance: '100000000000000',
  },
  wallet_4: {
    address: 'ST2NEB84ASENDXKYGJPQW86YXQCEFEX2ZQPG87ND',
    balance: '100000000000000',
  },
  wallet_5: {
    address: 'ST2REHHS5J3CERCRBEPMGH7921Q6PYKAADT7JP2VB',
    balance: '100000000000000',
  },
  wallet_6: {
    address: 'ST3AM1A56AK2C1XAFJ4115ZSV26EB49BVQ10MGCS0',
    balance: '100000000000000',
  },
  wallet_7: {
    address: 'ST3PF13W7Z0RRM42A8VZRVFQ75SV1K26RXEP8YGKJ',
    balance: '100000000000000',
  },
  wallet_8: {
    address: 'ST3NBRSFKX28FQ2ZJ1MAKX58HKHSDGNV5N7R21XCP',
    balance: '100000000000000',
  },
  wallet_9: {
    address: 'STNHKEPYEPJ8ET55ZZ0M5A34J0R3N5FM2CMMMAZ6',
    balance: '100000000000000',
  },
} as const;

export const identifiers = {
  bns: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.bns',
  bns_test: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.bns_test',
  pox4: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-4',
  pox5: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5',
  pox_4_test: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox_4_test',
  sbtcDeposit: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-deposit',
  sbtcRegistry: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry',
  sbtcToken: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token',
  sbtcWithdrawal: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal',
  signers: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.signers',
  signersVoting: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.signers-voting',
  sip031: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031',
  sip031Indirect: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031-indirect',
  testPox5Signer: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.test-pox-5-signer',
} as const;

export const simnet = {
  accounts,
  contracts,
  identifiers,
} as const;

export const deployments = {
  bns: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.bns',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.bns',
    testnet: null,
    mainnet: null,
  },
  bns_test: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.bns_test',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.bns_test',
    testnet: null,
    mainnet: null,
  },
  pox4: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-4',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-4',
    testnet: null,
    mainnet: null,
  },
  pox5: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox-5',
    testnet: null,
    mainnet: null,
  },
  pox_4_test: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox_4_test',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox_4_test',
    testnet: null,
    mainnet: null,
  },
  sbtcDeposit: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-deposit',
    simnet: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-deposit',
    testnet: null,
    mainnet: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-deposit',
  },
  sbtcRegistry: {
    devnet: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry',
    simnet: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-registry',
    testnet: null,
    mainnet: null,
  },
  sbtcToken: {
    devnet: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token',
    simnet: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-token',
    testnet: null,
    mainnet: null,
  },
  sbtcWithdrawal: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sbtc-withdrawal',
    simnet: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal',
    testnet: null,
    mainnet: 'SM3VDXK3WZZSA84XXFKAFAF15NNZX32CTSG82JFQ4.sbtc-withdrawal',
  },
  signers: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.signers',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.signers',
    testnet: null,
    mainnet: null,
  },
  signersVoting: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.signers-voting',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.signers-voting',
    testnet: null,
    mainnet: null,
  },
  sip031: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031',
    testnet: null,
    mainnet: null,
  },
  sip031Indirect: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031-indirect',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031-indirect',
    testnet: null,
    mainnet: null,
  },
  testPox5Signer: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.test-pox-5-signer',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.test-pox-5-signer',
    testnet: null,
    mainnet: null,
  },
} as const;

export const project = {
  contracts,
  deployments,
} as const;

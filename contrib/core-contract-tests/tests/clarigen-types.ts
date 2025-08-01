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
    constants: {},
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
        minAmountUstx: 125_000_000_000n,
        prepareCycleLength: 50n,
        rewardCycleId: 0n,
        rewardCycleLength: 1_050n,
        totalLiquidSupplyUstx: 1_000_000_000_000_000n,
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
      DEPLOY_BLOCK_HEIGHT: 3n,
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
  pox_4_test: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox_4_test',
  signers: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.signers',
  signersVoting: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.signers-voting',
  sip031: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031',
  sip031Indirect: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.sip-031-indirect',
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
  pox_4_test: {
    devnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox_4_test',
    simnet: 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM.pox_4_test',
    testnet: null,
    mainnet: null,
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
} as const;

export const project = {
  contracts,
  deployments,
} as const;

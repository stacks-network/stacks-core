# JSON Tokens JS

[![CircleCI](https://img.shields.io/circleci/project/blockstack/jsontokens-js/master.svg)](https://circleci.com/gh/blockstack/jsontokens-js/tree/master)
[![npm](https://img.shields.io/npm/l/jsontokens.svg)](https://www.npmjs.com/package/jsontokens)
[![npm](https://img.shields.io/npm/v/jsontokens.svg)](https://www.npmjs.com/package/jsontokens)
[![npm](https://img.shields.io/npm/dm/jsontokens.svg)](https://www.npmjs.com/package/jsontokens)
[![Slack](https://img.shields.io/badge/join-slack-e32072.svg?style=flat)](http://slack.blockstack.org/)

node.js library for signing, decoding, and verifying JSON Web Tokens (JWTs)

### Installation

```
npm install jsontokens
```

### Signing Tokens

```js
import { TokenSigner } from 'jsontokens'

const rawPrivateKey = '278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f'
const tokenPayload = {"iat": 1440713414.85}
const token = new TokenSigner('ES256K', rawPrivateKey).sign(tokenPayload)
```

### Creating Unsecured Tokens

```js
import { createUnsecuredToken } from 'jsontokens'

const unsecuredToken = createUnsecuredToken(tokenPayload)
```

### Decoding Tokens

```js
import { decodeToken } = from 'jsontokens'
const tokenData = decodeToken(token)
```

### Verifying Tokens

```js
import { TokenVerifier } from 'jsontokens'
const rawPublicKey = '03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479'
const verified = new TokenVerifier('ES256K', rawPublicKey).verify(token)
```

### Example Tokens

```text
eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

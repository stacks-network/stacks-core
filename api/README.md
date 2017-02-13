Blockstack Core API
=========

The Blockstack REST APIv1 is defined here. See the [development status](https://github.com/blockstack/blockstack-core/milestone/6). 

Blockstack Core v0.13 and earlier had an RPC interface. Starting from Blockstack Core v0.14, we'll focus on the new REST API as the primary interface. We're also consolidating various Blockstack services, like the resolver and search, into a single interface. 
 
# Blockstack Specifications

## Dashboard Endpoints

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Dashboard Home | GET / | identity | Serves the identity management panel | 
| Auth Request View | GET /auth?authRequest={authRequestToken} | identity | Serves the auth request view | 

#### Explanation of the auth request view:

When the user clicks “login” in an application, the app should redirect the user to this endpoint. If the user already has an account, they will be redirected along with requested data. If the user doesn’t have an account, the user will be presented with each of the app’s requested permissions, then will satisfy or deny them. The dashboard will then redirect the user back with a JWT. The response JWT contains a signature and an API token that the app can use for future authorization of endpoints.

Each application specifies in advance which family of API calls it will need to make to function properly.  This list is passed along to the dashboard endpoint when creating an application account.  The account-creation page shows this list of API endpoints and what they do, and allows the user to line-item approve or deny them.  The list is stored by the API server in the local account structure, and the list is given to the application as part of the session JWT.  The API server will NACK requests to endpoints in API families absent from the session JWT. 

## Administrative API

### Node

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Ping the node | GET /node/ping | - | - |
| Restart the node | POST /node/reboot | - | Requires a pre-shared secret in the `Authorization:` header |

### Wallet

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get wallet payment address | GET /wallet/payment_address | wallet_read | - |
| Get wallet owner address | GET /wallet/owner_address | wallet_read | - |
| Set the wallet | PUT /wallet/private | - | Requires a pre-shared secret in the `Authorization:` header |

### Authorization

| Method | API Call | API family | Notes |
| ------------- | ------------- | ------------- | ------------- |
| Create an authorization token | GET /auth?authRequest={authRequestToken} | - | Requires a pre-shared secret in the `Authorization:` header. |

The `GET /auth` endpoint creates a session JWT for an account.  Accounts are identified by a persona and an application (where a persona is derived from the user's master data key).  This endpoint expects a JSON document with at least the following fields defined:
```
{
   'name': str          # the app developer's blockchain ID
   'appname': str       # the app's DNS name (but can be arbitrary)
   'user_id': str       # the ID of the persona 
   'methods': [str]     # the list of "API families" that this token will enable.
}
```

Blockstack Core session tokens are JWTs defined as follows.  They will be signed by the data private key in the wallet:
```
{
    'name': str       # app developer's blockchain ID
    'appname': str    # app's DNS name (but can be arbitrary)
    'user_id': str    # persona identifier
    'methods': [str]  # the list of API families the bearer may call
    'timestamp': int  # the time at which this token was created
    'expires': int    # the time at which this token expires
}
```

The token represents the rights of an account, identified by the (`name`, `appname`, `user_id`) tuple.  For example, (`name="storage.app"`, `appname="www.blockstack-storage.com"`, `user_id=jude_storage`) can be interpreted as "The account for user persona `jude_storage` in `storage.app`'s application `www.blockstack-storage.com`". 

The `name` and `appname` fields identify the program that the token is for.  They are meant primarily for accounts of Web applications where the client program will ask Blockstack to fetch and authenticate both the app's `index.html` file and a `.blockstackrc` file.  In this case, `name` will be used to look up the public key to verify the signed `.blockstackrc` file (e.g. `name` is the developer's blockchain ID), which will then be used to authenticate the `index.html` file.  The `appname` field is the name of a specific application whose data is signed by the `name`'s owner (for Web apps, this is the app's DNS name).

The `user_id` field identifies user persona known to Blockstack Core (i.e. created with `blockstack create_user` or `POST /users`).  User personas are derived from the data private key in the wallet, and their public keys are replicated to the owner's storage providers by default (so other clients can look them up, given the `user_id` and the blockchain ID that points to the data public key).

User personas represent collections of accounts.  For example, a wallet owner might have a personal user and a business user.  An agent that wants to create tokens on behalf of other programs (like the Blockstack Browser Portal) should create a user persona for itself, and use that persona to generate tokens for its Web clients.

## Naming API

### Names

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all names | GET /names | names | - | 
| Register name | POST /names | register | Payload: {"name": NAME} | 
| Get name info | GET /names/{name} | names | - | 
| Get name history | GET /names/{name}/history | names | - | 
| Get historical zone file | GET /names/{name}/zonefile/{zoneFileHash} | zonefiles | - | 
| Delete user | DELETE /names/{name} | revoke | - | 
| Transfer name | PUT /names/{name}/owner | transfer | Payload: {"owner": OWNER } | 
| Set zone file | PUT /names/{name}/zonefile | update | Payload: {"zonefile": ZONE_FILE } | 
| Set zone file hash | PUT /names/{name}/zonefile | update | Payload: {"zonefile_hash": ZONE_FILE_HASH } | 

### Addresses

| Method | API Call | API family | Notes |
| ------------- | ------------- | ------------- | ------------- |
| Get names owned by address | GET /addresses/{address} | names | - |

### Namespaces

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all namespaces | GET /namespaces | namespaces | - | 
| Create namespace | POST /namespaces | namespace_registration | - | 
| Launch namespace | PUT /namespaces/{tld} | namespace_registration | - | 
| Get namespace names | GET /namespaces/{tld}/names | namespaces | - | 
| Pre-register a name | POST /namespaces/{tld}/names | namespace_registration | - | 
| Update pre-registered name | PUT /namespaces/{tld}/names/{name} | namespace_registration | - | 

### Prices

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get namespace price | GET /prices/namespaces/{tld} | prices | - | 
| Get name price | GET /prices/names/{name} | prices | - | 


### Blockchains

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get block operations | GET /blockchains/{blockchainName}/block/{blockHeight} | blockchains | - | 
| Get raw name history | GET /blockchains/{blockchainName}/names/{nameID}/history | blockchains |  - | 
| Get consensus hash | GET /blockchains/{blockchainName}/consensusHash | blockchains | - | 
| Get pending transactions | GET /blockchains/{blockchainName}/pending | blockchains | - |

## Identity API

### Users

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all users | GET /users | user_admin | - | 
| Create user | POST /users | user_admin | Payload: {"user_id": USER_ID, "profile": PROFILE} | 
| Get user profile | GET /users/{userID} | users | Only works on the session's designated user. | 
| Delete user | DELETE /users/{userID} | user_admin | - | 
| Update profile | PATCH /users/{userID} | user_admin | Payload: {"profile": PROFILE }.  Only works on the session's designiated user. | 

### User Stores

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all stores | GET /users/{userID}/stores | store_admin | - | 
| Create store | POST /users/{userID}/stores | store_admin | Payload: {'storeID': store ID} | 
| Get store | GET /users/{userID}/stores/{storeID} | store_admin | - | 
| Update store | PUT /users/{userID}/stores/{storeID} | store_admin | - | 
| Delete store | DELETE /users/{userID}/stores/{storeID} | store_admin | - | 
| - | - | - | - |
| Get inode info (stat) | GET /users/{userID}/stores/{storeID}/inodes?path={path} | store_read | - | 
| - | - | - | - |
| Get directory files (ls) | GET /users/{userID}/stores/{storeID}/directories?path={path} | store_read | - | 
| Create directory (mkdir) | POST /users/{userID}/stores/{storeID}/directories?path={path} | store_write | - | 
| Delete directory (rmdir) | DELETE /users/{userID}/stores/{storeID}/directories?path={path} | store_write | - | 
| - | - | - | - |
| Get file data (open) | GET /users/{userID}/stores/{storeID}/files?path={path} | store_read | - | 
| Create file | POST /users/{userID}/stores/{storeID}/files?path={path} | store_write | Uploads `application/octet-stream` raw file data | 
| Update file | PUT /users/{userID}/stores/{storeID}/files?path={path} | store_write | Uploads `application/octet-stream` raw file data | 
| Delete file (rm) | DELETE /users/{userID}/stores/{storeID}/files?path={path} | store_write | - | 

### User Collections

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all collections | GET /users/{userID}/collections | collection_read | - | 
| Create collection | POST /users/{userID}/collections | collection_admin | - | 
| Get all collection items | GET /users/{userID}/collections/{collectionID} | collection_read | - | 
| Create collection item | POST /users/{userID}/collections/{collectionID} | collection_write | - | 
| Get collection item | GET /users/{userID}/collections/{collectionID}/{itemID} | collection_read | - | 

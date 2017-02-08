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
| Get public wallet fields | GET /wallet/public | wallet_read | - |
| Set the wallet | PUT /wallet/private | - | Requires a pre-shared secret in the `Authorization:` header |

### Authorization

| Method | API Call | API family | Notes |
| ------------- | ------------- | ------------- | ------------- |
| Create an authorization token | POST /auth | - | Requires a pre-shared secret in the `Authorization:` header. |

The `POST /auth` endpoint expects a JSON document with at least the following fields defined:
```
{
   'name': str,         # OPTIONAL; see below
   'appname': str,      # OPTIONAL; see below
   'user_id': str,      # OPTIONAL; see below
   'public_key': str    # the ECDSA public key of the account this token is for
   'permissions': [str] # the list of "API families" that this token will enable.
}
```

Blockstack Core session tokens are JWTs defined as follows:
```
{
    'name': str       # the blockchain ID of the application's owner (e.g. the Host: field)
    'appname': str    # the name of the application
    'user_id': str    # the name of the user's persona that signed in
    'methods': [str]  # the list of API families the bearer may call
    'public_key': str # the ECDSA public key of the account
    'timestamp': int  # the time at which this token was created
    'expires': int    # the time at which this token expires
}
```
The token will be signed by the data private key in the wallet.

The process that calls `POST /auth` supplies the values for `name`, `appname`, and `user_id` fields.  While they are not required, their absence will limit some API calls as described below.

The `name` and `appname` fields identify the program that the token is for.  This makes the most sense for Web applications, where we have to authenticate `index.html` using a signed `.blockstackrc` file.  In these cases, `name` will be used to look up the public key to verify the signed `.blockstackrc` file, which will then be used to authenticate the `index.html` file and the app's DNS name.  The `appname` field is a long-form app-chosen description of the application (e.g. `name=google.app` and `appname=Google, Inc`).  If these fields are omitted, then the token-bearer will be unable to use the `resources` API family or use Blockstack Core as a Web proxy.

The `user_id` field identifies a child keypair derived from the node's data key that can be used for loading and storing profiles and data.  The core node must already know about the keypair.  It needs to have been generated prior to the `/auth` call by using the CLI's `create_user` command or the REST API's `POST /users` endpoint.  If the `user_id` field is omitted or does not correspond to a known user, then the token-bearer will be unable to use the Identities API (see below).

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
| Get names owned by address | GET /addresses/{address}/names | names | - |

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

### Resources

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get app resource | GET /appResources/{appID}/{resourceID} | resources | - | 

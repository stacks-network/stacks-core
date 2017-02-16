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
| Set the wallet | PUT /wallet/keys | - | Requires a pre-shared secret in the `Authorization:` header |
| Get the wallet | GET /wallet/keys | - | Requires a pre-shared secret in the `Authorization:` header |

### Authorization

| Method | API Call | API family | Notes |
| ------------- | ------------- | ------------- | ------------- |
| Create an authorization token | GET /auth?authRequest={authRequestToken} | - | Requires a pre-shared secret in the `Authorization:` header. |

The `GET /auth` endpoint creates a session JWT for an account.  Accounts are identified by a persona and an application (where a persona is derived from the user's master data key).  This endpoint expects a JSON document with at least the following fields defined:
```
{
   'app_domain': str        # the name of the application (DNS name or blockchain ID)
   'methods': [str]         # the list of "API families" that this token will enable.
}
```

Blockstack Core session tokens are JWTs defined as follows.  They will be signed by the data private key in its wallet:
```
{
    'app_domain': str    # same as above
    'app_user_id': str   # same as above
    'methods': [str]  # the list of API families the bearer may call
    'timestamp': int  # the time at which this token was created
    'expires': int    # the time at which this token expires
}
```

**Notes for Web developers**.  The `app_domain` should be a DNSSEC-secured DNS name, or a blockchain ID.  Either way, it must refer to a zone file with a `TXT` record that has a public key.  Core will fetch this public key, and use it to verify the signature of a `.blockstackrc` file hosted in the same directory as the application's `index.html` file.  This `.blockstackrc` file contains the hash of the `index.html` file, as well as other application assets. 

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

Here, `{userID}` is a name.

TODO: `{userID}` could be derived from the session, somehow.  If `{userID}` is a name, then the application is going to need to get it from the user.  More generally, if the application is going to do something on behalf of the user, like storing persistent state, then the user is going to need to give the application something that identifies his/her public key.

Alternatives to `{userID}` could be:

* the address of the user's data public key (UNSAFE TO SHARE--can reverse-lookup to find name).
* the address of the `app_user_id` public key

Also, I'm not sure what `{storeID}` should be, if not the address of `app_user_id` (i.e. equal to `{userID}`).

### Users

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Create user profile | POST /users | user_admin | Payload: {"name": NAME, "profile": PROFILE} | 
| Get user profile | GET /users/{userID} | user_read | TODO: for which name? | 
| Delete user profile | DELETE /users/{userID} | user_admin | TODO: for which name? | 
| Update profile | PATCH /users/{userID} | user_admin | Payload: {"name": NAME, "profile": PROFILE }. | 

### User Stores

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all stores | GET /users/{userID}/stores | store_admin | - | 
| Create store | POST /users/{userID}/stores | store_write | Creates a datastore for the application indicated by the session (akin to creating an account) | 
| Get store | GET /users/{userID}/stores/{storeID} | store_admin | Gets the datastore metadata | 
| Update store | PUT /users/{userID}/stores/{storeID} | store_write | Updates the datastore for the application indicated by the session | 
| Delete store | DELETE /users/{userID}/stores/{storeID} | store_write | Deletes the datastore for the application indicated by the session (akin to deleting one's account) | 
| - | - | - | - |
| Get inode info (stat) | GET /users/{userID}/stores/{storeID}/inodes?path={path} | store_read | - | 
| - | - | - | - |
| Get directory files (ls) | GET /users/{userID}/stores/{storeID}/directories?path={path} | store_read | - | 
| Create directory (mkdir) | POST /users/{userID}/stores/{storeID}/directories?path={path} | store_write | Only works on the datastore for the application indicated by the session | 
| Delete directory (rmdir) | DELETE /users/{userID}/stores/{storeID}/directories?path={path} | store_write | Only works on the datastore for the application indicated by the session | 
| - | - | - | - |
| Get file data (open) | GET /users/{userID}/stores/{storeID}/files?path={path} | store_read | - | 
| Create file | POST /users/{userID}/stores/{storeID}/files?path={path} | store_write | Uploads `application/octet-stream` raw file data.  Only works on the datastore for the application indicated by the session. | 
| Update file | PUT /users/{userID}/stores/{storeID}/files?path={path} | store_write | Uploads `application/octet-stream` raw file data.  Only works on the datastore for the application indicated by the session. | 
| Delete file (rm) | DELETE /users/{userID}/stores/{storeID}/files?path={path} | store_write | Only works on the datastore for the application indicated by the session | 

### User Collections

TODO: work out precise semantics here

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all collections | GET /users/{userID}/collections | collection_read | - | 
| Create collection | POST /users/{userID}/collections | collection_admin | - | 
| Get all collection items | GET /users/{userID}/collections/{collectionID} | collection_read | - | 
| Create collection item | POST /users/{userID}/collections/{collectionID} | collection_write | - | 
| Get collection item | GET /users/{userID}/collections/{collectionID}/{itemID} | collection_read | - | 

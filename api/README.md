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
    'app_user_id': str   # public key address of an app-specific hardened child private key
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

TODO:  We need to figure out what `{userID}` and `{storeID}` are.  I think this should be the address of the key used to create `app_user_id`, since then it would be unlinkable to the data private key (i.e. `app_user_id` derived from a hardened child of the master private key).  `{storeID}` should similarly be the address of the datastore public key, since the datastore private key would be a hardened child of `app_user_id`'s private key.

I like the idea of using the datastore's public key's address as `{storeID}`, since we can also use it to verify the authenticity of the datastore metadata record.

TODO: We need a way for an application to ask for a specific blockchain ID that identifies the user.  This is not yet covered by any endpoints.

### Users

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Create user profile | POST /users | user_admin | Payload: {"blockchain_id": NAME, "profile": PROFILE} | 
| Get user profile | GET /users/{userID} | user_read | TODO: could this be a generic `lookup` endpoint? | 
| Delete user profile | DELETE /users/{userID} | user_admin | TODO: caller needs the blockchain ID | 
| Update profile | PATCH /users/{userID} | user_admin | Payload: {"blockchain_id": NAME, "profile": PROFILE }. | 

### User Stores

TODO: `{userID}` and `{storeID}` are not used in the `store_write` API family, since the caller (the application) should only be able to modify its own datastore.  We can ignore them precisely because they can be independently derived with the data private key and the session token fields.  However, we could use `{userID}` and `{storeID}` in the endpoint to NACK writes from unauthorized token bearers.

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all stores | GET /users/{userID}/stores | store_admin | TODO: drop this method; no way to easily implement it (and we probably don't want to for privacy and scalability reasons).  Compromise option: this lists all datastores created by this device. | 
| Create store | POST /users/{userID}/stores | store_write | Creates a datastore for the application indicated by the session (akin to instantiating one's account) | 
| Get store | GET /users/{userID}/stores/{storeID} | store_admin | Gets arbitrary datastore metadata | 
| Update store | PUT /users/{userID}/stores/{storeID} | store_admin | Updates arbitrary datastore metadata.  Payload: {"device_ids": [uuids], "drivers": [driver names]} | 
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
| Get all collections | GET /users/{userID}/collections | collection_read | TODO: drop this method too (unless we have a canonical list of collections) | 
| Create collection | POST /users/{userID}/collections | collection_admin | - | 
| Get all collection items | GET /users/{userID}/collections/{collectionID} | collection_read | - | 
| Create collection item | POST /users/{userID}/collections/{collectionID} | collection_write | - | 
| Get collection item | GET /users/{userID}/collections/{collectionID}/{itemID} | collection_read | - | 

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
| Ping the node | GET /v1/node/ping | - | Requires pre-shared secret in the `Authorization:` header |
| - | - | - | - |
| Get the node's config | GET /v1/node/config | - | Requires pre-shared secret in the `Authorization:` header. Returns a dict with the config file |
| Set one or more config fields in a config section | POST /v1/node/config/{section}?{key}={value} | - | Requires pre-shared secret in the `Authorization:` header. |
| Delete a config field | DELETE /v1/node/config/{section}/{key} | - | Requires pre-shared secret in the `Authorization:` header. |
| Delete a config section | DELETE /v1/node/config/{section} | - | Requires pre-shared secret in the `Authorization:` header. |
| - | - | - | - |
| Get registrar state | GET /v1/node/registrar/state | - | Requires pre-shared secret in the `Authorization:` header. |

### Wallet

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get wallet payment address | GET /v1/wallet/payment_address | wallet_read | - |
| Get wallet owner address | GET /v1/wallet/owner_address | wallet_read | - |
| Get wallet data public key | GET /v1/wallet/data_pubkey | wallet_read | - |
| - | - | - | - |
| Set the wallet | PUT /v1/wallet/keys | - | Requires a pre-shared secret in the `Authorization:` header |
| Get the wallet | GET /v1/wallet/keys | - | Requires a pre-shared secret in the `Authorization:` header |
| - | - | - | - |
| Get the wallet balance | GET /v1/wallet/balance | wallet_read | - |
| Get the wallet balance, specifying the minconfs for txns included | GET /v1/wallet/balance/{minconfs} | wallet_read | - |
| Withdraw funds from the wallet | POST /v1/wallet/balance | wallet_write | Payload: `{'address': str, 'amount': int, 'min_confs': int, 'tx_only':  bool} |
| - | - | - | - |
| Change wallet password | PUT /v1/wallet/password | wallet_write | Payload: `{'password': ..., 'new_password': ...}`|

### Authorization

| Method | API Call | API family | Notes |
| ------------- | ------------- | ------------- | ------------- |
| Create an authorization token | GET /v1/auth?authRequest={authRequestToken} | - | Requires a pre-shared secret in the `Authorization:` header. |

TODO: authRequestToken format

## Naming API

### Names

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all names | GET /v1/names | names | - | 
| Register name | POST /v1/names | register | Payload: {"name": NAME} | 
| Get name info | GET /v1/names/{name} | names | - | 
| Get name history | GET /v1/names/{name}/history | names | - | 
| Get historical zone file | GET /names/{name}/zonefile/{zoneFileHash} | zonefiles | - | 
| Revoke name | DELETE /v1/names/{name} | revoke | - | 
| Transfer name | PUT /v1/names/{name}/owner | transfer | Payload: {"owner": OWNER } | 
| Set zone file | PUT /v1/names/{name}/zonefile | update | Payload: {"zonefile": ZONE_FILE } | 
| Set zone file hash | PUT /v1/names/{name}/zonefile | update | Payload: {"zonefile_hash": ZONE_FILE_HASH } | 

### Addresses

| Method | API Call | API family | Notes |
| ------------- | ------------- | ------------- | ------------- |
| Get names owned by address | GET /v1/addresses/{address} | names | - |

### Namespaces

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all namespaces | GET /v1/namespaces | namespaces | - | 
| Create namespace | POST /v1/namespaces | namespace_registration | NOT IMPLEMENTED | 
| Launch namespace | PUT /v1/namespaces/{tld} | namespace_registration | NOT IMPLEMENTED | 
| Get namespace names | GET /v1/namespaces/{tld}/names | namespaces | - | 
| Pre-register a name | POST /v1/namespaces/{tld}/names | namespace_registration | NOT IMPLEMENTED | 
| Update pre-registered name | PUT /v1/namespaces/{tld}/names/{name} | namespace_registration | NOT IMPLEMENTED | 

### Prices

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get namespace price | GET /v1/prices/namespaces/{tld} | prices | May return a warning if the wallet does not have enough funds | 
| Get name price | GET /v1/prices/names/{name} | prices | May return a warning if the wallet does not have enough funds | 


### Blockchains

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get block operations | GET /v1/blockchains/{blockchainName}/block/{blockHeight} | blockchain | - | 
| Get raw name history | GET /v1/blockchains/{blockchainName}/names/{nameID}/history | blockchain |  - | 
| Get consensus hash | GET /v1/blockchains/{blockchainName}/consensusHash | blockchain | - | 
| Get pending transactions | GET /v1/blockchains/{blockchainName}/pending | blockchain | - |

| Method | API Call | API family | Notes |
| ------ | -------- | ---------- | ----- |
| Get unspent outputs | GET /v1/blockchains/{blockchainName}/{address}/unspent | blockchain | Returns `{"transaction_hash": str, "output_index": int, "value": int (satoshis), "script_hex": str, "confirmations": int}` |
| Broadcast transaction | POST /v1/blockchains/{blockchainName}/txs | blockchain | Takes `{"tx": str}` as its payload |

## Identity API

### Profiles

TODO: this is not decided

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Create profile | POST /v1/profiles | profile_write | Payload: `{"name": NAME, "profile": PROFILE}`.  Wallet must own the name. | 
| Get profile | GET /v1/profiles/{name} | profile_read | - |
| Delete profile | DELETE /v1/profiles/{name} | profile_write | Wallet must own {name} | 
| Update profile | PATCH /v1/profiles/{name} | profile_write | Payload: `{"blockchain_id": NAME, "profile": PROFILE }`.  Wallet must own the name | 

### Datastores

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Create store for this session | POST /v1/stores | store_write | Creates a datastore for the application indicated by the session |
| Get store metadata | GET /v1/stores/{storeID} | store_admin | - | 
| Delete store | DELETE /v1/stores/{storeID} | store_write | Deletes all files and directories in the store as well |
| - | - | - | - |
| Get inode info (stat) | GET /v1/stores/{storeID}/inodes?path={path} | store_read | - | 
| - | - | - | - |
| Get directory files (ls) | GET /v1/stores/{storeID}/directories?path={path} | store_read | Returns structured inode data | 
| Create directory (mkdir) | POST /v1/stores/{storeID}/directories?path={path} | store_write | Only works on the datastore for the application indicated by the session | 
| Delete directory (rmdir) | DELETE /v1/stores/{storeID}/directories?path={path} | store_write | Only works on the datastore for the application indicated by the session | 
| - | - | - | - |
| Get file data (cat) | GET /v1/stores/{storeID}/files?path={path} | store_read | Returns `application/octet-stream` data | 
| Create file | POST /v1/stores/{storeID}/files?path={path} | store_write | Uploads `application/octet-stream` raw file data.  Only works on the datastore for the application indicated by the session. | 
| Update file | PUT /v1/stores/{storeID}/files?path={path} | store_write | Uploads `application/octet-stream` raw file data.  Only works on the datastore for the application indicated by the session. | 
| Delete file (rm) | DELETE /v1/stores/{storeID}/files?path={path} | store_write | Only works on the datastore for the application indicated by the session | 

### Collections

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Create collection | POST /v1/collections | collection_admin | NOT IMPLEMENTED | 
| Get all collection items | GET /v1/collections/{collectionID} | collection_read | NOT IMPLEMENTED | 
| Create collection item | POST /v1/collections/{collectionID} | collection_write | NOT IMPLEMENTED | 
| Get collection item | GET /v1/{collectionID}/{itemID} | collection_read | NOT IMPLEMENTED | 

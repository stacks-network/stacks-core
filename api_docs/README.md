# Blockstack Specifications

## Dashboard Endpoints

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Dashboard Home | GET / | identity | Serves the identity management panel | 
| Auth Request View | GET /auth?authRequest={authRequestToken} | identity | Serves the auth request view | 

#### Explanation of the auth request view:

When the user clicks “login” in an application, the app should redirect the user to this endpoint. If the user already has an account, they will be redirected along with requested data. If the user doesn’t have an account, the user will be presented with each of the app’s requested permissions, then will satisfy or deny them. The dashboard will then redirect the user back with a JWT. The response JWT contains a signature and an API token that the app can use for future authorization of endpoints.

Each application specifies in advance which family of API calls it will need to make to function properly.  This list is passed along to the dashboard endpoint when creating an application account.  The account-creation page shows this list of API endpoints and what they do, and allows the user to line-item approve or deny them.  The list is stored by the API server in the local account structure, and the list is given to the application as part of the session JWT.  The API server will NACK requests to endpoints in API families absent from the session JWT. 

## Naming API

### Names

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all names | GET /names | names | - | 
| Register name | POST /names | register | - | 
| Get name info | GET /names/{name} | names | - | 
| Get name history | GET /names/{name}/history | names | - | 
| Get historical zone file | GET /names/{name}/zoneFile/{zoneFileHash} | zonefiles | - | 
| Delete user | DELETE /names/{name} | revoke | - | 
| Transfer name | PATCH /names/{name} | transfer | Payload: {"owner": OWNER } | 
| Set zone file | PATCH /names/{name} | update | Payload: {"zoneFile": ZONE_FILE } | 
| Set zone file hash | PATCH /names/{name} | update | Payload: {"zoneFileHash": ZONE_FILE_HASH } | 

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

## Identity API

### Users

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all users | GET /users | users | - | 
| Create user | POST /users | user_admin | - | 
| Get user | GET /users/{userID} | users | - | 
| Delete user | DELETE /users/{userID} | user_admin | - | 
| Update profile | PATCH /users/{userID} | user_admin | Payload: {"profile": PROFILE } | 

### User Stores

| Method  | API Call | API family | Notes | 
| ------------- | ------------- | ------------- | ------------- |
| Get all stores | GET /users/{userID}/stores | store_admin | - | 
| Create store | POST /users/{userID}/stores | store_admin | - | 
| Get store | GET /users/{userID}/stores/{storeID} | store_admin | - | 
| Update store | PUT /users/{userID}/stores/{storeID} | store_admin | - | 
| Delete store | DELETE /users/{userID}/stores/{storeID} | store_admin | - | 
| - | - | - | - |
| Get directory files (ls) | GET /users/{userID}/stores/{storeID}/directories?path={path} | store_read | - | 
| Get directory info (stat) | HEAD /users/{userID}/stores/{storeID}/directories?path={path} | store_read | - | 
| Create directory (mkdir) | POST /users/{userID}/stores/{storeID}/directories?path={path} | store_write | - | 
| Delete directory (rmdir) | DELETE /users/{userID}/stores/{storeID}/directories?path={path} | store_write | - | 
| - | - | - | - |
| Get file data (open) | GET /users/{userID}/stores/{storeID}/files?path={path} | store_read | - | 
| Get file info (stat) | HEAD /users/{userID}/stores/{storeID}/files?path={path} | store_read | - | 
| Create file | POST /users/{userID}/stores/{storeID}/files?path={path} | store_write | - | 
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
| Get app resource | GET /appResources/{appID}/{resourceID} | external_web | - | 

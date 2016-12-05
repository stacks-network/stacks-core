# Blockstack REST API

## Names

| Method  | API Call | Notes | 
| ------------- | ------------- | ------------- |
| Get all names | GET /names | - | 
| Register name | POST /names | - | 
| Get name info | GET /names/{name} | - | 
| Get name history | GET /names/{name}/history | - | 
| Get historical zone file | GET /names/{name}/zoneFile/{zoneFileHash}  | - | 
| Delete user | DELETE /names/{name} | - | 
| Transfer name | PATCH /names/{name} | Payload: {"owner": OWNER } | 
| Set zone file | PATCH /names/{name} | Payload: {"zoneFile": ZONE_FILE } | 
| Set zone file hash | PATCH /names/{name} | Payload: {"zoneFileHash": ZONE_FILE_HASH } | 

## Namespaces

| Method  | API Call | Notes | 
| ------------- | ------------- | ------------- |
| Get all namespaces | GET /namespaces | - | 
| Create namespace | POST /namespaces | - | 
| Launch namespace | PUT /namespaces/{tld} | - | 
| Get namespace names | GET /namespaces/{tld}/names | - | 
| Pre-register a name | POST /namespaces/{tld}/names | - | 
| Update pre-registered name | PUT /namespaces/{tld}/names/{name} | - | 

## Prices

| Method  | API Call | Notes | 
| ------------- | ------------- | ------------- |
| Get namespace price | GET /prices/namespaces/{tld} | - | 
| Get name price | GET /prices/names/{name} | - | 

## Users

| Method  | API Call | Notes | 
| ------------- | ------------- | ------------- |
| Get all users | GET /users | - | 
| Create user | POST /users | - | 
| Get user | GET /users/{userID} | - | 
| Delete user | DELETE /users/{userID} | - | 
| Update profile | PATCH /users/{userID} | Payload: {"profile": PROFILE } | 

## User Stores

| Method  | API Call | Notes | 
| ------------- | ------------- | ------------- |
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 

## User Collections

| Method  | API Call | Notes | 
| ------------- | ------------- | ------------- |
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 

## User Apps

| Method  | API Call | Notes | 
| ------------- | ------------- | ------------- |
| - | - | - | 
| - | - | - | 
| - | - | - | 
| - | - | - | 

## Blockchains

| Method  | API Call | Notes | 
| ------------- | ------------- | ------------- |
| - | - | - | 
| - | - | - | 
| - | - | - | 

---
layout: core
permalink: /:collection/:path.html
---
# Subdomain Design and Implementation

{:.no_toc}

Subdomains allow us to provide names to end users cheaply (and quickly). This
tutorial explains you how to create, register, and run a subdomain register, it
contains the following sections:

* TOC
{:toc}


## Strong subdomain ownership

For those who are new to this concept, it's a model where domains can
permanently, cryptographically delegate subdomains to particular keys,
relinquishing their ability to revoke the names or change the name
resolution details.

These names will be indicated with an `.`, e.g., `foo.bar.id`

## Overall Design

We can do this today with a special indexer & resolver endpoint and
without any changes to the core protocol.

We can do this by having a zone file record for each subdomain *i*
containing the following information:

1. An owner address *addr*
2. A sequence number *N*
3. A zonefile
4. A signature *S* of the above

The signature *S_i* must be verifiable with the address in the
*(N-1)*th entry for subdomain *i*.

## Zonefile Format

For now, the resolver will use an *TXT* record per subdomain to define
this information. The entry name will be `$(subdomain)`.


We'll use the format of [RFC 1464](https://tools.ietf.org/html/rfc1464)
for the TXT entry. We'll have the following strings with identifiers:

1. **parts** : this specifies the number of pieces that the
zonefile has been chopped into. TXT strings can only be 255 bytes,
so we chop up the zonefile.
2. **zf{n}**: part *n* of the zonefile, base64 encoded
3. **owner**: the owner address delegated to operate the subdomain
4. **seqn**: the sequence number
5. **sig**: signature of the above data.

```
$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
aaron TXT "owner=33VvhhSQsYQyCVE2VzG3EHa9gfRCpboqHy" "seqn=0" "parts=1" "zf0=JE9SSUdJTiBhYXJvbgokVFRMIDM2MDAKbWFpbiBVUkkgMSAxICJwdWJrZXk6ZGF0YTowMzAyYWRlNTdlNjNiMzc1NDRmOGQ5Nzk4NjJhNDlkMDBkYmNlMDdmMjkzYmJlYjJhZWNmZTI5OTkxYTg3Mzk4YjgiCg=="
```

The `registrar` entry indicates how to contact the registrar service
for clients of the domain wishing to register or modify their entry.

### Operations per Zonefile

At 4kb zonefile size, we can only fit around 20 updates per zonefile.

## Domain Operator Endpoint

The directory `subdomain_registrar/` contains our code for running a
subdomain registrar. It can be executed by running:

```
$ blockstack-subdomain-registrar start foo.id
```

Here, `foo.id` is the domain for which subdomains will be associated.

### Configuration and Registration Files

Configuration of the subdomain registrar is done through `~/.blockstack_subdomains/config.ini`

The sqlite database which stores the registrations is located alongside the config `~/.blockstack_subdomains/registrar.db`.

You can change the location of the config file (and the database), by setting the environment variable `BLOCKSTACK_SUBDOMAIN_CONFIG`

### Register Subdomain

Subdomain registrations can be submitted to this endpoint using a REST
API.

```
POST /register
```

The schema for registration is:

```
{
        'type' : 'object',
        'properties' : {
            'name' : {
                'type': 'string',
                'pattern': '([a-z0-9\-_+]{3,36})$'
            },
            'owner_address' : {
                'type': 'string',
                'pattern': schemas.OP_ADDRESS_PATTERN
            },
            'zonefile' : {
                'type' : 'string',
                'maxLength' : blockstack_constants.RPC_MAX_ZONEFILE_LEN
            }
        },
        'required':[
            'name', 'owner_address', 'zonefile'
        ],
        'additionalProperties' : True
}
```

The registrar will:

1. Check if the subdomain `foo` exists already on the domain.
2. Add the subdomain to the queue.

On success, this returns `202` and the message

```
{"status": "true", "message": "Subdomain registration queued."}
```

When the registrar wakes up to prepare a transaction, it packs the queued
registrations together and issues an `UPDATE`.


### Check subdomain registration status

A user can check on the registration status of their name via querying the
registrar.

This is an API call:
```
GET /status/{subdomain}
```

The registrar checks if the subdomain has propagated (i.e., the
registration is completed), in which case the following is returned:

```
{"status": "Subdomain already propagated"}
```

Or, if the subdomain has already been submitted in a transaction:

```
{"status": "Your subdomain was registered in transaction 09a40d6ea362608c68da6e1ebeb3210367abf7aa39ece5fd57fd63d269336399 -- it should propagate on the network once it has 6 confirmations."}
```

If the subdomain still hasn't been submitted yet:

```
{"status": "Subdomain is queued for update and should be announced within the next few blocks."}
```

If an error occurred trying to submit the `UPDATE` transaction, this endpoint will return an error
message in the `"error"` key of a JSON object.

### Updating Entries

The subdomain registrar does not currently support updating subdomain entries.

## Resolver Behavior

When a lookup like `foo.bar.id` hits the resolver, the resolver will need to:

1. Lookup the zonefile history of `bar.id`
2. Fetch all these zonefiles and filter by operations on `foo`
3. Verify that all `foo` operations are correct
4. Return the latest record for foo
5. Do a profile lookup for `foo.bar.id` by fetching the URLs in the entry.
*Note*, this spec does not define a priority order for fetching those URLs.

### Supported Core / Resolver Endpoints

Generally, domain endpoints are not aware of subdomains (only endpoints
aware of subdomains is `/v1/users/<foo.bar.tld>`,
`/v1/names/<foo.bar.tld>`, and `/v1/addresses/bitcoin/<foo.bar.tld>`)
The endpoints which *are* subdomain aware are marked as such in
[api-specs.md].

This means that search is *not* yet supported.

The lookups work just like normal -- it returns the user's
profile object:

```
$ curl -H "Authorization: bearer blockstack_integration_test_api_password" -H "Origin: http://localhost:3000" http://localhost:16268/v1/users/bar.foo.id -v -s | python -m json.tool
*   Trying 127.0.0.1...
* Connected to localhost (127.0.0.1) port 16268 (#0)
> GET /v1/users/bar.foo.id HTTP/1.1
> Host: localhost:16268
> User-Agent: curl/7.50.1
> Accept: */*
> Authorization: bearer blockstack_integration_test_api_password
> Origin: http://localhost:3000
>
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Server: SimpleHTTP/0.6 Python/2.7.12+
< Date: Thu, 03 Aug 2017 14:39:16 GMT
< content-type: application/json
< Access-Control-Allow-Origin: *
<
{ [66 bytes data]
* Closing connection 0
{
    "bar": {
        "@type": "Person",
        "description": "Lorem Ipsum Bazorem"
    }
}
```

Name info lookups are also supported (this should enable authenticating logins
with `blockstack.js`, but I will need to double check).

```
$ curl -H "Authorization: bearer XXXX" -H "Origin: http://localhost:3000" http://localhost:6270/v1/names/created_equal.self_evident_truth.id -s | python -m json.tool
{
    "address": "1AYddAnfHbw6bPNvnsQFFrEuUdhMhf2XG9",
    "blockchain": "bitcoin",
    "expire_block": -1,
    "last_txid": "0bacfd5a3e0ec68723d5948d6c1a04ad0de1378c872d45fa2276ebbd7be230f7",
    "satus": "registered_subdomain",
    "zonefile_hash": "48fc1b351ce81cf0a9fd9b4eae7a3f80e93c0451",
    "zonefile_txt": "$ORIGIN created_equal\n$TTL 3600\n_https._tcp URI 10 1 \"https://www.cs.princeton.edu/~ablankst/created_equal.json\"\n_file URI 10 1 \"file:///tmp/created_equal.json\"\n"
}
```

### Subdomain Caching

A resolver *caches* a subdomain's state by keeping a database of all
the current subdomain records. This database is automatically updated
when a new zonefile for a particularly domain is seen by the resolver
(this is performed lazily).

### Testing Subdomain Registrar and Resolution

You can run a subdomain registrar and resolver with blockstack-core in
regtest mode as follows:

```bash
IMAGE=$(docker run -dt -p 3000:3000 -p 6270:6270 -p 16269:16269 -p 18332:18332 -e BLOCKSTACK_TEST_CLIENT_RPC_PORT=6270 -e BLOCKSTACK_TEST_CLIENT_BIND=0.0.0.0 -e BLOCKSTACK_TEST_BITCOIND_ALLOWIP=172.17.0.0/16 quay.io/blockstack/integrationtests:master blockstack-test-scenario --interactive 2 blockstack_integration_tests.scenarios.browser_env)
```

Once you see `Test finished; doing checks` in that container's logs, the
registrar has started and is ready to accept requests. (We recommend
following the docker instructions below for running this test in
Docker, as it will fetch the source code for the registrar and set the
correct environment variables for it to run).

Once this environment has started, you can issue a registration request from curl:

```
curl -X POST -H 'Content-Type: application/json' --data '{"zonefile": "$ORIGIN baz\n$TTL 3600\n_file URI 10 1 \"file:///tmp/baz.profile.json\"\n", "name": "baz", "owner_address": "14x2EMRz1gf16UzGbxZh2c6sJg4A8wcHLD"}' http://localhost:3000/register/
```

This registers `baz.foo.id` -- you can check the registrar's status with

```
curl http://localhost:3000/status/baz
```

The API endpoints `/v1/users/<foo.bar.tld>`,
`/v1/names/<foo.bar.tld>`, and `/v1/addresses/bitcoin/<foo.bar.tld>` all work, so if you query the core API, you'll get a response.

For example:

```
curl http://localhost:6270/v1/names/baz.foo.id | python -m json.tool
```

Will return:
```
{
    "address": "1Nup2UcbVuVoDZeZCtR4vjSkrvTi8toTqc",
    "blockchain": "bitcoin",
    "expire_block": -1,
    "last_txid": "43bbcbd8793cdc52f1b0bd2713ed136f4f104a683a9fd5c89911a57a8c4b28b6",
    "satus": "registered_subdomain",
    "zonefile_hash": "e7e3aada18c9ac5189f1c54089e987f58c0fa51e",
    "zonefile_txt": "$ORIGIN bar\n$TTL 3600\n_file URI 10 1 \"file:///tmp/baz.profile.json\"\n"
}
```

### Running an interactive testing environment with the Subdomain Registrar service

Follow the [instructions here](https://github.com/blockstack/blockstack-core/blob/master/integration_tests/README.md) to download the regtesting Docker image.

Since the subdomain registrar service runs on port 3000, we need to do two things to expose this endpoint to interact with it from the browser:
- Open port 3000 with `-p 3000:3000`

Here's the full command you'd run to start the interactive testing scenario:

```bash
IMAGE=$(docker run -dt -p 3000:3000 -p 6270:6270 -p 16269:16269 -p 18332:18332 -e BLOCKSTACK_TEST_CLIENT_RPC_PORT=6270 -e BLOCKSTACK_TEST_CLIENT_BIND=0.0.0.0 -e BLOCKSTACK_TEST_BITCOIND_ALLOWIP=172.17.0.0/16 quay.io/blockstack/integrationtests:master blockstack-test-scenario --interactive 2 blockstack_integration_tests.scenarios.browser_env)
```

# Subdomain Design and Implementation

This section is predominantly cribbed from 
[this issue](https://github.com/blockstack/blockstack/issues/308).
The discussion there may be more active than the design doc here, but I 
will try to keep this up to date.

Subdomains will allow us to provide names to end users cheaply (and quickly). 

### Strong subdomain ownership

For those who are new to this concept, it's a model where domains can
permanently, cryptographically delegate subdomains to particular keys,
relinquishing their ability to revoke the names or change the name
resolution details.

These names will be indicated with an `.`, e.g., `foo.bar.id`

### Overall Design

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

### Zonefile Format

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

#### Operations per Zonefile

At 4kb zonefile size, we can only fit around 20 updates per zonefile.

### Domain Operator Endpoint

The directory `subdomain_registrar/` contains our code for running a
subdomain registrar. It can be executed by running:

```
$ blockstack-subdomain-registrar start foo.id
```

Here, `foo.id` is the domain for which subdomains will be associated.

#### Configuration and Registration Files

Configuration of the subdomain registrar is done through `~/.blockstack_subdomains/config.ini`

The sqlite database which stores the registrations is located alongside the config `~/.blockstack_subdomains/registrar.db`.

You can change the location of the config file (and the database), by setting the environment variable `BLOCKSTACK_SUBDOMAIN_CONFIG`

#### Register Subdomain

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


#### Check subdomain registration status

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

#### Updating Entries

The subdomain registrar does not currently support updating subdomain entries.

### Resolver Behavior

When a lookup like `foo.bar.id` hits the resolver, the resolver will need to:

1. Lookup the zonefile history of `bar.id`
2. Fetch all these zonefiles and filter by operations on `foo`
3. Verify that all `foo` operations are correct
4. Return the latest record for foo 
5. Do a profile lookup for `foo.bar.id` by fetching the URLs in the entry.
*Note*, this spec does not define a priority order for fetching those URLs.

#### Subdomain Caching

A resolver *caches* a subdomain's state by keeping a database of all
the current subdomain records. This database is automatically updated
when a new zonefile for a particularly domain is seen by the resolver
(this is performed lazily).


#### Todos

1. Testing bad zonefile transitions / updates.
   a. Wrong _n_ : this could be a rewrite, roll-back, whatever. [x]
   b. Bad signature [x]
2. Caching resolver database [x]
3. Batching updates [x]
4. Web API [x]
5. Resolver database cache for holding *multiple* domains, instead of just one [x]
6. Endpoint support for changing zonefiles/rotating keys [o]

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

1. A public key *PK*
2. A sequence number *N*
3. A set of URLs
4. A signature *S* of the above

The signature *S_i* must be provided by the public key in the
*(N-1)*th entry for subdomain *i*.

### Zonefile Format

For now, the resolver will use an *TXT* record per subdomain to define
this information. The entry name will be `_subd.$(name)`, and the
information will be comma-delimited:

```
$ORIGIN bar.id
$TTL 3600
pubkey TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
registrar URI 10 1 "bsreg://foo.com:8234"
_subd.foo TXT "pubkey:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,N:3,url:https://foobar.com/profile,url:https://dropbox.com/profile2,sig:data:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
```

The `registrar` entry indicates how to contact the registrar service
for clients of the domain wishing to register or modify their entry.

#### Support for compression

As we will be packing more data into the zonefiles, 4K may become
cumbersome. Compression can be explored in this case.

### Domain Operator Endpoint

We'll need to provide an API endpoint for sending operations to the
domain operator *and* an interface for sending commands to that
endpoint.

Operating a domain should be something that anyone running a Core node
should be able to do with a simple command:

```
$ blockstack domain foo.id start
```


#### AddSubdomain Command

```
addSubdomain("foo", "bar.id", pubkey_hex, urls)
```

This command adds a subdomain `foo` to a domain `bar.id`. This will:

1. Check if the subdomain `foo` exists already on the domain.
2. Add a record to the zonefile. 
3. Issue zonefile update.

#### UpdateSubdomain Command

```
updateSubdomain("foo", "bar.id", pubkey_hex, n, urls, signature)
```

This command updates subdomain `foo` to a domain `bar.id`. This will:

1. Check if the subdomain `foo` exists already on the domain
2. Check that n = n' + 1
3. Check the signature 
4. Issue zonefile update


### Resolver Behavior

When a lookup like `foo.bar.id` hits the resolver, the resolver will need to:

1. Lookup the zonefile history of `bar.id`
2. Fetch all these zonefiles and filter by operations on `foo`
3. Verify that all `foo` operations are correct
4. Return the latest record for foo 
5. Do a profile lookup for `foo.bar.id` by fetching the URLs in the entry.
*Note*, this spec does not define a priority order for fetching those URLs.

#### Subdomain Caching

A resolver may *cache* a subdomain's state by keeping a database of
all the current subdomain records.

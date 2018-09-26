# Zone File JS

[![CircleCI](https://img.shields.io/circleci/project/blockstack/zone-file-js/master.svg)](https://circleci.com/gh/blockstack/zone-file-js/tree/master)
[![npm](https://img.shields.io/npm/l/zone-file.svg)](https://www.npmjs.com/package/zone-file)
[![npm](https://img.shields.io/npm/v/zone-file.svg)](https://www.npmjs.com/package/zone-file)
[![npm](https://img.shields.io/npm/dm/zone-file.svg)](https://www.npmjs.com/package/zone-file)
[![Slack](http://chat.blockstack.org/badge.svg)](http://chat.blockstack.org/)

An [RFC1035-compliant](http://www.ietf.org/rfc/rfc1035.txt) DNS zone file parser and generator for Node.js and the browser. Based on the `dns-zonefile` library by Elgs Qian Chen.

### Installation

```bash
$ npm install zone-file
```

### Usage

#### Making Zone Files

```js
import { makeZoneFile } from 'zone-file'
let zoneFileText = makeZoneFile(zoneFileJson)
```

#### Parsing Zone Files

```js
import { parseZoneFile } from 'zone-file'
let zoneFileJson = parseZoneFile(zoneFileText)
```

#### Zone File Objects

```js
import { ZoneFile } from 'zone-file'

let zoneFileData = {
  "$origin": "MYDOMAIN.COM.",
  "$ttl": 3600,
  "a": [
    { "name": "@", "ip": "127.0.0.1" },
    { "name": "www", "ip": "127.0.0.1" }
  ]
}

let zoneFile = new ZoneFile(zoneFileData)
let zoneFileString = zoneFile.toString()
let zoneFileJson = zoneFile.toJSON()
```

### Background Info

This library accepts both zone data expressed as a JSON object or as a plain text zone file. It supports `SOA`, `NS`, `A`, `AAAA`, `CNAME`, `MX`, `PTR`, `SRV`, `TXT` and `URI` record types as well as the `$ORIGIN` keyword (for zone-wide use only). Each record type
(and the `$ORIGIN` keyword) is optional, although _bind_ expects to find at least an `SOA` record in a valid zone file.

#### Forward DNS Zone Files

The following JSON produces a zone file for a forward DNS zone:

```json
{
    "$origin": "MYDOMAIN.COM.",
    "$ttl": 3600,
    "soa": {
        "mname": "NS1.NAMESERVER.NET.",
        "rname": "HOSTMASTER.MYDOMAIN.COM.",
        "serial": "{time}",
        "refresh": 3600,
        "retry": 600,
        "expire": 604800,
        "minimum": 86400
    },
    "ns": [
        { "host": "NS1.NAMESERVER.NET." },
        { "host": "NS2.NAMESERVER.NET." }
    ],
    "a": [
        { "name": "@", "ip": "127.0.0.1" },
        { "name": "www", "ip": "127.0.0.1" },
        { "name": "mail", "ip": "127.0.0.1" }
    ],
    "aaaa": [
        { "ip": "::1" },
        { "name": "mail", "ip": "2001:db8::1" }
    ],
    "cname":[
        { "name": "mail1", "alias": "mail" },
        { "name": "mail2", "alias": "mail" }
    ],
    "mx":[
        { "preference": 0, "host": "mail1" },
        { "preference": 10, "host": "mail2" }
    ],
    "txt":[
        { "name": "txt1", "txt": "hello" },
        { "name": "txt2", "txt": "world" }
    ],
    "srv":[
        { "name": "_xmpp-client._tcp", "target": "jabber", "priority": 10, "weight": 0, "port": 5222 },
        { "name": "_xmpp-server._tcp", "target": "jabber", "priority": 10, "weight": 0, "port": 5269 }
    ]
}
```

_dns-zonefile_ will produce the following zone file from the above information,
while the following zone file can as well be parsed to produce the zone file
like above:

```
; Zone: MYDOMAIN.COM.
; Exported  (yyyy-mm-ddThh:mm:ss.sssZ): 2014-09-22T21:10:36.697Z

$ORIGIN MYDOMAIN.COM.
$TTL 3600

; SOA Record
@	 		IN	SOA	NS1.NAMESERVER.NET.	HOSTMASTER.MYDOMAIN.COM.	(
			1411420237	 ;serial
			3600	 ;refresh
			600	 ;retry
			604800	 ;expire
			86400	 ;minimum ttl
)

; NS Records
@	IN	NS	NS1.NAMESERVER.NET.
@	IN	NS	NS2.NAMESERVER.NET.

; MX Records
@	IN	MX	0	mail1
@	IN	MX	10	mail2

; A Records
@	IN	A	127.0.0.1
www	IN	A	127.0.0.1
mail	IN	A	127.0.0.1

; AAAA Records
@	IN	AAAA	::1
mail	IN	AAAA	2001:db8::1

; CNAME Records
mail1	IN	CNAME	mail
mail2	IN	CNAME	mail

; TXT Records
txt1	IN	TXT	"hello"
txt2	IN	TXT	"world"

; SRV Records
_xmpp-client._tcp	IN	SRV	10	0	5222	jabber
_xmpp-server._tcp	IN	SRV	10	0	5269	jabber
```

#### Reverse DNS Zone Files

This JSON will produce a zone file for a reverse DNS zone (the `$ORIGIN`
keyword is recommended for reverse DNS zones):

```json
{
	"$origin": "0.168.192.IN-ADDR.ARPA.",
	"$ttl": 3600,
	"soa": {
		"mname": "NS1.NAMESERVER.NET.",
		"rname": "HOSTMASTER.MYDOMAIN.COM.",
		"serial": "{time}",
		"refresh": 3600,
		"retry": 600,
		"expire": 604800,
		"minimum": 86400
	},
  "ns": [
      { "host": "NS1.NAMESERVER.NET." },
      { "host": "NS2.NAMESERVER.NET." }
  ],
  "ptr":[
      { "name": 1, "host": "HOST1.MYDOMAIN.COM." },
      { "name": 2, "host": "HOST2.MYDOMAIN.COM." }
  ]
}
```

_dns-zonefile_ will produce the following zone file from the above information,
while the following zone file can as well be parsed to produce the zone file
like above:

```
; Zone: 0.168.192.IN-ADDR.ARPA.
; Exported  (yyyy-mm-ddThh:mm:ss.sssZ): 2014-09-22T21:10:36.698Z

$ORIGIN 0.168.192.IN-ADDR.ARPA.
$TTL 3600

; SOA Record
@	 		IN	SOA	NS1.NAMESERVER.NET.	HOSTMASTER.MYDOMAIN.COM.	(
			1411420237	 ;serial
			3600	 ;refresh
			600	 ;retry
			604800	 ;expire
			86400	 ;minimum ttl
)

; NS Records
@	IN	NS	NS1.NAMESERVER.NET.
@	IN	NS	NS2.NAMESERVER.NET.

; PTR Records
1	IN	PTR	HOST1.MYDOMAIN.COM.
2	IN	PTR	HOST2.MYDOMAIN.COM.
```

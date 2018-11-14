---
layout: learn
permalink: /:collection/:path.html
---
# Developer FAQs
{:.no_toc}

These FAQs are intended for developers of Blockstack.

* TOC
{:toc}


## I'm a Web developer.  Can I build on Blockstack?

Yes!  Blockstack is geared primarily towards Web developers.  All of your
existing knowledge is immediately applicable to Blockstack.  Anything you can do
in a Web browser, you can do in a Blockstack app.

## I'm a non-Web developer.  Can I build on Blockstack?

Yes!  Blockstack implements a [RESTful API](https://core.blockstack.org) which
lets you interact with Blockstack from any language and any runtime.  In fact,
the reference client
([blockstack.js](https://github.com/blockstack/blockstack.js)) is mainly a
wrapper around these RESTful API calls, so you won't be missing much by using a
language other than Javascript.

## What's the difference between a Web app and a Blockstack app?

Blockstack apps are built like [single-page Web
apps](https://en.wikipedia.org/wiki/Single-page_application)---they are, in
fact, a type of Web application.

Blockstack apps are a subset of Web applications that use Blockstack's
technology to preserve the user's control over their identities and data.
As such, they tend to be simpler
in design and operation, since in many cases they don't have to host anything
besides the application's assets.

## Do I need to learn any new languages or frameworks?

No.  Blockstack applications are built using existing Web frameworks and programming
The only new thing you need to learn is either [blockstack.js](https://github.com/blockstack/blockstack.js) or
the [Blockstack RESTful API](https://core.blockstack.org).

## How does my Web app interact with Blockstack?

The [blockstack.js](https://github.com/blockstack/blockstack.js) library gives
any Web application the ability to interact with Blockstack's authentication and
storage services.  In addition, we supply a [public RESTful API](https://core.blockstack.org).

## What does `blockstack.js` do?

This is the reference client implementation for Blockstack.  You use it in your
Web app to do the following:

* Authenticate users
* Load and store user data
* Read other users' public data

## How do I use `blockstack.js`?

Please see the API documentation [here](https://github.com/blockstack/blockstack.js).

## How can I look up names and profiles?

You can use `blockstack.js`, or you can use the [public Blockstack Core
endpoint](https://core.blockstack.org).

## How can I read my public app data without `blockstack.js`?

The URLs to a user's public app data are in a canonical location in their
profile.  For example, here's how you would get public data from the
[Publik](https://publik.ykliao.com) app, stored under the Blockstack ID `ryan.id`.

1. Get the bucket URL
```bash
$ BUCKET_URL="$(curl -sL https://core.blockstack.org/v1/users/ryan.id | jq -r '."ryan.id"["profile"]["apps"]["http://publik.ykliao.com"]')"
$ echo "$BUCKET_URL"
https://gaia.blockstack.org/hub/1FrZTGQ8DM9TMPfGXtXMUvt2NNebLiSzad/
```

2. Get the data
```bash
$ curl -sL "${BUCKET_URL%%/}/statuses.json"
[{"id":0,"text":"Hello, Blockstack!","created_at":1515786983492}]
```

## How do I register Blockstack IDs?

You should use the [Blockstack Browser](https://github.com/blockstack/blockstack-browser).

## How do I register Blockstack Subdomains?

You can deploy and use a [Blockstack Subdomain Registrar]({{ site.baseurl }}/core/naming/subdomains.html), or
use an existing one.

## Can I programmatically register Blockstack IDs?

Blockstack applications do not currently have
have access to the user's wallet.  Users are expected to
register Blockstack IDs themselves.

However, if you feel particularly ambitious, you can do one of the following:

* Set up a `blockstack api` endpoint (see the project [README](https://github.com/blockstack/blockstack-core/blob/master/README.md)) and write a
  program to automatically register names.  Also, see the [API
documentation](https://blockstack.github.io/blockstack-core/#managing-names-register-a-name)
for registering names on this endpoint.

* Write a `node.js` program that uses `blockstack.js` to register
  names.  This is currently in development.

## Can I programmatically register Blockstack Subdomains?

Yes!  Once you deploy your own subdomain registrar, you can have your Web app
send it requests to register subdomains on your Blockstack ID.  You can also
create a program that drives subdomain registration on your Blockstack ID.

## Do you have a testnet or sandbox to experiment with Blockstack?

We have an [integration test framework](https://github.com/blockstack/blockstack-core/tree/master/integration_tests) that provides a
private Blockstack testnet.  It uses `bitcoin -regtest` to create a private
blockchain that you can interact with, without having to spend any Bitcoin or
having to wait for blocks to confirm.  Please see the
[README](https://github.com/blockstack/blockstack-core/blob/master/integration_tests/README.md) for details.

## Does Blockstack have a smart contract system?

No, not yet.  This is because
Blockstack's design philosophy focuses on keeping system complexity at the
"edges" of the network (e.g. clients), instead of the "core" of the network (e.g.
the blockchain), in accordance with the [end-to-end
principle](https://en.wikipedia.org/wiki/End-to-end_principle).
Generally speaking, this can be interpreted as "if you can do X without
a smart contract, you should do X without a smart contract."  This organizing
principle applies to a lot of useful decentralized applications.

## Can Blockstack applications interact with Bitcoin? Ethereum? Smart contracts? Other blockchains?

Yes!  Since Blockstack applications are built like Web applications, all you need to do is include the
relevant Javascript library into your application.

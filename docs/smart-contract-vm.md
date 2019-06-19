# Interacting with Smart Contracts Locally
## Instantiating a local development environment

You have two options for setting up a local development environment:

1. Pulling and using a docker image.
2. Building and installing from source.

### Pulling a docker image

Fetch the docker image

```bash
$ docker pull blockstack/blockstack-core:alpha.contracts.1
```

You can "enter" a docker environment using the following command:

```bash
$ docker run -it -v $HOME/blockstack-dev-data:/data/ blockstack/blockstack-core:alpha.contracts.1 bash
```

This also _mounts_ the folder `$HOME/blockstack-dev-data` so that you
can reuse any databases you construct while interacting with the
development environment. You can change that path to any other path
you wish to store data in.

### Installing from source

Build using `rust` and `cargo`:

```bash
$ cargo build --release
```

Install globally (you may have to run as sudoer):

```bash
$ cargo install --path .
```

You should now be able to run the command:

```bash
$ blockstack-core
```

## Running the sample programs

Once you have your environment setup (and, if you are using docker,
have _entered_ the docker environment), you can start interacting
with the smart contract VM.

Start by initializing a new database in the `/data/` directory

```bash
$ blockstack-core local initialize /data/db
```

You should see a message saying "Database created".


### Type check the sample programs

Start by type checking the "names" sample contract.

```bash
$ blockstack-core local check sample-programs/names.clar /data/db
```

You should get an error:

```
Type check error.
NoSuchContract("tokens")
Near:
( contract-call! tokens token-transfer burn-address name-price )
```

This happens because the `names.clar` contract _calls_ the `tokens` contract, and
that contract doesn't exist yet!

If you type check the `tokens.clar` contract, it should pass validation:

```bash
$ blockstack-core local check sample-programs/tokens.clar /data/db
```

When the `check` command executes successfully, it does not output any information,
it just exits with the stand UNIX `0` exit code.

### Instantiating a contract

Now, let's instantiate the tokens contract:

```bash
$ blockstack-core local launch tokens sample-programs/tokens.clar /data/db
```

Now that our development database has an instantiated tokens contract, let's see if
the `names.clar` contract will successfully pass the type checker now:

```bash
$ blockstack-core local check sample-programs/names.clar /data/db
```

It should pass validation. So now let's instantiate the names contract as well.

```bash
$ blockstack-core local launch names sample-programs/names.clar /data/db
```

### Executing a contract

Let's start off by minting some tokens and sending them to an address we'll use for our demo.

```bash
$ DEMO_ADDRESS=SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR
$ blockstack-core local execute /data/db tokens mint! $DEMO_ADDRESS 100000
```

This executes the public `mint!` function defined in the tokens contract, sending 100000 tokens to
the `$DEMO_ADDRESS`.

How can we see the effects of this contract execution? Well, we can use the `eval` command to
evaluate a program in read-only mode, within the context of an existing smart contract. In this case,
let's say we want to get the current _balance_ of our demo address:

```bash
$ echo "(get-balance '$DEMO_ADDRESS)" | blockstack-core local eval tokens /data/db
```

You should see the output:

```
Program executed successfully! Output: 
 110000
```

Now, let's register a name using the `names.clar` contract:

First, we have to preorder the name -- so let's compute the
hash of the name we want to register. Names in the sample contract are just
`int`s, so let's try to register the name `10`, and we'll _salt_ the hash with the
salt `8888`:

```bash
$ echo "(hash160 (xor 10 8888))" | blockstack-core local eval names /data/db
```

The value of our name hash is:

```
 0xb572fb1ce2e9665f1efd0994fe077b50c3a48fde
```

So now let's preorder the name using the _execute_ command:

```bash
$ blockstack-core local execute /data/db names preorder $DEMO_ADDRESS 0xb572fb1ce2e9665f1efd0994fe077b50c3a48fde 1000
```

This will execute the _preorder_ function defined in the `names.clar` contract, which reserves a name
by paying the name fee (in this case, 1000 tokens).

After executing the transaction, let's check the demo address' new balance:

```bash
$ echo "(get-balance '$DEMO_ADDRESS)" | blockstack-core local eval tokens /data/db
```

You should now see a balance of _109000_.

Now, let's finish register the name by executing the _register_ function:

```bash
$ blockstack-core local execute /data/db names register $DEMO_ADDRESS \'$DEMO_ADDRESS 10 8888
```

Let's see if we can lookup the "owner address" for the name:

```bash
$ echo "(get owner (fetch-entry name-map (tuple (name 10))))" | blockstack-core local eval names /data/db
```

And you should see:

```
Program executed successfully! Output: 
 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR
```

# Generating API Documentation

Blockstack core compiles with a documentation generator for the native functions
defined in the smart contract VM.

You can obtain them from the docker container with:

```
$ docker run -it -v $HOME/blockstack-dev-data:/data/ blockstack/blockstack-core:alpha.contracts.1 blockstack-core docgen
```

This outputs a JSON encoding of the API specifications for the native functions.


---
layout: core
permalink: /:collection/:path.html
---
# Welcome to Clarity
{:.no_toc}

Clarity is Blockstack's smart contracting language for use with the Stacks blockchain. Clarity supports programmatic control over digital assets within the Stacks blockchain (for example, BNS names, Stacks tokens, and so forth). This section discusses the following topics:

* TOC
{:toc}

<div class="uk-card uk-card-default uk-card-body">
<h5>Clarity is in pre-release</h5>
<p>Clarity, its accompanying toolset, and the SDK are in pre-release.  If you encounter issues with or have feature requests regarding Clarity, please create an issue on the <a href='https://github.com/blockstack/blockstack-core/issues' target='_blank'>blockstack/blockstack-core</a> repository. To read previous or join ongoing discussions about smart contracts in general and Clarity in particular, visit the <strong><a href='https://forum.blockstack.org/c/clarity' target='_blank'>Smart Contracts</a></strong> topic in the Blockstack Forum.
</p>
</div>

## Who should use smart contracts?

You can use Clarity to write standalone contracts or to write contracts that are part of decentralized applications (DApps) you write with the blockstack.js library. Smart contracts allow two parties to exchange anything of value (money, property, shares), in an automated, auditable, and secure way _without the services of a middleman_. Nick Szabo introduced the canonical metaphor for smart contracts, a vending machine. 

In Nick Szabo's metaphor, the vending machine is the smart contract. The buyer and machine owner are the two parties. A vending machine executes a set of hard-coded actions when the buyer engages with it. The machine displays the items and their prices. A buyer enters money into the machine which determines if the amount fails to mee, meets, or exceeds an item's price. Based on the amount, the machine asks for more money, dispenses an item, or dispenses and item and change. 

Not every application requires smart contracts. If you are not sure or are new to smart contracts concepts, you should read <a href="https://blockgeeks.com/guides/smart-contracts/" target="_blank">a good general explanation of smart contracts</a> before working with Clarity. 

## Language and program design

Clarity differs from most other smart contract languages in two essential ways:

* The language is not intended to be compiled.
* The language is not Turing complete. 
  
These differences allow for static analysis of programs to determine properties like runtime cost and data usage. 

A Clarity smart contract is composed of two parts &mdash; a data-space and a set of functions.  Only the associated smart contract may modify its corresponding data-space on the blockchain. Functions are private unless they are defined as public functions. Users call smart contracts' public functions by broadcasting a transaction on the blockchain which invokes the public function.

Contracts can also call public functions from other smart contracts. The ability to do a static analysis of a smart contract allows a user to determine dependency between contracts.

## The coding environment

Clarity is a list processing (LISP) language, as such it is not compiled. Omitting compilation prevents the possibility of error or bugs introduced at the compiler level. You can write Clarity smart contract programs on any operating system with a text editor. You can use any editor you are comfortable with such as Atom, Vim, or even Notepad. The Clarity files you create with an editor have a `.clar` extension.

Clarity is in pre-release and does not yet directly interact with the live Stacks blockchain. For the pre-release period you need a test environment to run Clarity contracts. Blockstack provides a Docker image called `clarity-developer-preview` that you can use or you can build a test environment locally from code. Either the Docker image or a local environment is sufficient for testing Clarity programming for standalone contracts.

You use the `clarity-cli` command line to check, launch, and execute standalone Clarity contracts. You can use this same command line to create simulate mining Stacks and inspecting a blockchain. 

Blockstack expects that some decentralized applications (DApp) will want to make use of Clarity contracts as part of their applications. For this purpose, you should use the Clarity SDK, also in pre-release. The SDK is a development environment, testing framework, and deployment tool. It provides a library for safe interactions with Clarity contracts from a DApp written with the blockstack.js library. 

## Basic building blocks of Clarity contracts

The basic building blocks of Clarity are _atoms_ and _lists_. An atom is a number or string of contiguous characters. Some examples of atoms:

* `token-sender`
* `10000`
* `SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR`

Atoms can be native functions, user-defined functions, variables, and values that appear in a program. Functions that mutate data by convention terminate with an `!` exclamation point, for example the `insert-entry!` function. 

A list is a sequences of atoms enclosed with `()` parentheses. Lists can contain other lists. Some examples of lists are:

* `(get-block-info time 10)`
* `(and 'true 'false)`
* `(is-none? (get id (fetch-entry names-map (tuple (name \"blockstack\")))))`

You can add comments to your Clarity contracts using  `;;` (double semi-colons). Both standalone and inline comments are supported.

```cl
;; Transfers tokens to a specified principal
(define-public (transfer (recipient principal) (amount int))
  (transfer! tx-sender recipient amount)) ;; returns: boolean
```

You use the `clarity-cli` command to check and launch a Clarity (`.clar`) program.

## hello-world example

The easiest program to run in any language is a hello world program. In Clarity, you can write this `hello-world.clar` program.

```cl
(begin 
   (print "hello world"))
```

This program defines a single `hello-world` expression that is excuted when the contract launches. The `begin` is a native Clarity function that evaluates the expressions input to it and returns the value of the last expression.  Here there is a single `print` expression. Both the `begin` and the `print` are enclosed in `()` parentheses.

For the pre-release, the Blockstack test environment includes the `clarity-cli` command for interacting with the contract and SQLite to support the data space. You create a SQLLite database to hold data related to Clarity contracts. This database simulates the blockchain by recording the contract activity. 

You can't run even an a hello-world program without first initializing a Clarity contract's data space within the database. You can use the `clarity-cli initialize` command to set up the database.

```clarity-cli initialize /data/db```

This command initializes the `db` database which resides in the `/data` directory of the container. You can name the database anything you like, the name `db` is not required. You can use SQLite to query this database:

```sql
sqlite> .open db
sqlite> .tables
contracts            maps_table           type_analysis_table
data_table           simmed_block_table 
sqlite> 
```

After you initialize the contract's data space, you can `check` a Clarity program for problems.

```clarity-cli check ./hello.clar /data/db```

As the name implies, the `check` ensures the contract definition passes a type check; passing programs will returns an exit code of `0` (zero). Once a contract passes a check, you `launch` it.

```bash
root@4224dd95b5f5:/data# clarity-cli launch hello ./hello.clar /data/db
Buffer(BuffData { data: [104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100] })
Contract initialized!
```

Because Clarity does not support simple strings, it stores the `hello world` string in a buffer. Printing out that string displays the ASCII representation for each character. You can see the record of this contract's launch in the corresponding database:

```sql
sqlite> select * from contracts;
1|hello|{"contract_context":{"name":"hello","variables":{},"functions":{}}}
sqlite> select * from type_analysis_table;
1|hello|{"private_function_types":{},"variable_types":{},"public_function_types":{},"read_only_function_types":{},"map_types":{}}
sqlite> 
```

## Language rules and limitations

The Clarity smart contract has the following limitations:

* The only atomic types are booleans, integers, fixed length buffers, and principals
* Recursion is illegal and there is no lambda function.
* Looping may only be performed via `map`, `filter`, or `fold`
* There is support for lists of the atomic types, however, the only variable length lists in the language appear as function inputs; There is no support for list operations like append or join.
* Variables are created via `let` binding and there is no support for mutating functions like `set`.


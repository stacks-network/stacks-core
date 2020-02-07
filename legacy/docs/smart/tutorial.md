---
layout: core
permalink: /:collection/:path.html
---
# Hello Clarity tutorial

In this tutorial, you learn how to use Clarity, Blockstack's smart contracting language. Use this tutorial to get a quick introduction to Clarity and the default Blockstack test environment.

* TOC
{:toc}

<div class="uk-card uk-card-default uk-card-body">
<h5>Clarity is in pre-release</h5>
<p>Clarity and its accompanying toolset are in pre-release. If you encounter issues with or have feature requests regarding Clarity, please create an issue on the <a href='https://github.com/blockstack/blockstack-core/issues' target='_blank'>blockstack/blockstack-core</a> repository. To read previous or join ongoing discussions about smart contracts in general and Clarity in particular, visit the <strong><a href='https://forum.blockstack.org/c/clarity' target='_blank'>Smart Contracts</a></strong> topic in the Blockstack Forum.
</p>
</div>

## Before you begin (pre-requisites)

The Clarity language goes live in the next Stacks blockchain fork. Until the fork, you can run Clarity in a test environment. You run this test environment in a Docker container.  Before you begin this tutorial, make sure you have <a href="https://docs.docker.com" target="_blank">Docker installed on your workstation</a>.

If for some reason you don't want to run the test environment with Docker, you can build and maintain a local environment. Instructions for downloading and building the environment are available in the `blockstack/blockstack-core` repository's <a href='https://github.com/blockstack/blockstack-core' target='_blank'>README</a> file.


## Task 1: Set up the test environment

Blockstack publishes the `clarity-developer-preview` image on Docker hub. A container built from this image contains sample programs, the Blockstack Core, and tools for working with them. In this task, you use Docker to pull and and run the image on your local workstation. 

1. Pull the Blockstack core `clarity-developer-preview` image from Docker Hub.

    ```bash
    $ docker pull blockstack/blockstack-core:clarity-developer-preview
    ``` 

2. Start the Blockstack Core test environment with a Bash shell.

    ```bash
    $ docker run -it -v $HOME/blockstack-dev-data:/data/ blockstack/blockstack-core:clarity-developer-preview bash
    ```

    The launches a container with the Clarity test environment and opens a bash shell into the container. The `-v` flag creates a local `$HOME/blockstack-dev-data` directory in your workstation and mounts it at the `/data` directory inside the container. The shell opens into the `src/blockstack-core` directory. This directory contains the source for a core and includes Clarity contract samples you can run.

3. List the contents of the `sample-programs` directory.

   ```bash
   root@f88368ba07b2:/src/blockstack-core# ls sample-programs/
   names.clar  tokens.clar
   ```

   The sample programs directory contains two simple Clarity programs. Clarity code files have a `.clar` suffix.

4. Go ahead and display the contents of the `tokens.clar` program with the `cat` command.

    ```bash
    root@c28600552694:/src/blockstack-core# cat sample-programs/tokens.clar 
    ```

    The next section gives you an introduction to the Clarity language by way of examining this program's code.

## Task 2: Review a simple Clarity program

If you haven't already done so, use the `cat` or `more` command to display the `tokens.clar` file's code. Clarity is designed for static analysis; it is not a compiled language and is not Turing complete. It language is a LISP-like language.  LISP is an acronym for list processing. 

The first line of the `tokens.clar` program contains a user-defined `get-balance` function.  

```cl
(define (get-balance (account principal))
  (default-to 0 (get balance (fetch-entry tokens (tuple (account account))))))
```

`get-balance` is a private function because it is constructed with the `define` call. To create public functions, you would use the `define-public` function. Public functions can be called from other contracts or even from the command line with the `clarity-cli`.

Notice the program is enclosed in  `()` (parentheses) and each statement as well.  The `get-balance` function takes an `account` argument of the special type `principal`. Principals represent a spending entity and are roughly equivalent to a Stacks address. 

Along with the `principal` types, Clarity supports  booleans, integers, and fixed length buffers. Variables are created via `let` binding but there is no support for mutating functions like `set`.

The next sequence of lines shows an `if` statement that allows you to set conditions for execution in the language.. 

```cl
(define (token-credit! (account principal) (tokens int))
  (if (<= tokens 0)
      (err "must move positive balance")
      (let ((current-amount (get-balance account)))
        (begin
          (set-entry! tokens (tuple (account account))
                      (tuple (balance (+ tokens current-amount))))
          (ok tokens)))))
```

Every smart contract has both a data space and code. The data space of a contract may only interact with that contract. This particular function is interacting with a map named `tokens`. The `set-entry!` function is a native function that sets the value associated with the input key to the inputted value in the `tokens` data map. Because `set-entry!`  mutates data so it has an `!` exclamation point; this is by convention in Clarity. 

In the first `token-transfer` public function, you see that it calls the private `get-balance` function and passes it `tx-sender`. The `tx-sender` isa a globally defined variable that represents the the current principal.

```cl
(define-public (token-transfer (to principal) (amount int))
  (let ((balance (get-balance tx-sender)))
    (if (or (> amount balance) (<= amount 0))
        (err "must transfer positive balance and possess funds")
        (begin
          (set-entry! tokens (tuple (account tx-sender))
                      (tuple (balance (- balance amount))))
          (token-credit! to amount)))))

(define-public (mint! (amount int))
   (let ((balance (get-balance tx-sender)))
     (token-credit! tx-sender amount)))

(token-credit! 'SZ2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQ9H6DPR 10000)
(token-credit! 'SM2J6ZY48GV1EZ5V2V5RB9MP66SW86PYKKQVX8X0G 300)
```

The final two lines of the program pass a principal, represented by a Stacks address, and an amount to the private user-defined `token-credit` function.

Smart contracts may call other smart contracts using a `contract-call!` function. This means that if a transaction invokes a function in a given smart contract, that function is able to make calls into other smart contracts on your behalf. The ability to read and do a static analysis of Clarity code allows clients to learn which functions a given smart contract will ever call. Good clients should always warn users about any potential side effects of a given transaction.

Take a moment to `cat` the contents of the `names.clar` file.

```bash
cat names.clar
````

Which `tokens.clar` function is being called? 

## Task 3: Initialize data-space and launch contracts

In this task, you interact with the the contracts using the `clarity-cli` command line. 

1. Initialize a new `db` database in the `/data/` directory

    ```bash
    #  clarity-cli initialize /data/db
    Database created
    ```

    You should see a message saying `Database created`. The command creates an SQLlite database.  The database is available in the container and also in your workstation. In this tutorial, your workstation mount should at this point contain the `$HOME/blockstack-dev-data/db`  directory.

2. Type check the `names.clar` contract.

    ```bash
    #  clarity-cli check sample-programs/names.clar /data/db
    ```
    You should get an error:

    ```
    Type check error.
    NoSuchContract("tokens")
    ```

    This happens because the `names.clar` contract _calls_ the `tokens.clar` contract, and that contract has not been created on the blockchain.

3. Type check the `tokens.clar` contract, it should pass a check as it does not use the `contract-call` function:

    ```bash
    # clarity-cli check sample-programs/tokens.clar /data/db
    Checks passed.
    ```

    When the `check` command executes successfully and exits with the stand UNIX `0` exit code.

4. Launch the `tokens.clar` contract.

   You use the `launch` command to instantiate a contract on the Stacks blockchain. If you have dependencies between contracts, for example names.clar is dependent on tokens.clar, you must launch the dependency first.

    ```bash
    # clarity-cli launch tokens sample-programs/tokens.clar /data/db
    Contract initialized!
    ```
    
    Once launched, you can execute the contract or a public method on the contract. Your development database has an instantiated `tokens` contract. If you were to close the container and restart it later with the same mount point and you wouldn't need to relaunch that database; it persists until you remove it from your local drive.
    
5. Recheck the `names.clar` contract.

    ```bash
    # clarity-cli check sample-programs/names.clar /data/db
    ```

   The program should pass validation because its dependency on `tokens.clar` is fulfilled. 
   
6. Instantiate the `names.clar` contract as well.

    ```bash
    # clarity-cli launch names sample-programs/names.clar /data/db
    ```

## Task 4. Examine the SQLite database

The test environment uses a SQLite database to represent the blockchain. You initialized this database when you ran this earlier:

```bash
clarity-cli initialize /data/db
```

As you work the contracts, data is added to the `db` database because you pass this database as a parameter, for example:

```bash
clarity-cli launch tokens sample-programs/tokens.clar /data/db
```

The database exists on your local workstation and persists through restarts of the container. You can use this database to examine the effects of your Clarity programs. The tables in the SQLite database are the following:


<table class="uk-table">
  <tr>
    <th>Name</th>
    <th>Purpose</th>
  </tr>
  <tr>
    <td><code>contracts</code></td>
    <td>Lists contracts and stores a JSON description of it.</td>
  </tr>
  <tr>
    <td><code>data_table</code></td>
    <td>Lists the data associated with a contract.</td>
  </tr>
    <tr>
    <td><code>maps_table</code></td>
    <td>Lists maps types associated with a contract and stores JSON description of it.</td>
  </tr>
    <tr>
    <td><code>simmed_block_table</code></td>
    <td>Supports the test environment by simulating responses to blockchain information queries.</td>
  </tr>
    <tr>
    <td><code>type_analysis_table</code></td>
    <td>Provides a JSON describing contract data.</td>
  </tr>
</table>

While not required, you can install SQLite in your local environment and use it to examine the data associated with and impacted by your contract. For example, this what the `maps_table` contains after you initialize the `tokens` contract.

```
sqlite> select * from maps_table;
1|tokens|tokens|{"Atom":{"TupleType":{"type_map":{"account":{"Atom":"PrincipalType"}}}}}|{"Atom":{"TupleType":{"type_map":{"balance":{"Atom":"IntType"}}}}}
sqlite> 
````

## Task 5: Execute a public function

In this section, you use the public `mint!` function in the  `tokens` contract to mint some new tokens. 

1. Use the `clarity_cli` command to create a demo address.

   ```
   # clarity-cli generate_address
   SP26CHZZ26Q25WDD1CFJYSED169PS9HTNX445XKDG
   ```

2. Add the address to your environment.

    ```bash
    # DEMO_ADDRESS=SP26CHZZ26Q25WDD1CFJYSED169PS9HTNX445XKDG
    ```

3. Get the current balance of your new address.

   ```bash
    # echo "(get-balance '$DEMO_ADDRESS)" | clarity-cli eval tokens /data/db
    Program executed successfully! Output: 
    0
    ```

    This command uses the private `get-balance` function in the `tokens` contract and pipes the result to the `eval` subcommand. The `eval` subcommand lets you evaluate both public and _private_ functions of a contract in read-only mode.

4. Try minting some tokens and sending them to an address we'll use for our demo.

    ```bash
    # clarity-cli execute /data/db tokens mint! $DEMO_ADDRESS 100000
    ```

    This executes the public `mint!` function defined in the tokens contract, sending 100000 tokens to you `$DEMO_ADDRESS`.

5. Use the `clarity-cli eval` command to check the result of this call.

    ```bash
    # echo "(get-balance '$DEMO_ADDRESS)" | clarity-cli eval tokens /data/db
    Program executed successfully! Output: 
    100000
    ```

## Task 6: Spend tokens by registering a name 

Now, let's register a name using the `names.clar` contract. Names are just integers in this sample contract, so you'll register the name 10.

1. Compute the hash of the name we want to register. 

   You'll _salt_ the hash with the salt `8888`:

    ```bash
    # echo "(hash160 (xor 10 8888))" | clarity-cli eval names /data/db
    Program executed successfully! Output: 
    0xb572fb1ce2e9665f1efd0994fe077b50c3a48fde
    ```

    The value of the name hash is:

    ```
    0xb572fb1ce2e9665f1efd0994fe077b50c3a48fde
    ```

2. Preorder the name using the _execute_ command:

    ```bash
    # clarity-cli execute /data/db names preorder $DEMO_ADDRESS 0xb572fb1ce2e9665f1efd0994fe077b50c3a48fde 1000
    Transaction executed and committed. Returned: 0
    ```

    This executes the public `preorder` function defined in the `names.clar` contract. The function reserves a name by paying the name fee (in this case, 1000 tokens).

3.  Check the demo address' new balance:

    ```bash
    # echo "(get-balance '$DEMO_ADDRESS)" | clarity-cli eval tokens /data/db
    Program executed successfully! Output: 
    99000
    ```

4. Register the name by executing the _register_ function:

    ```bash
    # clarity-cli execute /data/db names register $DEMO_ADDRESS \'$DEMO_ADDRESS 10 8888
    Transaction executed and committed. Returned: 0clarity-cli execute /data/db names register $DEMO_ADDRESS \'$DEMO_ADDRESS 10 8888
    ```

5. Lookup the "owner address" for the name:

    ```bash
    # echo "(get owner (fetch-entry name-map (tuple (name 10))))" | clarity-cli eval names /data/db
    Program executed successfully! Output: 
    (some 'SP26CHZZ26Q25WDD1CFJYSED169PS9HTNX445XKDG)
    ```

## Where to go next
{:.no_toc}

* <a href="clarityRef.html">Clarity Language Reference</a>
* <a href="clarityRef.html">clarity-cli command line</a>
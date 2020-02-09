---
layout: core
permalink: /:collection/:path.html
---
# clarity-cli command line
{:.no_toc}

You use the `clarity-cli` command to work with smart contracts within the Blockstack virtual environment. This command has the following subcommands:

* TOC
{:toc}

## initialize         

```bash
clarity-cli initialize [vm-state.db]
```

Initializes a local VM state database. If the database exists, this command throws an error.

## mine_block

```bash
clarity-cli mine_block [block time] [vm-state.db]
```

Simulates mining a new block.

## get_block_height  

```bash
clarity-cli get_block_height [vm-state.db]
```

Prints the simulated block height.

## check

```bash
clarity-cli check [program-file.scm] (vm-state.db)
```

Type checks a potential contract definition.

## launch

```bash
clarity-cli launch [contract-name] [contract-definition.scm] [vm-state.db]
```

Launches a new contract in the local VM state database.

## eval

```bash
clarity-cli eval [context-contract-name] (program.scm) [vm-state.db]
```

Evaluates, in read-only mode, a program in a given contract context.

## eval_raw

```bash
```

Type check and evaluate an expression for validity inside of a function’s source. It does not evaluate within a contract or database context.

## repl

```bash
clarity-cli repl
```

Type check and evaluate expressions in a stdin/stdout loop.

## execute

```bash
clarity-cli execute [vm-state.db] [contract-name] [public-function-name] [sender-address] [args...]
```

Executes a public function of a defined contract.

## generate_address

```bash
clarity-cli generate_address
```

Generates a random Stacks public address for testing purposes.
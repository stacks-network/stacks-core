# Contributing to Stacks Blockchain

Stacks Blockchain is open-source software written in Rust.  Contributions should adhere to the following best practices.

You can find information on joining online community forums (Discord, mailing list etc.) in the [README](README.md).

#### Table Of Contents

[Code of Conduct](#code-of-conduct)

[How Can I Contribute?](#how-can-i-contribute)
* [Development Workflow](#development-workflow)
* [Contributing Conventions](#contributing-conventions)

[Style](#style)
* [Git Commit Messages](#git-commit-messages)
* [Rust Styleguide](#rust-styleguide)
* [Comments](#comments)

[Versioning](#versioning)

[Non-Consensus Breaking Release Process](#non-consensus-breaking-release-process)

[License Agreement](#licensing-and-contributor-license-agreement)

# Code of Conduct

This project and everyone participating in it is governed by this [Code of Conduct](CODE_OF_CONDUCT.md).

# How Can I Contribute?
## Development Workflow

- For typical development, branch off of the `develop` branch.
- For consensus breaking changes, branch off of the `next` branch.
- For hotfixes, branch off of `master`.

Normal releases in this repository that add features such as improved RPC endpoints, improved boot-up time, new event observer fields or event types, etc., are released on a monthly schedule. The currently staged changes for such releases are in the [develop branch](https://github.com/stacks-network/stacks-blockchain/tree/develop). It is generally safe to run a `stacks-node` from that branch, though it has received less rigorous testing than release tags. If bugs are found in the `develop` branch, please do report them as issues on this repository.

For fixes that impact the correct functioning or liveness of the network, _hotfixes_ may be issued. These are patches
to the main branch which are backported to the develop branch after merging. These hotfixes are categorized by priority
according to the following rubric:

- **High Priority**. Any fix for an issue that could deny service to the network as a whole, e.g., an issue where a particular kind of invalid transaction would cause nodes to stop processing requests or shut down unintentionally. Any fix for an issue that could cause honest miners to produce invalid blocks.
- **Medium Priority**. Any fix for an issue that could cause miners to waste funds.
- **Low Priority**. Any fix for an issue that could deny service to individual nodes.

### Tests and Coverage

PRs must include test coverage. However, if your PR includes large tests or tests which cannot run in parallel (which is the default operation of the `cargo test` command), these tests should be decorated with `#[ignore]`.
If you add `#[ignore]` tests, you should add your branch to the filters for the `all_tests` job in our circle.yml (or if you are working on net code or marf code, your branch should be named such that it matches the existing filters there).

A test should be marked `#[ignore]` if:

1. It does not _always_ pass `cargo test` in a vanilla environment (i.e., it does not need to run with `--test-threads 1`).
2. Or, it runs for over a minute via a normal `cargo test` execution (the `cargo test` command will warn if this is not the case).

### Documentation Updates

- Any major changes should be added to the [CHANGELOG](CHANGELOG.md).
- Mention any required documentation changes in the description of your pull request.
- If adding an RPC endpoint, add an entry for the new endpoint to the OpenAPI spec `./docs/rpc/openapi.yaml`.
- If your code adds or modifies any major features (struct, trait, test, module, function, etc.), each should be documented according to our [style rules](#comments).
  - To generate HTML documentation for the library, run `cargo doc --no-deps --open`.
  - It's possible to check the percentage of code coverage by (a) switching to the nightly version of rust (can run `rustup default nightly`, and also might need to edit `rust-toolchain` file to say "nightly" instead of "stable"), and (b) running `RUSTDOCFLAGS='-Z unstable-options --show-coverage' cargo doc`.

### Each file should include relevant unit tests

Each Rust file should contain a `mod test {}` definition, in which unit tests
should be supplied for the file's methods.  Unit tests should cover a maximal
amount of code paths.

## Contributing Conventions

### Simplicity of implementation

The most important consideration when accepting or rejecting a contribution is
the simplicity (i.e. ease of understanding) of its implementation.
Contributions that are "clever" or introduce functionality beyond the scope of
the immediate problem they are meant to solve will be rejected.

#### Type simplicity

Simplicity of implementation includes simplicity of types.  Type parameters
and associated types should only be used if there are at
least two possible implementations of those types.

Lifetime parameters should only be introduced if the compiler cannot deduce them
on its own.

### Builds with a stable Rust compiler
We use a recent, stable Rust compiler.  Contributions should _not_
require nightly Rust features to build and run.

### Use built-in logging facilities

Stacks Blockchain implements logging macros in `util::log`.  If your code needs to
output data, it should use these macros _exclusively_ for doing so.  The only
exception is code that is explicitly user-facing, such as help documentation.

### Minimal dependencies

Adding new package dependencies is very much discouraged.  Exceptions will be
granted on a case-by-case basis, and only if deemed absolutely necessary.

### Minimal global macros

Adding new global macros is discouraged.  Exceptions will only be given if
absolutely necessary.

### Minimal compiler warnings

Contributions should not trigger compiler warnings if possible, and should not
mask compiler warnings with macros.  Common sources of compiler warnings that
will not be accepted include, but are not limited to:

* unnecessary imports
* unused code
* variable naming conventions
* unhandled return types

### Minimal `unsafe` code

Contributions should not contain `unsafe` blocks if at all possible.

### Error definitions

Each module should include an `Error` enumeration in its `mod.rs` that encodes
errors specific to the module.  All error code paths in the module should return
an `Err` type with one of the module's errors.

# Style
## Git Commit Messages
Aim to use descriptive git commit messages. We try to follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/).
The general format is as follows:
```
<type>[optional scope]: <one-line description>

[optional body]
[optional footer(s)]
```
Common types include build, ci, docs, fix, feat, test, refactor, etc.

## Rust styleguide

This repository uses the default rustfmt formatting style. PRs will be checked against `rustfmt` and will _fail_ if not properly formatted.

You can check the formatting locally via:

```bash
cargo fmt --all -- --check
```

You can automatically reformat your commit via:

```bash
cargo fmt --all
```

### Code block consistency

Surrounding code blocks with `{` and `}` is encouraged, even when the enclosed
block is a single statement.  Blocks in the same lexical scope must use
consistent conventions.  For example, consider the following:

```
match foo {
   1..2 => {
      // this is a single statement, but it is surrounded
      // with { and } because the other blocks in the match
      // statement need them.
      Ok(true)
   },
   3..4 => {
      error!("Bad value for foo");
      Err(Error::BadFoo)
   },
   _ => {
      // similarly, this block uses { }
      Ok(true)
   }
}

// conversely, all of the arms of this match statement
// have one-statement blocks, so { and } can be elided.
match bar {
   1..2 => Some("abc"),
   3..4 => Some("def"),
   _ => None
}
```

### Whitespace

All contributions should use the same whitespacing as the rest of the project.
Moreover, Pull requests where a large number of changes only deal with whitespace will be
rejected.

## Comments
Comments are very important for the readability and correctness of the codebase. The purpose of comments is:

* Allow readers to understand the roles of components and functions without having to check how they are used.
* Allow readers to check the correctness of the code against the comments.
* Allow readers to follow tests.

In the limit, if there are no comments, the problems that arise are:

* Understanding one part of the code requires understanding *many* parts of the code. This is because the reader is forced to learn the meanings of constructs inductively through their use. Learning how one construct is used requires understanding its neighbors, and then their neighbors, and so on, recursively. Instead, with a good comment, the reader can understand the role of a construct with `O(1)` work by reading the comment.
* The user cannot be certain if there is a bug in the code, because there is no distinction between the contract of a function, and its definition.
* The user cannot be sure if a test is correct, because the logic of the test is not specified, and the functions do not have contracts.

### Comment Formatting

Comments are to be formatted in typical `rust` style, specifically:

- Use markdown to format comments.

- Use the triple forward slash "///" for modules, structs, enums, traits and functions. Use double forward slash "//" for comments on individual lines of code.

- Start with a high-level description of the function, adding more sentences with details if necessary.

- When documenting panics, errors, or other conceptual sections, introduce a Markdown section with a single `#`, e.g.:

  - ```
    # Errors
    * ContractTooLargeError: Thrown when `contract` is larger than `MAX_CONTRACT_SIZE`.
    ```

### Content of Comments
The following kinds of things should have comments.

#### Components
Comments for a component (`struct`, `trait`, or `enum`) should explain what the overall
purpose of that component is. This is usually a concept, and not a formal contract. Include anything that is not obvious about this component.

**Example:**

```rust
/// The `ReadOnlyChecker` analyzes a contract to determine whether
/// there are any violations of read-only declarations. By a "violation"
/// we mean a function that is marked as "read only" but which tries
/// to modify chainstate.
pub struct ReadOnlyChecker<'a, 'b> {
```

This comment is considered positive because it explains the concept behind the class at a glance, so that the reader has some idea about what the methods will achieve, without reading each method declaration and comment. It also defines some terms that can be used in the comments on the method names.

#### Functions

The comments on a function should explain what the function does, without having to read it. Wherever practical, it should specify the contract of a function, such that a bug in the logic could be discovered by a discrepancy between contract and implementation, or such that a test could be written with only access to the function comment.

Without being unnecessarily verbose, explain how the output is calculated
from the inputs. Explain the side effects. Explain any restrictions on the inputs. Explain failure
conditions, including when the function will panic, return an error
or return an empty value.

**Example:**

```rust
/// A contract that does not violate its read-only declarations is called
/// *read-only correct*.
impl<'a, 'b> ReadOnlyChecker<'a, 'b> {
    /// Checks each top-level expression in `contract_analysis.expressions`
    /// for read-only correctness.
    ///
    /// Returns successfully iff this function is read-only correct.
    ///
    /// # Errors
    ///
    /// - Returns CheckErrors::WriteAttemptedInReadOnly if there is a read-only
    ///   violation, i.e. if some function marked read-only attempts to modify
    ///   the chainstate.
    pub fn run(&mut self, contract_analysis: &ContractAnalysis) -> CheckResult<()>
```

This comment is considered positive because it explains the contract of the function in pseudo-code. Someone who understands the constructs mentioned could, e.g., write a test for this method from this description.

#### Comments on Implementations of Virtual Methods 

Note that, if a function implements a virtual function on an interface, the comments should not
repeat what was specified on the interface declaration. The comment should only add information specific to that implementation.

### Data Members
Each data member in a struct should have a comment describing what that member
is, and what it is used for. Such comments are usually brief but should
clear up any ambiguity that might result from having only the variable
name and type.

**Example:**

```rust
pub struct ReadOnlyChecker<'a, 'b> {
    /// Mapping from function name to a boolean indicating whether
    /// the function with that name is read-only.
    /// This map contains all functions in the contract analyzed.
    defined_functions: HashMap<ClarityName, bool>,
```

This comment is considered positive because it clarifies users might have about the content and role of this member. E.g., it explains that the `bool` indicates whether the function is *read-only*, whereas this cannot be gotten from the signature alone.

#### Tests

Each test should have enough comments to help an unfamiliar reader understand:

1. what is conceptually being tested
1. why a given answer is expected

Sometimes this can be obvious without much comments, perhaps from the context,
or because the test is very simple. Often though, comments are necessary.

**Example:**

```rust
#[test]
#[ignore]
fn transaction_validation_integration_test() {
    /// The purpose of this test is to check if the mempool admission checks
    /// for the post tx endpoint are working as expected wrt the optional
    /// `mempool_admission_check` query parameter.
    ///
    /// In this test, we are manually creating a microblock as well as
    /// reloading the unconfirmed state of the chainstate, instead of relying
    /// on `next_block_and_wait` to generate microblocks. We do this because
    /// the unconfirmed state is not automatically being initialized
    /// on the node, so attempting to validate any transactions against the
    /// expected unconfirmed state fails.
```

This comment is considered positive because it explains the purpose of the test (checking the case of an optional parameter), it also guides the reader to understand the low-level details about why a microblock is created manually.

### How Much to Comment

Contributors should strike a balance between commenting "too much" and commenting "too little". Commenting "too much" primarily includes commenting things that are clear from the context. Commenting "too little" primarily includes writing no comments at all, or writing comments that leave important questions unresolved.

Human judgment and creativity must be used to create good comments, which convey important information with small amounts of text. There is no single rule which can determine what a good comment is. Longer comments are *not* always better, since needlessly long comments have a cost: they require the reader to read more, take up whitespace, and take longer to write and review.

#### Don't Restate the Function Names

The contracts of functions should be implemented precisely enough that tests could be written looking only at the declaration and the comments (and without looking at the definition!). However:

* **the author should assume that the reader has already read and understood the function name, variable names, type names, etc.**
* **the author should only state information that is new**

So, if a function and its variables have very descriptive names, then there may be nothing to add in the comments at all!

**Bad Example**

```
/// Appends a transaction to a block.
fn append_transaction_to_block(transaction:Transaction, &mut Block) -> Result<()>
```

This is considered bad because the function name already says "append transaction to block", so it doesn't add anything to restate it in the comments. However, *do* add anything that is not redundant, such as elaborating what it means to "append" (if there is more to say), or what conditions will lead to an error.

**Good Example**

```
/// # Errors
///
/// - BlockTooBigError: Is returned if adding `transaction` to `block` results
/// in a block size bigger than MAX_BLOCK_SIZE.
fn append_transaction_to_block(transaction:Transaction, block:&mut Block) -> Result<()>
```

This is considered good because the reader builds on the context created by the function and variable names. Rather than restating them, the function just adds elements of the contract that are not implicit in the declaration. 

#### Do's and Dont's

*Don't* over-comment by documenting things that are clear from the context. E.g.:

- Don't document the types of inputs or outputs, since these are parts of the type signature in `rust`.
- Don't necessarily document standard "getters" and "setters", like `get_clarity_version()`, unless there is unexpected information to add with the comment.
- Don't explain that a specific test does type-checking, if it is in a file that is dedicated to type-checking.

*Do* document things that are not clear, e.g.:

- For a function called `process_block`, explain what it means to "process" a block.
- For a function called `process_block`, make clear whether we mean anchored blocks, microblocks, or both.
- For a function called `run`, explain the steps involved in "running".
- For a function that takes arguments `peer1` and `peer2`, explain the difference between the two.
- For a function that takes an argument `height`, either explain in the comment what this is the *height of*. Alternatively, expand the variable name to remove the ambiguity.
- For a test, document what it is meant to test, and why the expected answers are, in fact, expected.

### Changing Code Instead of Comments

Keep in mind that better variable names can reduce the need for comments, e.g.:

* `burnblock_height` instead of `height` may eliminate the need to comment that `height` refers to a burnblock height
* `process_microblocks` instead of `process_blocks` is more correct, and may eliminate the need to to explain that the inputs are microblocks
* `add_transaction_to_microblock` explains more than `handle_transaction`, and reduces the need to even read the comment

# Versioning

This repository uses a 5 part version number.

```
X.Y.Z.A.n

X = 2 and does not change in practice unless there’s another Stacks 2.0 type event
Y increments on consensus-breaking changes
Z increments on non-consensus-breaking changes that require a fresh chainstate (akin to semantic MAJOR)
A increments on non-consensus-breaking changes that do not require a fresh chainstate, but introduce new features (akin to semantic MINOR)
n increments on patches and hot-fixes (akin to semantic PATCH)
```

For example, a node operator running version `2.0.10.0.0` would not need to wipe and refresh their chainstate
to upgrade to `2.0.10.1.0` or `2.0.10.0.1`. However, upgrading to `2.0.11.0.0` would require a new chainstate.

# Non-Consensus Breaking Release Process

For non-consensus breaking releases, this project uses the following release process:

1. The release must be timed so that it does not interfere with a *prepare phase*.  The timing of the next Stacking cycle can be found [here](https://stacking.club/cycles/next).
A release to `mainnet` should happen at least 24 hours before the start of a new cycle, to avoid interfering with the prepare phase. So, start by being aware of when the release can happen.

1. Before creating the release, the release manager must determine the *version
number* for this release.  The factors that determine the version number are
discussed in [Versioning](#versioning).  We assume, in this section,
that the change is not consensus-breaking.  So, the release manager must first
determine whether there are any "non-consensus-breaking changes that require a
fresh chainstate". This means, in other words, that the database schema has
changed, but an automatic migration was not implemented. Then, the release manager 
should determine whether this is a feature release, as opposed to a hot fix or a
patch. Given the answers to these questions, the version number can be computed.

1. The release manager enumerates the PRs or issues that would _block_
   the release. A label should be applied to each such issue/PR as
   `2.0.x.y.z-blocker`. The release manager should ping these
   issue/PR owners for updates on whether or not those issues/PRs have
   any blockers or are waiting on feedback.

1. The release manager should open a `develop -> master` PR. This can be done before
   all the blocker PRs have merged, as it is helpful for the manager and others
   to see the staged changes.

1. The release manager must update the `CHANGELOG.md` file with summaries what
was `Added`, `Changed`, and `Fixed`. The pull requests merged into `develop`
can be found
[here](https://github.com/stacks-network/stacks-blockchain/pulls?q=is%3Apr+is%3Aclosed+base%3Adevelop+sort%3Aupdated-desc). Note, however, that GitHub apparently does not allow sorting by
*merge time*, so, when sorting by some proxy criterion, some care should
be used to understand which PR's were *merged* after the last `develop ->
master` release PR.  This `CHANGELOG.md` should also be used as the description
of the `develop -> master` so that it acts as *release notes* when the branch
is tagged.

1. Once the blocker PRs have merged, the release manager will create a new tag
   by manually triggering the [`stacks-blockchain` Github Actions workflow](https://github.com/stacks-network/stacks-blockchain/actions/workflows/stacks-blockchain.yml) against the `develop` branch, inputting the release candidate tag, `2.0.x.y.z-rc0`,
   in the Action's input textbox.

1. Once the release candidate has been built, and docker images, etc. are available,
   the release manager will notify various ecosystem participants to test the release
   candidate on various staging infrastructure:

   1. Stacks Foundation staging environments.
   1. Hiro PBC testnet network.
   1. Hiro PBC mainnet mock miner.

   The release candidate should be announced in the `#stacks-core-devs` channel in the
   Stacks Discord. For coordinating rollouts on specific infrastructure, the release
   manager should contact the above participants directly either through e-mail or
   Discord DM. The release manager should also confirm that the built release on the
   [Github releases](https://github.com/stacks-network/stacks-blockchain/releases/)
   page is marked as `Pre-Release`.

1. The release manager will test that the release candidate successfully syncs with
   the current chain from genesis both in testnet and mainnet. This requires starting
   the release candidate with an empty chainstate and confirming that it synchronizes
   with the current chain tip.

1. If bugs or issues emerge from the rollout on staging infrastructure, the release
   will be delayed until those regressions are resolved. As regressions are resolved,
   additional release candidates should be tagged. The release manager is responsible
   for updating the `develop -> master` PR with information about the discovered issues,
   even if other community members and developers may be addressing the discovered
   issues.

1. Once the final release candidate has rolled out successfully without issue on the
   above staging infrastructure, the release manager tags 2 additional `stacks-blockchain`
   team members to review the `develop -> master` PR. If there is a merge conflict in this
   PR, this is the protocol: open a branch off of develop, merge master into that branch, 
   and then open a PR from this side branch to develop. The merge conflicts will be 
   resolved. 

1. Once reviewed and approved, the release manager merges the PR, and tags the release
   via the [`stacks-blockchain` Github action](https://github.com/stacks-network/stacks-blockchain/actions/workflows/stacks-blockchain.yml) by clicking "Run workflow" and providing the release version as the tag (e.g.,
   `2.0.11.1.0`) This creates a release and release images. Once the release has been
   created, the release manager should update the Github release text with the
   `CHANGELOG.md` "top-matter" for the release.

# Licensing and contributor license agreement

Stacks Blockchain is released under the terms of the GPL version 3.  Contributions
that are not licensed under compatible terms will be rejected.  Moreover,
contributions will not be accepted unless _all_ authors accept the project's
contributor license agreement.

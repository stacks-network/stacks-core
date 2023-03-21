# How to Create and Review PRs

This document describes some best practices on how to create and review PRs in this context.  The target audience is people who have commit access to this repository (reviewers), and people who open PRs (submitters).  This is a living document -- developers can and should document their own additional guidelines here.

## Overview

Blockchain software development requires a much higher degree of rigor than most other kinds of software.  This is because with blockchains, **there is no roll-back** from a bad deployment.

Therefore, making changes to the codebase is necessarily a review-intensive process.  No one wants bugs, but **no one can afford consensus bugs**.  This page describes how to make and review _non-consensus_ changes.  The process for consensus changes includes not only the entirety of this document, but also the [SIP process](https://github.com/stacksgov/sips/blob/main/sips/sip-000/sip-000-stacks-improvement-proposal-process.md).

A good PR review sets both the submitter and reviewers up for success.  It minimizes the time required by both parties to get the code into an acceptable state, without sacrificing quality or safety.  Unlike most other software development practices, _safety_ is the primary concern.  A PR can and will be delayed or closed if there is any concern that it will lead to unintended consensus-breaking changes.

This document describes some best practices on how to create and review PRs in this context.  The target audience is people who have commit access to this repository (reviewers), and people who open PRs (submitters).  This is a living document -- developers can and should document their own additional guidelines here.

This document is formatted like a checklist.  Each paragraph is one goal or action item that the reviewer and/or submitter must complete.  The **key take-away** from each paragraph is bolded.

## Reviewer Expectations

The overall task of a reviewer is to create an **acceptance plan** for the submitter.  This is simply the list of things that the submitter _must_ do in order for the PR to be merged.  The acceptance plan should be coherent, cohesive, succinct, and complete enough that the reviewer will understand exactly what they need to do to make the PR worthy of merging, without further reviews.  The _lack of ambiguity_ is the most important trait of an acceptance plan.

Reviewers should **complete the review in one round**.  The reviewer should provide enough detail to the submitter that the submitter can make all of the requested changes without further supervision.  Whenever possible, the reviewer should provide all of these details publicly as comments, so that _other_ reviewers can vet them as well.  If a reviewer _cannot_ complete the review in one round due to its size and complexity, then the reviewer may request that the PR be simplified or broken into multiple PRs.

Reviewers should make use of Github's "pending comments" feature. This ensures that the review is "atomic": when the reviewer submits the review, all the comments are published at once.

Reviewers should aim to **perform a reviewer in one sitting** whenever possible.  This enables a reviewer to time-box their review, and ensures that by the time they finish studying the patch, they have a complete understanding of what the PR does in their head.  This, in turn, sets them up for success when writing up the acceptance plan.  It also enables reviewers to mark time for it on their calendars, which helps everyone else develop reasonable expectations as to when things will be done.

Code reviews should be timely.  A PR review should begin no more than **2 business days** after the PR is submitted.  The `develop` and `next` branches in particular often change quickly, so letting a PR languish only creates more merge work for the submitter.  If a review cannot be begun within 2 business days, then the reviewers should **tell the submitter when they can begin**.  This gives the reviewer the opportunity to keep working on the PR (if needed) or even withdraw and resubmit it.

Reviewers must, above all else, **ensure that submitters follow the PR checklist** below. 

**As a reviewer, if you do not understand the PR's code or the potential consequences of the code, it is the submitter's responsibility to simplify the code, provide better documentation, or withdraw the PR.**

## Submitter Expectations

Everyone is busy all the time with a host of different tasks.  Consequently, a PR's size and scope should be constrained so that **a review can be written for it no more than 2 hours.**  This time block starts when the reviewer opens the patch, and ends when the reviewer hits the "submit review" button.  If it takes more than 2 hours, then the PR should be broken into multiple PRs unless the reviewers agree to spend more time on it.  A PR can be rejected if the reviewers believe they will need longer than this.

The size and scale of a PR depend on the reviewers' abilities to process the change.  Different reviewers and submitters have different levels of familiarity with the codebase.  Moreover, everyone has a different schedule -- sometimes, some people are more busy than others.

A successful PR submitter **takes the reviewers' familiarity and availability into account** when crafting the PR, even going so far as to ask in advance if a particular person could be available for review.

Providing detailed answers to reviewer questions is often necessary as a submitter. In order to make this information accessible even after a PR has merged, submitters should strive to incorporate any clarifications into code comments.

## Submission Checklist

A PR submission's text should **answer the following questions** for reviewers:

* What problem is being solved by this PR?
* What does the solution do to address them?
* Why is this the best solution?  What alternatives were considered, and why are they worse?
* What do reviewers need to be familiar with in order to provide useful feedback?
* What issue(s) are addressed by this PR?
* What are some hints to understanding some of the more intricate or clever parts of the PR?
* Does this PR change any database schemas? Does a node need to re-sync from genesis when this PR is applied?

In addition, the PR submission should **answer the prompts of the Github template** we use for PRs.

The code itself should adhere to our coding guidelines, which both submitters and reviewers should check.

## Coding Guidelines

### Documentation

* Each file must have a **copyright statement**.
* Any new non-test modules should have **module-level documentation** explaining what the module does, and how it fits into the blockchain as a whole.
* Any new files must have some **top-of-file documentation** that describes what the contained code does, and how it fits into the overall module.

Within the source files, the following **code documentation** standards are expected:

* Each public function, struct, enum, and trait should have a Rustdoc comment block describing the API contract it offers.  This goes for private structs and traits as well.
* Each _non-trivial_ private function should likewise have a Rustdoc comment block.  Trivial ones that are self-explanatory, like getters and setters, do not need documentation.  If you are unsure if your function needs a docstring, err on the side of documenting it.
* Each struct and enum member must have a Rustdoc comment string indicating what it does, and how it is used.  This can be as little as a one-liner, as long as the relevant information is communicated.

### Factoring

* **Public or exported struct, enum, and trait definitions go into the `mod.rs` file**.  Private structs, enums, and traits can go anywhere.

* **Each non-`mod.rs` file implements at most one subsystem**.  It may include multiple struct implementations and trait implementations.  The filename should succinctly identify the subsystem, and the file-level documentation must succinctly describe it and how it relates to other subsystems it interacts with.

* Directories represent collections of related but distinct subsystems.

* To the greatest extent possible, **business logic and I/O should be separated**.  A common pattern used in the codebase is to place the business logic into an "inner" function that does not do I/O, and handle I/O reads and writes in an "outer" function.  The "outer" function only does the needful I/O and passes the data into the "inner" function.  The "inner" function is often private, whereas the "outer" function is often public.

### Refactoring

* **Any PR that does a large-scale refactoring must be in its own PR**.  This includes PRs that touch multiple subsystems.  Refactoring often adds line noise that obscures the new functional changes that the PR proposes.  Small-scale refactorings are permitted to ship with functional changes.

* Refactoring PRs can generally be bigger, because they are easier to review.  However, **large refactorings that could impact the functional behavior of the system should be discussed first** before carried out.  This is because it is imperative that they do not stay open for very long (to keep the submitter's maintenance burden low), but nevertheless reviewing them must still take at most 2 hours.  Discussing them first front-loads part of the review process.

### Databases

* If at all possible, **the database schema should be preserved**.  Exceptions can be made on a case-by-case basis.  The reason for this is that it's a big ask for people to re-sync nodes from genesis when they upgrade to a new point release.

* Any changes to a database schema must also ship with a **new schema version and new schema migration logic**, as well as _test coverage_ for it.

* The submitter must verify that **any new database columns are indexed**, as relevant to the queries performed on them.  Table scans are not permitted if they can be avoided (and they almost always can be).  You can find table scans manually by setting the environment variable `BLOCKSTACK_DB_TRACE` when running your tests (this will cause every query executed to be preceded by the output of `EXPLAIN QUERY PLAN` on it).

* Database changes **cannot be consensus-critical** unless part of a hard fork (see below).

* If the database schema changes and no migration can be feasibly done, then the submitter **must spin up a node from genesis to verify that it works** _before_ submitting the PR.  This genesis spin-up will be tested again before the next node release is made.

### Data Input

* **Data from the network, from Bitcoin, and from the config file is untrusted.**  Code that ingests such data _cannot assume anything_ about its structure, and _must_ handle any possible byte sequence that can be submitted to the Stacks node.

* **Data previously written to disk by the node is trusted.** If data loaded from the database that was previously stored by the node is invalid or corrupt, it is appropriate to panic.

* **All input processing is space-bound.**  Every piece of code that ingests data must impose a maximum size on its byte representation.  Any inputs that exceed this size _must be discarded with as little processing as possible_.

* **All input deserialization is resource-bound.** Every piece of code that ingests data must impose a maximum amount of RAM and CPU required to decode it into a structured representation.  If the data does not decode with the allotted resources, then no further processing may be done and the data is discarded.

* **All network input reception is time-bound.**  Every piece of code that ingests data _from the network_ must impose a maximum amount of time that ingestion can take.  If the data takes too long to arrive, then it must be discarded without any further processing.  There is no time bound for data ingested from disk or passed as an argument; this requirement is meant by the space-bound requirement.

* **Untrusted data ingestion must not panic.**  Every piece of code that ingests untrusted data must gracefully handle errors.  Panicking failures are forbidden for such data.  Panics are only allowed if the ingested data was previously written by the node (and thus trusted).

### Non-consensus Changes to Blocks, Microblocks, Transactions, and Clarity

Any changes to code that alters how a block, microblock, or transaction is processed by the node should be **treated as a breaking change until proven otherwise**.  This includes changes to the Clarity VM.  The reviewer _must_ flag any such changes in the PR, and the submitter _must_ convince _all_ reviewers that they will _not_ break consensus.

Changes that touch any of these four code paths must be treated with the utmost care.  If _any_ core developer suspects that a given PR would break consensus, then they _must_ act to prevent the PR from merging.

### Changes to the Peer Network

Any changes to the peer networking code **must be run in production before the PR can be merged.**  The submitter should set up a testable node or set of nodes that reviewers can interact with.

Changes to the peer network should be deployed incrementally and tested by multiple ecosystem entities when possible to verify that they function properly in a production setting.

### Performance Improvements

Any PRs that claim to improve performance **must ship with reproducible benchmarks** that accurately measure the improvement.  This data must also be reported in the PR submission.

### Error Handling

* **Each subsystem must have its own `Error` type.**  Error types of aggregate subsystems are encouraged to both wrap their constituent subsystems' `Error` types in their own `Error` types, as well as provide conversions from them via a `From` trait implementation.

* Functions that act on externally-submitted data **must never panic**.  This includes code that acts on incoming network messages, blockchain data, and burnchain (Bitcoin) data.

* **Runtime panics should be used sparingly**.  Generally speaking, a runtime panic is only appropriate if there is no reasonable way to recover from the error condition.  For example, this includes (but is not limited to) disk I/O errors, database corruption, and unreachable code.

* If a runtime panic is desired, it **must have an appropriate error message**.

### Logging

* Log messages should be informative and context-free as possible.  They are used mainly to help us identify and diagnose problems.  They are _not_ used to help you verify that your code works; that's the job of a unit test.

* **DO NOT USE println!() OR eprintln!()**.  Instead, use the logging macros (`test_debug!()`, `trace!()`, `debug!()`, `info!()`, `warn!()`, `error!()`).

* Use **structured logging** whenever you find yourself logging multiple data with a format string.

* Use `trace!()` and `test_debug!()` liberally.  It only runs in tests.

* Use `debug!()` for information that is relevant for diagnosing problems at runtime.  This is off by default, but can be turned on with the `BLOCKSTACK_DEBUG` environment variable.

* Use `info!()` sparingly.

* Use `warn!()` or `error!()` only when there really is a problem.

### Consensus-Critical Code

A **consensus-critical change** is a change that affects how the Stacks blockchain processes blocks, microblocks, or transactions, such that a node with the patch _could_ produce a different state root hash than a node without the patch.  If this is even _possible_, then the PR is automatically treated as a consensus-critical change and must ship as part of a hard fork.  It must also be described in a SIP.

* **All changes to consensus-critical code must be opened against `next`**.  It is _never acceptable_ to open them against `develop` or `master`.

* **All consensus-critical changes must be gated on the Stacks epoch**.  They may only take effect once the system enters a specific epoch (and this must be documented).

A non-exhaustive list of examples of consensus-critical changes include:

* Adding or changing block, microblock, or transaction wire formats
* Changing the criteria under which a burnchain operation will be accepted by the node
* Changing the data that gets stored to a MARF key/value pair in the Clarity or Stacks chainstate MARFs
* Changing the order in which data gets stored in the above
* Adding, changing, or removing Clarity functions
* Changing the cost of a Clarity function
* Adding new kinds of transactions, or enabling certain transaction data field values that were previously forbidden.

### Testing

* **Unit tests should focus on the business logic with mocked data**.  To the greatest extent possible, each error path should be tested _in addition to_ the success path.  A submitter should expect to spend most of their test-writing time focusing on error paths; getting the success path to work is often much easier than the error paths.

* **Unit tests should verify that the I/O code paths work**, but do so in a way that does not "clobber" other tests or prevent other tests from running in parallel (if it can be avoided).  This means that unit tests should use their own directories for storing transient state (in `/tmp`), and should bind on ports that are not used anywhere else.

* If randomness is needed, **tests should use a seeded random number generator if possible**.  This ensures that they will reliably pass in CI.

* When testing a consensus-critical code path, the test coverage should verify that the new behavior is only possible within the epoch(s) in which the behavior is slated to activate.  Above all else, **backwards-compatibility is a hard requirement.**

* **Integration tests are necessary when the PR has a consumer-visible effect**.  For example, changes to the RESTful API, event stream, and mining behavior all require integration tests.

* Every consensus-critical change needs an integration test to verify that the feature activates only when the hard fork activates.

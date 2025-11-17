# Property Testing

In the stacks-core repo, we want every new consensus-critical feature to be thoroughly tested: we want unit tests with tight assertions, test fixtures, integration tests, and end-to-end tests. In order to ensure that the new functions are sufficiently tested, we also want to have *property tests* in place.

Property testing incorporates a few different concepts, but fundamentally, property testing means:

1. Writing tests which accept only an input for the function being tested (i.e., there's no "expected" result, like in a fixture test).
2. The test executes the function being tested on the input and then asserts that the output matches certain properties.
3. The test harness has the ability to generate new inputs for the function being tested

The goal is that every new feature and function in the stacks-core repo supplies property tests for the new feature.

## `proptest-rs`

The test harness we'll use for this will be [`proptest-rs`](https://proptest-rs.github.io/proptest/). There's a bit of a learning curve to using this library, but once you get used to it (and we develop enough strategies for input generation in our codebase) it shouldn't pose too much of a burden.

We recommend perusing the [`proptest-rs`](https://proptest-rs.github.io/proptest/) tutorial as it contains a lot of useful theory and information. At a high-level, though, to use the library, you'll define testing functions which return proptest error types indicating whether or not the test failed or the input was invalid for the test (panics also work like a normal rust test). Then, you'll use macros provided by the library to define input-generation *strategies* for your test function. `proptest` defines strategies for many standard types in rust, and also provides macros for combining/mapping strategies into new ones (examples discussed below may be useful). Once you've done this, your new proptest will run like any other rust unit test during `cargo test`. During the test execution, `proptest-rs` generates and runs 250 cases for the property test before marking the test as *passed*.

## Examples

There are a couple examples of proptest in action in our codebase. The first is a set of property tests for new clarity functions in Epoch 3.3 (Clarity4). These tests generate clarity code (as strings) for property tests that assert the new clarity functions behave as expected ([vm::tests::post_conditions](clarity/src/vm/tests/post_conditions.rs#L1761)). The second is a property test for `make_reward_set`, which is used to translate data pulled from the `pox` contracts into the actual reward set ([chainstate::stacks::tests::reward_set](stackslib/src/chainstate/stacks/tests/reward_set.rs)).

### Reward Set Example

The reward set example can be thought of as two major pieces: the test itself and the input generation. Let's first look at the test:

```rust
pub fn check_make_reward_set(
    pox_settings: PoxConstants,
    addresses: &[RawRewardSetEntry],
    unstacked_ustx: u128,
) -> Result<(), TestCaseError> {
    let total_stacked = addresses.iter().try_fold(0_u128, |total, entry| {
        total
            .checked_add(entry.amount_stacked)
            .ok_or_else(|| TestCaseError::Reject("Reward set entries must be summable".into()))
    })?;

    let liquid_ustx = total_stacked
        .checked_add(unstacked_ustx)
        .ok_or_else(|| TestCaseError::Reject("Total ustx must be summable".into()))?;

    prop_assume!(total_stacked <= liquid_ustx);

    let (threshold, participation) = StacksChainState::get_reward_threshold_and_participation(
        &pox_settings,
        addresses,
        liquid_ustx,
    );

    let reward_set =
        StacksChainState::make_reward_set(threshold, addresses.to_vec(), StacksEpochId::Epoch33);

    prop_assert_eq!(Some(threshold), reward_set.pox_ustx_threshold);

    let mut sum_by_addresses: HashMap<PoxAddress, u128> = HashMap::new();
    for addr in addresses.iter() {
        let entry = sum_by_addresses
            .entry(addr.reward_address.clone())
            .or_default();
        *entry += addr.amount_stacked;
    }

    for (addr, stacked_amount) in sum_by_addresses.iter() {
        let slot_count: u128 = reward_set
            .rewarded_addresses
            .iter()
            .filter(|x| *x == addr)
            .count()
            .try_into()
            .unwrap();

        prop_assert_eq!(slot_count, stacked_amount / threshold);
    }

    Ok(())
}
```

This test essentially just takes the raw PoX entries, computes the PoX stacking threshold, and then feeds that data into `make_reward_set`. Afterwards, it checks that each PoX entry has the expected number of slots (i.e., the sum of all of that address's entries floor-divided by the threshold). The one "proptest hack" in this function is the way total liquid ustx is computed. Rather than allowing total liquid ustx to be a free argument and then just "prop assuming" that it is greater than the sum of the reward set entries, we make total liquid ustx a derived variable. The reason to do this is that it makes input generation easier if it doesn't have to worry too much about generating invalid data.

Now, the part of the test that becomes more complex (and proptest-specific) is the actual input generation. We need strategies for generating the inputs to that function. For `PoxConstants`, we're really only interested in the number of slots, so we can just generate uints and construct `PoxConstants` from that. Similarly, `unstacked_ustx` is just a `u128`. However, we do have to write a strategy for the reward set entries themselves.

To write a strategy for `RawRewardSetEntry`, we'll start by writing a strategy for `PoxAddress`:

```rust
pub fn pox_address_standard() -> impl Strategy<Value = PoxAddress> {
    (
        prop::sample::select(&[20u8, 21, 22, 26]),
        uniform20(any::<u8>()),
    )
        .prop_map(|(version, bytes)| {
            PoxAddress::Standard(StacksAddress::new(version, Hash160(bytes)).unwrap(), None)
        })
}

pub fn pox_address_addr20() -> impl Strategy<Value = PoxAddress> {
    (
        any::<bool>(),
        prop::sample::select(&[PoxAddressType20::P2WPKH]),
        uniform20(any::<u8>()),
    )
        .prop_map(|(mainnet, addr_ty, bytes)| PoxAddress::Addr20(mainnet, addr_ty, bytes))
}

pub fn pox_address_addr32() -> impl Strategy<Value = PoxAddress> {
    (
        any::<bool>(),
        prop::sample::select(&[PoxAddressType32::P2TR, PoxAddressType32::P2WSH]),
        uniform32(any::<u8>()),
    )
        .prop_map(|(mainnet, addr_ty, bytes)| PoxAddress::Addr32(mainnet, addr_ty, bytes))
}

pub fn pox_address_strategy() -> impl Strategy<Value = PoxAddress> {
    prop_oneof![
        pox_address_standard(),
        pox_address_addr32(),
        pox_address_addr20()
    ]
}
```

The way we do this is by writing a strategy for each variant of `PoxAddress`, and then using a `proptest` macro to combine the three of them into a single strategy that picks one of the substrategies. When writing strategies for the composite types (like `PoxAddress::Standard`), the `prop_map` function is very useful. It basically lets you take a strategy for generating something like a `[u8; 20]` into a strategy for generating `StacksAddress`. In the examples above, we generate tuples which can be mapped into the various address types.

Once we've done that, we can map that strategy into one for generated reward set entries by including an amount stacked as well:

```rust
pub fn reward_set_entry_strategy() -> impl Strategy<Value = RawRewardSetEntry> {
    (pox_address_strategy(), 1..100_000_000_000_000u128).prop_map(
        |(reward_address, amount_stacked)| RawRewardSetEntry {
            reward_address,
            amount_stacked,
            stacker: None,
            signer: None,
        },
    )
}
```

Finally, we can actually write the property test:

```rust

proptest! {
    #[test]
    fn make_reward_set(
        pox_slots in 1..4_000u32,
        unstacked_ustx in 0..100_000_000_000_000u128,
        addrs in prop::collection::vec(reward_set_entry_strategy(), 1..50_000),
    ) {
        let prepare_length = 10;
        let reward_length = pox_slots * 2;
        let cycle_length = reward_length + prepare_length;
        let pox_settings = PoxConstants::new(
            cycle_length,
            prepare_length,
            prepare_length / 2 + 1,
            10,
            10,
            u64::MAX,
            u64::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
            u32::MAX,
        );

        check_make_reward_set(pox_settings, addrs.as_slice(), unstacked_ustx)?;
    }
}
```

This uses `proptest`'s vec generation to generate a vec of reward set entries for each case to be tested.

This works great, but one downside of property testing is that it doesn't necessarily surface corner cases very well: random input generation is great, but if corner cases are low probability, they won't get caught in 250 random cases.

For the above example, one thing we really want to be sure of is that multiple entries from the same address are handled effectively. `proptest` *should* eventually generate cases with multiple entries for the same address, but if you comment out the duplicate entry handling lines in the `make_reward_set` function, you can see that the property test still often passes!

So to deal with this, we can alter our input generation so that we're getting more interesting test cases:

```rust
    #[test]
    fn make_reward_set(
        pox_slots in 1..4_000u32,
        unstacked_ustx in 0..1_000_000_000u128,
        mut addrs in prop::collection::vec(reward_set_entry_strategy(), 1..25_000),
        to_duplicate in prop::collection::vec((0..25_000usize, 0..100_000_000u128), 0..25_000)
    ) {
        ...
        
        let _ = addrs.try_reserve(to_duplicate.len());
        for (to_dup_ix, duplicated_amount) in to_duplicate.into_iter() {
            let mut new_entry = addrs[to_dup_ix % addrs.len()].clone();
            new_entry.amount_stacked = duplicated_amount;
            addrs.push(new_entry);
        }

        check_make_reward_set(pox_settings, addrs.as_slice(), unstacked_ustx)?;
    }
```

This technique allows to be sure that proptest generates a lot of cases where there are multiple entries for the same reward address. Unfortunately, this kind of thing tends to be more art than science, which means that PR authors and reviewers will need to be careful about the input strategies for property tests (this should also be aided by the CI task for PRs). This is one of the reasons that property tests can't totally supplant unit tests. However, a lot of the work of property tests helps with writing unit tests: many unit tests can be essentially fixed inputs to the property test.

## Reusing Strategies 

Writing new input strategies may be the most tedious part of writing property tests, so it is worthwhile figuring out if the input you are looking for (or maybe a component of the input you're looking for) already has a strategy in the codebase. If you search for functions that return `impl Strategy<Value = ?>` in the codebase, you should find the set of functions that have already been written.

## Continuous Integration

By default, we'll get some CI integration from `proptest` automatically: the new property tests will run with 250 randomly generated inputs on every execution of the unit test job in CI. This is great. However, we want some additional support for executing *new* property tests extra amounts before PRs merge.

The environment variable `PROPTEST_CASES` can be set to a higher number (e.g., `PROPTEST_CASES=2500`) to explore more test cases before declaring success. From the CI, what we want is a job which:

1. Executes once a PR has been approved.
2. Discovers the set of new tests (this is probably easiest to achieve by running `cargo nextest list` on the source and target branches and then diffing the outputs).
3. Executes only the new tests with the environment variable `PROPTEST_CASES` set to 2500.

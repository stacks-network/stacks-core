use chainstate::stacks::boot::STACKS_BOOT_CODE_MAINNET;
use vm::analysis::{mem_type_check, mem_type_check_with_db, ContractAnalysis};
use vm::docs::{get_input_type_string, get_output_type_string, get_signature};
use vm::types::{FunctionType, Value};

use std::collections::{BTreeMap, HashMap, HashSet};
use std::iter::FromIterator;

use crate::clarity_vm::database::MemoryBackingStore;
use crate::core::StacksEpochId;
use crate::vm::contexts::GlobalContext;
use crate::vm::costs::LimitedCostTracker;
use crate::vm::types::QualifiedContractIdentifier;
use crate::vm::{self, ContractContext};

const DOCS_GENERATION_EPOCH: StacksEpochId = StacksEpochId::Epoch2_05;

#[derive(Serialize)]
struct ContractRef {
    public_functions: Vec<FunctionRef>,
    read_only_functions: Vec<FunctionRef>,
    error_codes: Vec<ErrorCode>,
}

#[derive(Serialize)]
struct FunctionRef {
    name: String,
    input_type: String,
    output_type: String,
    signature: String,
    description: String,
}

#[derive(Serialize)]
struct ErrorCode {
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    value: String,
}

struct ContractSupportDocs {
    descriptions: HashMap<&'static str, &'static str>,
    skip_func_display: HashSet<&'static str>,
}

fn make_contract_support_docs() -> HashMap<&'static str, ContractSupportDocs> {
    let pox_descriptions = vec![
        ("disallow-contract-caller", "Revokes authorization from a contract to invoke stacking methods through contract-calls"),
        ("allow-contract-caller", "Give a contract-caller authorization to call stacking methods. Normally, stacking methods may
only be invoked by _direct_ transactions (i.e., the `tx-sender` issues a direct `contract-call` to the stacking methods).
By issuing an allowance, the tx-sender may call through the allowed contract."),
        ("stack-stx", "Lock up some uSTX for stacking!  Note that the given amount here is in micro-STX (uSTX).
The STX will be locked for the given number of reward cycles (lock-period).
This is the self-service interface.  tx-sender will be the Stacker.

* The given stacker cannot currently be stacking.
* You will need the minimum uSTX threshold. This isn't determined until the reward cycle begins, but this
   method still requires stacking over the _absolute minimum_ amount, which can be obtained by calling `get-stacking-minimum`.
* The pox-addr argument must represent a valid reward address.  Right now, this must be a Bitcoin
p2pkh or p2sh address.  It cannot be a native Segwit address, but it may be a p2wpkh-p2sh or p2wsh-p2sh address.

The tokens will unlock and be returned to the Stacker (tx-sender) automatically."),
        ("revoke-delegate-stx", "Revoke a Stacking delegate relationship. A particular Stacker may only have one delegate,
so this method does not take any parameters, and just revokes the Stacker's current delegate (if one exists)."),
        ("delegate-stx", "Delegate to `delegate-to` the ability to stack from a given address.
This method _does not_ lock the funds, rather, it allows the delegate to issue the stacking lock.

The caller specifies:
 * amount-ustx: the total amount of ustx the delegate may be allowed to lock
 * until-burn-ht: an optional burn height at which this delegation expiration
 * pox-addr: an optional p2pkh or p2sh address to which any rewards *must* be sent"),
        ("delegate-stack-stx", "As a delegate, stack the given principal's STX using `partial-stacked-by-cycle`.
Once the delegate has stacked > minimum, the delegate should call `stack-aggregation-commit`."),
        ("stack-aggregation-commit", "Commit partially stacked STX.

This allows a stacker/delegate to lock fewer STX than the minimal threshold in multiple transactions,
so long as:
   1. The pox-addr is the same.
   2. This \"commit\" transaction is called _before_ the PoX anchor block.
This ensures that each entry in the reward set returned to the stacks-node is greater than the threshold,
  but does not require it be all locked up within a single transaction"),
        ("reject-pox", "Reject Stacking for this reward cycle.
`tx-sender` votes all its uSTX for rejection.
Note that unlike Stacking, rejecting PoX does not lock the tx-sender's tokens: PoX rejection acts like a coin vote."),
        ("can-stack-stx", "Evaluate if a participant can stack an amount of STX for a given period."),
        ("get-stacking-minimum", "Returns the absolute minimum amount that could be validly Stacked (the threshold to Stack in
a given reward cycle may be higher than this"),
        ("get-pox-rejection", "Returns the amount of uSTX that a given principal used to reject a PoX cycle."),
        ("is-pox-active", "Returns whether or not PoX has been rejected at a given PoX cycle."),
        ("get-stacker-info", "Returns the _current_ stacking information for `stacker.  If the information
is expired, or if there's never been such a stacker, then returns none."),
        ("get-total-ustx-stacked", "Returns the amount of currently participating uSTX in the given cycle."),
        ("get-pox-info", "Returns information about PoX status.")
    ];

    let bns_descriptions = vec![
        ("namespace-preorder", "Registers the salted hash of the namespace with BNS nodes, and burns the requisite amount of cryptocurrency. Additionally, this step proves to the BNS nodes that user has honored the BNS consensus rules by including a recent consensus hash in the transaction. Returns pre-order's expiration date (in blocks)."),
        ("namespace-reveal", "Reveals the salt and the namespace ID (after a namespace preorder). It reveals how long names last in this namespace before they expire or must be renewed, and it sets a price function for the namespace that determines how cheap or expensive names its will be.\
All of the parameters prefixed by `p` make up the `price function`. These parameters govern the pricing and lifetime of names in the namespace.

The rules for a namespace are as follows:
* a name can fall into one of 16 buckets, measured by length. Bucket 16 incorporates all names at least 16 characters long.
* the pricing structure applies a multiplicative penalty for having numeric characters, or punctuation characters.
* the price of a name in a bucket is `((coeff) * (base) ^ (bucket exponent)) / ((numeric discount multiplier) * (punctuation discount multiplier))`

Example:

* base = 10
* coeff = 2
* nonalpha discount: 10
* no-vowel discount: 10
* buckets 1, 2: 9
* buckets 3, 4, 5, 6: 8
* buckets 7, 8, 9, 10, 11, 12, 13, 14: 7
* buckets 15, 16+:"),
        ("name-import", "Imports name to a revealed namespace. Each imported name is given both an owner and some off-chain state."),
        ("namespace-ready", "Launches the namespace and makes it available to the public. Once a namespace is launched, anyone can register a name in it if they pay the appropriate amount of cryptocurrency."),
        ("name-preorder", "Preorders a name by telling all BNS nodes the salted hash of the BNS name. It pays the registration fee to the namespace owner's designated address."),
        ("name-register", "Reveals the salt and the name to all BNS nodes, and assigns the name an initial public key hash and zone file hash."),
        ("name-update", "Changes the name's zone file hash. You would send a name update transaction if you wanted to change the name's zone file contents. For example, you would do this if you want to deploy your own Gaia hub and want other people to read from it."),
        ("name-transfer", "Changes the name's public key hash. You would send a name transfer transaction if you wanted to:
* Change your private key
* Send the name to someone else or
* Update your zone file

When transferring a name, you have the option to also clear the name's zone file hash (i.e. set it to null). This is useful for when you send the name to someone else, so the recipient's name does not resolve to your zone file."),
        ("name-revoke", "Makes a name unresolvable. The BNS consensus rules stipulate that once a name is revoked, no one can change its public key hash or its zone file hash.  The name's zone file hash is set to null to prevent it from resolving. You should only do this if your private key is compromised, or if you want to render your name unusable for whatever reason."),
        ("name-renewal", "Depending in the namespace rules, a name can expire. For example, names in the .id namespace expire after 2 years. You need to send a name renewal every so often to keep your name.

You will pay the registration cost of your name to the namespace's designated burn address when you renew it.
When a name expires, it enters a \"grace period\". The period is set to 5000 blocks (a month) but can be configured for each namespace. 

It will stop resolving in the grace period, and all of the above operations will cease to be honored by the BNS consensus rules.
You may, however, send a NAME_RENEWAL during this grace period to preserve your name. After the grace period, everybody can register that name again.
If your name is in a namespace where names do not expire, then you never need to use this transaction."),
        ("get-namespace-price", "Gets the price for a namespace."),
        ("get-name-price", "Gets the price for a name."),
        ("can-namespace-be-registered", "Returns true if the provided namespace is available."),
        ("is-name-lease-expired", "Return true if the provided name lease is expired."),
        ("can-name-be-registered", "Returns true if the provided name can be registered."),
        ("name-resolve", "Get name registration details."),
        ("get-namespace-properties", "Get namespace properties."),
        ("can-receive-name", "Returns true if the provided name can be received. That is, if it is not curretly owned, a previous lease is expired, and the name wasn't revoked."),
        ("get-name", "Returns a response with the username that belongs to the user if any, otherwise an error ERROR_NOT_FOUND is returned."),
        ("resolve-principal", "Returns the registered name that a principal owns if there is one. A principal can only own one name at a time.")
    ];

    let exit_contract_descriptions = vec![
        (
            "vote-for-exit-rc",
            "Stackers call this function with a specific exit proposal. When \
        their STX unlocks, they are eligible to vote again. The vote must also fall into a \
        valid range (greater than the minimum exit reward cycle, and within a particular range\
        relative to the current reward cycle).",
        ),
        (
            "reject-exit-rc",
            "Block miners call this function during the rejection period for a specific \
        exit proposal to reject the proposal. The rejection is only valid if they were the miner of a\
        block within the rejection period.",
        ),
    ];

    let pox_skip_display = vec![
        "set-burnchain-parameters",
        "minimal-can-stack-stx",
        "get-reward-set-size",
        "get-reward-set-pox-address",
    ];

    let bns_skip_display = vec![
        "namespace-update-function-price",
        "namespace-revoke-function-price-edition",
        "check-name-ops-preconditions",
        "is-name-in-grace-period",
    ];

    let exit_contract_skip_display = vec![
        "set-burnchain-parameters",
        "burn-height-to-reward-cycle",
        "current-pox-reward-cycle",
        "add-to-rc-proposal-map",
        "get-voting-reward-cycles",
    ];

    HashMap::from_iter(vec![
        (
            "pox",
            ContractSupportDocs {
                descriptions: HashMap::from_iter(pox_descriptions.into_iter()),
                skip_func_display: HashSet::from_iter(pox_skip_display.into_iter()),
            },
        ),
        (
            "bns",
            ContractSupportDocs {
                descriptions: HashMap::from_iter(bns_descriptions.into_iter()),
                skip_func_display: HashSet::from_iter(bns_skip_display.into_iter()),
            },
        ),
        (
            "exit-at-rc",
            ContractSupportDocs {
                descriptions: HashMap::from_iter(exit_contract_descriptions.into_iter()),
                skip_func_display: HashSet::from_iter(exit_contract_skip_display.into_iter()),
            },
        ),
    ])
}

fn make_func_ref(func_name: &str, func_type: &FunctionType, description: &str) -> FunctionRef {
    let input_type = get_input_type_string(func_type);
    let output_type = get_output_type_string(func_type);
    let signature = get_signature(func_name, func_type)
        .expect("BUG: failed to build signature for boot contract");
    FunctionRef {
        input_type,
        output_type,
        signature,
        name: func_name.to_string(),
        description: description.to_string(),
    }
}

fn get_constant_value(var_name: &str, contract_content: &str) -> Value {
    let to_eval = format!("{}\n{}", contract_content, var_name);
    doc_execute(&to_eval)
        .expect("BUG: failed to evaluate contract for constant value")
        .expect("BUG: failed to return constant value")
}

fn doc_execute(program: &str) -> Result<Option<Value>, vm::Error> {
    let contract_id = QualifiedContractIdentifier::transient();
    let mut contract_context = ContractContext::new(contract_id.clone());
    let mut marf = MemoryBackingStore::new();
    let conn = marf.as_clarity_db();
    let mut global_context = GlobalContext::new(
        false,
        conn,
        LimitedCostTracker::new_free(),
        DOCS_GENERATION_EPOCH,
    );
    global_context.execute(|g| {
        let parsed = vm::ast::build_ast(&contract_id, program, &mut ())?.expressions;
        vm::eval_all(&parsed, &mut contract_context, g)
    })
}

fn produce_docs() -> BTreeMap<String, ContractRef> {
    let mut docs = BTreeMap::new();
    let support_docs = make_contract_support_docs();

    let mut marf = MemoryBackingStore::new();
    let mut analysis_db = marf.as_analysis_db();
    for (contract_name, content) in STACKS_BOOT_CODE_MAINNET.iter() {
        let (_, contract_analysis) =
            mem_type_check_with_db(content, contract_name, &mut analysis_db)
                .expect("BUG: failed to type check boot contract");

        if let Some(contract_support) = support_docs.get(*contract_name) {
            let ContractAnalysis {
                public_function_types,
                read_only_function_types,
                variable_types,
                ..
            } = contract_analysis;
            let public_functions: Vec<_> = public_function_types
                .iter()
                .filter(|(func_name, _)| {
                    !contract_support
                        .skip_func_display
                        .contains(func_name.as_str())
                })
                .map(|(func_name, func_type)| {
                    let description = contract_support
                        .descriptions
                        .get(func_name.as_str())
                        .expect(&format!("BUG: no description for {}", func_name.as_str()));
                    make_func_ref(func_name, func_type, description)
                })
                .collect();

            let read_only_functions: Vec<_> = read_only_function_types
                .iter()
                .filter(|(func_name, _)| {
                    !contract_support
                        .skip_func_display
                        .contains(func_name.as_str())
                })
                .map(|(func_name, func_type)| {
                    let description = contract_support
                        .descriptions
                        .get(func_name.as_str())
                        .expect(&format!("BUG: no description for {}", func_name.as_str()));
                    make_func_ref(func_name, func_type, description)
                })
                .collect();

            let ecode_names = variable_types
                .iter()
                .filter_map(|(var_name, _)| {
                    if var_name.starts_with("ERR_") {
                        Some(format!("{}: {}", var_name.as_str(), var_name.as_str()))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            let ecode_to_eval = format!("{}\n {{ {} }}", content, ecode_names);
            let ecode_result = doc_execute(&ecode_to_eval)
                .expect("BUG: failed to evaluate contract for constant value")
                .expect("BUG: failed to return constant value")
                .expect_tuple();

            let error_codes = variable_types
                .iter()
                .filter_map(|(var_name, type_signature)| {
                    if var_name.starts_with("ERR_") {
                        let value = ecode_result
                            .get(var_name)
                            .expect("BUG: failed to fetch tuple entry from ecode output")
                            .to_string();
                        Some(ErrorCode {
                            name: var_name.to_string(),
                            value,
                            value_type: type_signature.to_string(),
                        })
                    } else {
                        None
                    }
                })
                .collect();

            docs.insert(
                contract_name.to_string(),
                ContractRef {
                    public_functions,
                    read_only_functions,
                    error_codes,
                },
            );
        }
    }

    docs
}

pub fn make_json_boot_contracts_reference() -> String {
    let api_out = produce_docs();
    format!(
        "{}",
        serde_json::to_string(&api_out).expect("Failed to serialize documentation")
    )
}

#[cfg(test)]
mod tests {
    use vm::docs::contracts::make_json_boot_contracts_reference;

    #[test]
    fn test_make_boot_contracts_reference() {
        make_json_boot_contracts_reference();
    }
}

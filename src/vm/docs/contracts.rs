use chainstate::stacks::boot::STACKS_BOOT_CODE_MAINNET;
use vm::analysis::{mem_type_check, ContractAnalysis};
use vm::docs::{get_input_type_string, get_output_type_string, get_signature};
use vm::types::{FunctionType, Value};

use vm::execute;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::iter::FromIterator;

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

The tokens will unlock and be returned to the Stacker (tx-sender) automatically."),
        ("revoke-delegate-stx", "Revoke a Stacking delegate relationship. A particular Stacker may only have one delegate,
so this method does not take any parameters, and just revokes the Stacker's current delegate (if one exists)."),
        ("delegate-stx", "Delegate to `delegate-to` the ability to stack from a given address.
This method _does not_ lock the funds, rather, it allows the delegate to issue the stacking lock.

The caller specifies:
 * amount-ustx: the total amount of ustx the delegate may be allowed to lock
 * until-burn-ht: an optional burn height at which this delegation expiration
 * pox-addr: an optional address to which any rewards *must* be sent"),
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

    let pox_skip_display = vec![
        "set-burnchain-parameters",
        "minimal-can-stack-stx",
        "get-reward-set-size",
        "get-reward-set-pox-address",
    ];

    HashMap::from_iter(vec![(
        "pox",
        ContractSupportDocs {
            descriptions: HashMap::from_iter(pox_descriptions.into_iter()),
            skip_func_display: HashSet::from_iter(pox_skip_display.into_iter()),
        },
    )])
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
    execute(&to_eval)
        .expect("BUG: failed to evaluate contract for constant value")
        .expect("BUG: failed to return constant value")
}

fn produce_docs() -> BTreeMap<String, ContractRef> {
    let mut docs = BTreeMap::new();
    let support_docs = make_contract_support_docs();

    for (contract_name, content) in STACKS_BOOT_CODE_MAINNET.iter() {
        let (_, contract_analysis) =
            mem_type_check(content).expect("BUG: failed to type check boot contract");

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
            let ecode_result = execute(&ecode_to_eval)
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

#[cfg(test)]
use proptest::{prelude::*, string::string_regex};

#[cfg(test)]
use crate::vm::{
    representations::{CLARITY_NAME_REGEX_STRING, MAX_STRING_LEN},
    ClarityName,
};

#[cfg(test)]
/// Generates a proptest strategy for valid Clarity names.
///
/// This function creates a branched strategy based on the `CLARITY_NAME_REGEX_STRING` pattern.
///
/// The strategy covers three categories of valid names:
/// - Letter-based names starting with a letter followed by alphanumeric or symbol characters
/// - Single arithmetic operators (`-`, `+`, `=`, `/`, `*`)
/// - Comparison operators (`<`, `>`, `<=`, `>=`)
fn any_valid_clarity_name() -> impl Strategy<Value = String> {
    // Ensure the regex branches match the actual validator.
    let expected_regex = "^[a-zA-Z]([a-zA-Z0-9]|[-_!?+<>=/*])*$|^[-+=/*]$|^[<>]=?$";
    assert_eq!(
        CLARITY_NAME_REGEX_STRING.as_str(),
        expected_regex,
        "CLARITY_NAME_REGEX_STRING has changed"
    );

    let letter_names = string_regex(&format!(
        "[a-zA-Z][a-zA-Z0-9_!?+<>=/*-]{{0,{}}}",
        (MAX_STRING_LEN as usize).saturating_sub(1)
    ))
    .unwrap();

    let single_ops = prop_oneof![
        Just("-".to_string()),
        Just("+".to_string()),
        Just("=".to_string()),
        Just("/".to_string()),
        Just("*".to_string()),
    ];

    let comparison_ops = prop_oneof![
        Just("<".to_string()),
        Just(">".to_string()),
        Just("<=".to_string()),
        Just(">=".to_string()),
    ];

    prop_oneof![letter_names, single_ops, comparison_ops]
}

#[test]
fn prop_clarity_name_valid_patterns() {
    proptest!(|(name in any_valid_clarity_name())| {
        prop_assume!(!name.is_empty());
        prop_assume!(name.len() <= MAX_STRING_LEN as usize);

        let clarity_name = ClarityName::try_from(name.clone())
            .unwrap_or_else(|_| panic!("Should parse valid clarity name: {}", name));
        prop_assert_eq!(clarity_name.as_str(), name);
    });
}

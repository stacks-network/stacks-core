use crate::vm::analysis::errors::{RuntimeCheckErrorKind, StaticCheckErrorKind};

#[test]
fn runtime_check_is_unreachable() {
    assert!(RuntimeCheckErrorKind::Unreachable("test".into()).is_unreachable());

    // All non-Unreachable variants must return false
    assert!(!RuntimeCheckErrorKind::CostOverflow.is_unreachable());
    assert!(!RuntimeCheckErrorKind::ValueTooLarge.is_unreachable());
}

#[test]
fn static_check_is_unreachable() {
    assert!(StaticCheckErrorKind::Unreachable("test".into()).is_unreachable());

    // All non-Unreachable variants must return false
    assert!(!StaticCheckErrorKind::SupertypeTooLarge.is_unreachable());
    assert!(!StaticCheckErrorKind::CostOverflow.is_unreachable());
    assert!(!StaticCheckErrorKind::TypeAlreadyAnnotatedFailure.is_unreachable());
}

mod pre_type_check;
mod post_type_check;

pub use self::pre_type_check::{PreTypeCheckingTraitChecker};
pub use self::post_type_check::{PostTypeCheckingTraitChecker};

#[cfg(test)]
mod tests;

pub mod lexer;

#[cfg(feature = "vm")]
pub mod parser_impl;
#[cfg(feature = "vm")]
pub use parser_impl::*;

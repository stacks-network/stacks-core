#[cfg(feature = "log")]
mod std;

#[cfg(feature = "log")]
pub use self::std::*;

#[cfg(not(feature = "log"))]
mod noop;

#[cfg(not(feature = "log"))]
pub use self::noop::*;

//! Architecture layer. Only x86_64 exists today; everything above this layer
//! uses the re-exported names so another architecture can slot in.

pub mod x86_64;
pub use self::x86_64::*;

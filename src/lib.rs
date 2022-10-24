#[cfg(all(feature = "pairing", feature = "blst"))]
compile_error!("only pairing or blst can be enabled");

mod error;
mod key;
mod signature;

pub use self::error::Error;
pub use self::key::{sigma_protocol, DeserializeUnchecked, PrivateKey, PublicKey, Serialize};
pub use self::signature::{aggregate, hash, verify_messages, verify_same_message, Signature};

#[cfg(test)]
#[macro_use]
extern crate base64_serde;

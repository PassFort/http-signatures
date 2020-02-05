use hmac::Hmac;
use sha2::Sha256;

const DATE_FORMAT: &str = "%a, %d %b %Y %T GMT";
type DefaultSignatureAlgorithm = Hmac<Sha256>;
type DefaultDigestAlgorithm = Sha256;

mod algorithm;
pub use algorithm::*;

mod header;
pub use header::*;

mod signing;
pub use signing::*;

mod verifying;
pub use verifying::*;

#[cfg(feature = "reqwest")]
mod reqwest_impls;
#[cfg(feature = "reqwest")]
pub use reqwest_impls::*;

#[cfg(feature = "rouille")]
mod rouille_impls;
#[cfg(feature = "rouille")]
pub use rouille_impls::*;

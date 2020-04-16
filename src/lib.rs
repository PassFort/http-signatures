#![deny(missing_docs)]
//! Implementation of the IETF draft 'Signing HTTP Messages'
//! https://tools.ietf.org/id/draft-cavage-http-signatures-12.html
//!
//! ## Features
//!
//! This crate is intended to be used with multiple different HTTP clients and/or servers.
//! As such, client/server-specific implementations are gated by correspondingly named
//! features.
//!
//! ### Supported crates:
//!
//! | Crate / Feature name                              | Client/Server | Notes                                                         |
//! | ------------------------------------------------- | ------------- | ------------------------------------------------------------- |
//! | [reqwest](https://crates.io/crates/reqwest)       | Client        | Supports blocking and non-blocking requests.<sup>1</sup>      |
//! | [rouille](https://crates.io/crates/rouille)       | Server        |                                                               |
//!
//! 1. Due to limitations of the reqwest API, digests can only be calculated automatically for non-blocking non-streaming requests. For
//!    blocking or streaming requests, the user must add the digest manually before signing the request, or else the `Digest` header will
//!    not be included in the signature.
//!
//! ### Supported signature algorithms:
//!
//! Algorithm registry: https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#hsa-registry
//!
//! - `hmac-sha256`
//!
//! ### Supported digest algorithms:
//!
//! Digest registry: https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml
//!
//! - `SHA-256`
//! - `SHA-512`
//!
//! ## Example usage (reqwest)
//!
//! ```rust,no_run
//! use http_sig::*;
//!
//! const SECRET_KEY: &[u8] = b"secret";
//!
//! let config = SigningConfig::new_default("My Key", SECRET_KEY);
//!
//! let client = reqwest::blocking::Client::new();
//!
//! let req = client
//!     .get("http://localhost:8080/")
//!     .build()
//!     .unwrap()
//!     .signed(&config)
//!     .unwrap();
//!
//! let result = client.execute(req).unwrap();
//! ```

use sha2::Sha256;

const DATE_FORMAT: &str = "%a, %d %b %Y %T GMT";
type DefaultSignatureAlgorithm = algorithm::HmacSha256;
type DefaultDigestAlgorithm = Sha256;

#[macro_use]
mod macros;

mod algorithm;
pub use algorithm::*;

mod header;
pub use header::*;

mod canonicalize;
pub use canonicalize::*;

mod signing;
pub use signing::*;

mod verifying;
pub use verifying::*;

/// Module containg a mock request type which implements both
/// `ClientRequestLike` and `ServerRequestLike` for testing.
pub mod mock_request;

#[cfg(feature = "reqwest")]
mod reqwest_impls;
#[cfg(feature = "reqwest")]
pub use reqwest_impls::*;

#[cfg(feature = "rouille")]
mod rouille_impls;
#[cfg(feature = "rouille")]
pub use rouille_impls::*;

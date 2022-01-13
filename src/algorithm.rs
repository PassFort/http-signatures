use std::fmt::Debug;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

/// Implements the signing half of an HTTP signature algorithm. For symmetric
/// algorithms the same type implements both signing and verification.
pub trait HttpSignatureSign: Debug + Send + Sync + 'static {
    /// Returns the encoded signature, ready for inclusion in the HTTP Authorization
    /// header. For all currently supported signature schemes, the encoding is
    /// specified to be base64.
    fn http_sign(&self, bytes_to_sign: &[u8]) -> String;

    /// Returns the name of this signing algorithm, as expected by the algorithm
    /// parameter in the HTTP Authorization header.
    fn name(&self) -> &str;
}

/// Implements the verification half of an HTTP signature algorithm. For symmetric
/// algorithms the same type implements both signing and verification.
pub trait HttpSignatureVerify: Debug + Send + Sync + 'static {
    /// Returns true if the signature is valid for the provided content. The
    /// implementation should be sure to perform any comparisons in constant
    /// time.
    fn http_verify(&self, bytes_to_verify: &[u8], signature: &str) -> bool;
}

/// Implementations of this trait correspond to digest algorithms
/// listed here:
/// https://www.iana.org/assignments/http-dig-alg/http-dig-alg.xhtml
pub trait HttpDigest: Debug + Send + Sync + 'static {
    /// Must return the name exactly as specified in the above list of HTTP
    /// digest algorithms.
    fn name(&self) -> &str;
    /// Returns the encoded digest, ready for inclusion in the HTTP Digest
    /// header. The encoding to use is specified in the above list of HTTP digest
    /// algorithms.
    fn http_digest(&self, bytes_to_digest: &[u8]) -> String;
}

macro_rules! hmac_signature {
    ($typename:ident($algorithm:ident) = $name:literal) => {
        #[doc = "Implementation of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        #[derive(Debug)]
        pub struct $typename(Hmac<$algorithm>);

        impl $typename {
            /// Create a new instance of the signature scheme using the
            /// provided key.
            pub fn new(key: &[u8]) -> Self {
                Self(Hmac::new_from_slice(key).expect("Hmac construction should be infallible"))
            }
        }

        impl HttpSignatureSign for $typename {
            fn http_sign(&self, bytes_to_sign: &[u8]) -> String {
                let mut hmac = self.0.clone();
                hmac.update(bytes_to_sign);
                let tag = hmac.finalize().into_bytes();
                base64::encode(tag)
            }

            fn name(&self) -> &str {
                $name
            }
        }
        impl HttpSignatureVerify for $typename {
            fn http_verify(&self, bytes_to_verify: &[u8], signature: &str) -> bool {
                let tag = match base64::decode(signature) {
                    Ok(tag) => tag,
                    Err(_) => return false,
                };
                let mut hmac = self.0.clone();
                hmac.update(bytes_to_verify);
                hmac.verify_slice(&tag).is_ok()
            }
        }
    };
}

hmac_signature!(HmacSha256(Sha256) = "hmac-sha256");
hmac_signature!(HmacSha512(Sha512) = "hmac-sha512");

impl HttpDigest for Sha256 {
    fn name(&self) -> &str {
        "SHA-256"
    }
    fn http_digest(&self, bytes_to_digest: &[u8]) -> String {
        base64::encode(&Self::digest(bytes_to_digest))
    }
}

impl HttpDigest for Sha512 {
    fn name(&self) -> &str {
        "SHA-512"
    }
    fn http_digest(&self, bytes_to_digest: &[u8]) -> String {
        base64::encode(&Self::digest(bytes_to_digest))
    }
}

#[cfg(feature = "openssl")]
mod openssl;
#[cfg(feature = "openssl")]
pub use self::openssl::*;

#[cfg(all(not(feature = "openssl"), feature = "ring"))]
mod ring;
#[cfg(all(not(feature = "openssl"), feature = "ring"))]
pub use self::ring::*;

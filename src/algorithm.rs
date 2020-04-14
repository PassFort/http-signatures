use std::fmt::Debug;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

/// Implementations of this trait correspond to signature algorithms
/// listed here:
/// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#hsa-registry
///
/// If the HTTP signatures draft is accepted, these will be moved to a registry
/// managed by the IANA.
pub trait HttpSignature: Debug + Send + Sync + 'static {
    /// Must return the name exactly as specified in the above list of HTTP
    /// signature algorithms.
    fn name(&self) -> &str;
    /// Returns the encoded signature, ready for inclusion in the HTTP Authorization
    /// header. For all currently supported signature schemes, the encoding is
    /// specified to be base64.
    fn http_sign(&self, bytes_to_sign: &[u8]) -> String;
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

impl HttpSignature for Hmac<Sha256> {
    fn name(&self) -> &str {
        "hmac-sha256"
    }
    fn http_sign(&self, bytes_to_sign: &[u8]) -> String {
        let mut mac = self.clone();
        mac.input(bytes_to_sign);
        base64::encode(&mac.result().code())
    }
    fn http_verify(&self, bytes_to_verify: &[u8], signature: &str) -> bool {
        let expected_signature = self.http_sign(bytes_to_verify);
        expected_signature
            .as_bytes()
            .ct_eq(signature.as_bytes())
            .into()
    }
}

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

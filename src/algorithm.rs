use std::fmt::Debug;

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub trait HttpSignature: Debug + Send + Sync + 'static {
    fn name(&self) -> &str;
    fn http_sign(&self, bytes_to_sign: &[u8]) -> String;
}

pub trait HttpDigest: Debug + Send + Sync + 'static {
    fn name(&self) -> &str;
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

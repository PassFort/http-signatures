use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub trait HttpSignatureAlgorithm {
    const NAME: &'static str;
    fn http_sign(&self, bytes_to_sign: &[u8]) -> String;
}

pub trait HttpDigestAlgorithm {
    const NAME: &'static str;
    fn http_digest(bytes_to_digest: &[u8]) -> String;
}

pub struct InvalidKey;

impl HttpSignatureAlgorithm for Hmac<Sha256> {
    const NAME: &'static str = "hmac-sha256";
    fn http_sign(&self, bytes_to_sign: &[u8]) -> String {
        let mut mac = self.clone();
        mac.input(bytes_to_sign);
        base64::encode(&mac.result().code())
    }
}

impl HttpDigestAlgorithm for Sha256 {
    const NAME: &'static str = "SHA-256";
    fn http_digest(bytes_to_digest: &[u8]) -> String {
        base64::encode(&Sha256::digest(bytes_to_digest))
    }
}

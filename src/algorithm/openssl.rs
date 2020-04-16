use std::fmt;

use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};

use crate::{HttpSignatureSign, HttpSignatureVerify};

macro_rules! rsa_signature {
    ({$sign_name:ident, $verify_name:ident}($hash_alg:ident) = $name:literal) => {
        #[doc = "Implementation of the signing half of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        pub struct $sign_name(PKey<Private>);

        impl fmt::Debug for $sign_name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(stringify!($sign_name))
            }
        }

        #[doc = "Implementation of the verification half of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        pub struct $verify_name(PKey<Public>);

        impl fmt::Debug for $verify_name {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(stringify!($verify_name))
            }
        }

        impl $sign_name {
            /// Create a new instance of the signature scheme using the
            /// provided private key.
            pub fn new_pkcs8(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(PKey::private_key_from_pkcs8(private_key)?))
            }
            /// Create a new instance of the signature scheme using the
            /// provided private key.
            pub fn new_der(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(PKey::from_rsa(Rsa::private_key_from_der(private_key)?)?))
            }
            /// Create a new instance of the signature scheme using the
            /// provided private key.
            pub fn new_pem(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(PKey::from_rsa(Rsa::private_key_from_pem(private_key)?)?))
            }
        }

        impl $verify_name {
            /// Create a new instance of the signature scheme using the
            /// provided public key.
            pub fn new_der(public_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(PKey::from_rsa(Rsa::public_key_from_der(public_key)?)?))
            }
            /// Create a new instance of the signature scheme using the
            /// provided public key.
            pub fn new_pem(public_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(PKey::from_rsa(Rsa::public_key_from_pem(public_key)?)?))
            }
        }

        impl HttpSignatureSign for $sign_name {
            fn http_sign(&self, bytes_to_sign: &[u8]) -> String {
                let mut signer = Signer::new(MessageDigest::$hash_alg(), &self.0).unwrap();
                signer.set_rsa_padding(Padding::PKCS1).unwrap();
                let tag = signer.sign_oneshot_to_vec(bytes_to_sign).expect("Signing to be infallible");
                base64::encode(&tag)
            }
        }
        impl HttpSignatureVerify for $verify_name {
            fn http_verify(&self, bytes_to_verify: &[u8], signature: &str) -> bool {
                let tag = match base64::decode(signature) {
                    Ok(tag) => tag,
                    Err(_) => return false,
                };
                let mut verifier = Verifier::new(MessageDigest::$hash_alg(), &self.0).unwrap();
                verifier.set_rsa_padding(Padding::PKCS1).unwrap();
                match verifier.verify_oneshot(&tag, bytes_to_verify) {
                    Ok(true) => true,
                    Ok(false) => false,
                    Err(e) => {
                        dbg!(e);
                        false
                    }
                }
            }
        }
    };
}

rsa_signature!({RsaSha256Sign, RsaSha256Verify}(sha256) = "rsa-sha256");
rsa_signature!({RsaSha512Sign, RsaSha512Verify}(sha512) = "rsa-sha512");

use ring::{rand, signature};

use crate::{HttpSignature, HttpSignatureSign, HttpSignatureVerify};

macro_rules! rsa_signature {
    ({$sign_name:ident($sign_alg:ident), $verify_name:ident($verify_alg:ident)} = $name:literal) => {
        #[doc = "Implementation of the signing half of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        #[derive(Debug)]
        pub struct $sign_name(signature::RsaKeyPair);

        #[doc = "Implementation of the verification half of the '"]
        #[doc = $name]
        #[doc = "' HTTP signature scheme."]
        #[derive(Debug)]
        pub struct $verify_name(Vec<u8>);

        impl $sign_name {
            /// Create a new instance of the signature scheme using the
            /// provided private key.
            pub fn new_pkcs8(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(signature::RsaKeyPair::from_pkcs8(private_key)?))
            }
            /// Create a new instance of the signature scheme using the
            /// provided private key.
            pub fn new_der(private_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(signature::RsaKeyPair::from_der(private_key)?))
            }
        }

        impl $verify_name {
            /// Create a new instance of the signature scheme using the
            /// provided public key.
            pub fn new_der(public_key: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
                Ok(Self(public_key.into()))
            }
        }

        impl HttpSignature for $sign_name {
            fn name(&self) -> &str {
                $name
            }
        }
        impl HttpSignature for $verify_name {
            fn name(&self) -> &str {
                $name
            }
        }
        impl HttpSignatureSign for $sign_name {
            fn http_sign(&self, bytes_to_sign: &[u8]) -> String {
                let mut tag = vec![0; self.0.public_modulus_len()];
                self.0
                    .sign(
                        &signature::$sign_alg,
                        &rand::SystemRandom::new(),
                        bytes_to_sign,
                        &mut tag,
                    )
                    .expect("Signing should be infallible");
                base64::encode(&tag)
            }
        }
        impl HttpSignatureVerify for $verify_name {
            fn http_verify(&self, bytes_to_verify: &[u8], signature: &str) -> bool {
                let tag = match base64::decode(signature) {
                    Ok(tag) => tag,
                    Err(_) => return false,
                };
                signature::VerificationAlgorithm::verify(
                    &signature::$verify_alg,
                    self.0.as_slice().into(),
                    bytes_to_verify.into(),
                    tag.as_slice().into(),
                )
                .is_ok()
            }
        }
    };
}

rsa_signature!({RsaSha256Sign(RSA_PKCS1_SHA256), RsaSha256Verify(RSA_PKCS1_2048_8192_SHA256)} = "rsa-sha256");
rsa_signature!({RsaSha512Sign(RSA_PKCS1_SHA512), RsaSha512Verify(RSA_PKCS1_2048_8192_SHA512)} = "rsa-sha512");

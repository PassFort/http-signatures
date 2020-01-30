use chrono::{DateTime, Utc};
use http::header::{HeaderName, HeaderValue, AUTHORIZATION, DATE};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

fn body_digest(body: &[u8]) -> String {
    let mut hasher = Sha256::default();
    hasher.input(body);
    base64::encode(&hasher.result())
}

fn signature(
    // base64 encoded integration key
    key: &str,
    bytes_to_sign: &[u8],
) -> Result<String, base64::DecodeError> {
    let key = base64::decode(key)?;
    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_varkey(&key).expect("HMAC can take key of any size");
    mac.input(bytes_to_sign);
    Ok(base64::encode(&mac.result().code()))
}

const KEY_ID_LEN: usize = 8;

pub trait HttpSigExt: Sized {
    type Error;
    fn with_sig(
        self,
        key: &str,
        date: DateTime<Utc>,
        headers: Vec<(HeaderName, Option<HeaderValue>)>,
    ) -> Result<Self, Self::Error>;
}

#[cfg(feature = "reqwest_client")]
mod reqwest {
    pub use super::*;
    
    #[derive(Debug)]
    pub enum ReqwestSignatureError {
        KeyTooShort,
        KeyNotBase64(base64::DecodeError),
        UrlHostMissing,
    }

    impl HttpSigExt for ::reqwest::Request {
        type Error = ReqwestSignatureError;

        fn with_sig(
            mut self,
            key: &str,
            date: DateTime<Utc>,
            headers: Vec<(HeaderName, Option<HeaderValue>)>,
        ) -> Result<Self, Self::Error> {
            if key.len() < KEY_ID_LEN {
                return Err(ReqwestSignatureError::KeyTooShort);
            }

            let date = date.format("%a, %d %b %Y %T GMT").to_string();

            let digest = self.body().map(|body| {
                body_digest(
                    body.as_bytes()
                        .expect("cannot compute digest for stream body"),
                )
            });

            let host = self
                .url()
                .host_str()
                .ok_or(ReqwestSignatureError::UrlHostMissing)?;
            let path = self.url().path();

            let mut bytes_to_sign = format!(
                r#"(request-target): {} {}
host: {}
date: {}"#,
                self.method().as_str().to_lowercase(),
                path,
                host,
                date
            );

            self.headers_mut().insert(
                DATE,
                HeaderValue::from_str(&date)
                    .expect("HTTP formatted date should always be a valid header value"),
            );

            if let Some(digest) = digest {
                let digest_string = format!("SHA-256={}", digest);

                bytes_to_sign.push_str("\ndigest: ");
                bytes_to_sign.push_str(&digest_string);
                self.headers_mut().insert(
                    HeaderName::from_static("digest"),
                    HeaderValue::from_str(&digest_string)
                        .expect("Base64 encoded digest should always be a valid header value"),
                );
            }

            let signature = signature(key, bytes_to_sign.as_bytes())
                .map_err(ReqwestSignatureError::KeyNotBase64)?;
            let auth_header = format!(
                r#"Signature keyId="{}",algorithm="hmac-sha256",signature="{}",headers="(request-target) host date digest"#,
                &key[..KEY_ID_LEN],
                signature
            );

            self.headers_mut().insert(
                AUTHORIZATION,
                HeaderValue::from_str(&auth_header)
                    .expect("Auth signature should always be a valid header value"),
            );

            Ok(self)
        }
    }

    #[cfg(test)]
    mod tests {
        use chrono::{offset::TimeZone, Utc};
        use http::header::{AUTHORIZATION, CONTENT_TYPE, DATE, HOST};

        use super::HttpSigExt;

        #[test]
        fn it_works() {
            let client = reqwest::Client::new();

            let without_sig = client
                .post("http://test.com/foo/bar")
                .header(CONTENT_TYPE, "application/json")
                .body(&br#"{ "x": 1, "y": 2}"#[..])
                .build()
                .unwrap();

            let with_sig = without_sig
                .with_sig(
                    "abcdefgh",
                    Utc.ymd(2014, 7, 8).and_hms(9, 10, 11),
                    vec![(HOST, None)],
                )
                .unwrap();

            assert_eq!(with_sig.headers().get(AUTHORIZATION).unwrap(), "Signature keyId=\"abcdefgh\",algorithm=\"hmac-sha256\",signature=\"2fZGHoEIscD9Kak7lxSmKgwk6KZEYiE+rm3s1qMtj8w=\",headers=\"(request-target) host date digest");
        }
    }

}

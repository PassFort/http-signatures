use std::collections::BTreeSet;
use std::convert::TryInto;
use std::error::Error;
use std::fmt;
use std::sync::Arc;

use chrono::Utc;
use http::header::{HeaderName, HeaderValue, AUTHORIZATION, DATE, HOST};

use hmac::Mac;
use sha2::Digest;

use crate::algorithm::{HttpDigest, HttpSignature};
use crate::header::{Header, PseudoHeader};
use crate::{DefaultDigestAlgorithm, DefaultSignatureAlgorithm, DATE_FORMAT};

pub trait ClientRequestLike {
    fn host(&self) -> Option<String>;
    fn set_header(&mut self, header: HeaderName, value: HeaderValue);
    fn header(&self, header: &Header) -> Option<HeaderValue>;
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String>;
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SigningError {
    Unknown,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SigningError::Unknown => f.write_str("Unknown error"),
        }
    }
}

impl Error for SigningError {}

#[derive(Debug, Clone)]
pub struct SigningConfig {
    signature: Arc<dyn HttpSignature>,
    digest: Arc<dyn HttpDigest>,
    key_id: String,
    headers: BTreeSet<Header>,
    compute_digest: bool,
    add_date: bool,
    add_host: bool,
}

impl SigningConfig {
    // Use the default signature algorithm
    pub fn new_default(key_id: &str, key: &[u8]) -> Self {
        Self::new(
            key_id,
            DefaultSignatureAlgorithm::new_varkey(key).expect("HMAC can take key of any size"),
        )
    }

    pub fn new<SigAlg: HttpSignature>(key_id: &str, signature: SigAlg) -> Self {
        SigningConfig {
            signature: Arc::new(signature),
            digest: Arc::new(DefaultDigestAlgorithm::new()),
            key_id: key_id.into(),
            headers: [
                Header::Pseudo(PseudoHeader::RequestTarget),
                Header::Normal(HOST),
                Header::Normal(DATE),
                Header::Normal(HeaderName::from_static("digest")),
            ]
            .iter()
            .cloned()
            .collect(),
            compute_digest: true,
            add_date: true,
            add_host: true,
        }
    }

    pub fn key_id(&self) -> &str {
        self.key_id.as_ref()
    }
    pub fn digest(&self) -> &dyn HttpDigest {
        &*self.digest
    }
    fn set_digest<DigestAlg: HttpDigest>(&mut self, digest: DigestAlg) -> &mut Self {
        self.digest = Arc::new(digest);
        self
    }
    pub fn with_digest<DigestAlg: HttpDigest>(mut self, digest: DigestAlg) -> Self {
        self.set_digest(digest);
        self
    }
    pub fn compute_digest(&self) -> bool {
        self.compute_digest
    }
    pub fn set_compute_digest(&mut self, compute_digest: bool) -> &mut Self {
        self.compute_digest = compute_digest;
        self
    }
    pub fn with_compute_digest(mut self, compute_digest: bool) -> Self {
        self.set_compute_digest(compute_digest);
        self
    }
    pub fn add_date(&self) -> bool {
        self.add_date
    }
    pub fn set_add_date(&mut self, add_date: bool) -> &mut Self {
        self.add_date = add_date;
        self
    }
    pub fn with_add_date(mut self, add_date: bool) -> Self {
        self.set_add_date(add_date);
        self
    }
    pub fn add_host(&self) -> bool {
        self.add_host
    }
    pub fn set_add_host(&mut self, add_host: bool) -> &mut Self {
        self.add_host = add_host;
        self
    }
    pub fn with_add_host(mut self, add_host: bool) -> Self {
        self.set_add_host(add_host);
        self
    }
    pub fn headers(&self) -> impl IntoIterator<Item = &Header> {
        &self.headers
    }
    pub fn set_headers(&mut self, headers: &[Header]) -> &mut Self {
        self.headers = headers.iter().cloned().collect();
        self
    }
    pub fn with_headers(mut self, headers: &[Header]) -> Self {
        self.set_headers(headers);
        self
    }
}

pub trait SigningExt: Sized {
    fn signed(mut self, config: &SigningConfig) -> Result<Self, SigningError> {
        self.sign(config)?;
        Ok(self)
    }

    fn sign(&mut self, config: &SigningConfig) -> Result<(), SigningError>;
}

impl<R: ClientRequestLike> SigningExt for R {
    fn sign(&mut self, config: &SigningConfig) -> Result<(), SigningError> {
        let digest_header = HeaderName::from_static("digest");

        // Add missing date header
        if config.add_date && self.header(&DATE.into()).is_none() {
            let date = Utc::now().format(DATE_FORMAT).to_string();
            self.set_header(
                DATE,
                date.try_into()
                    .expect("Dates should always be valid header values"),
            );
        }
        // Add missing host header
        if config.add_host && self.header(&HOST.into()).is_none() {
            if let Some(host) = self.host() {
                self.set_header(
                    HOST,
                    host.try_into()
                        .expect("Host should be valid in a HTTP header"),
                );
            }
        }
        // Add missing digest header
        if config.compute_digest && self.header(&digest_header.clone().into()).is_none() {
            if let Some(digest_str) = self.compute_digest(&*config.digest) {
                let digest = format!("{}={}", config.digest.name(), digest_str);
                self.set_header(
                    digest_header,
                    digest
                        .try_into()
                        .expect("Digest should be valid in a HTTP header"),
                );
            }
        }

        // Build the content block
        let (header_vec, content_vec): (Vec<_>, Vec<_>) = config
            .headers
            .iter()
            .filter_map(|header| {
                // Lookup header values, and filter out any headers that are missing
                self.header(&header)
                    .as_ref()
                    .and_then(|value| value.to_str().ok())
                    .map(|value| (header.as_str(), value.to_owned()))
            })
            .map(|(header, value)| {
                // Construct the content to be signed
                (header, format!("{}: {}", header, value))
            })
            .unzip();

        let headers = header_vec.join(" ");
        let content = content_vec.join("\n");

        // Sign the content
        let signature = config.signature.http_sign(content.as_bytes());

        // Construct the authorization header
        let auth_header = format!(
            r#"Signature keyId="{}",algorithm="{}",signature="{}",headers="{}"#,
            config.key_id,
            config.signature.name(),
            signature,
            headers
        );

        // Attach the authorization header to the request
        self.set_header(
            AUTHORIZATION,
            auth_header
                .try_into()
                .expect("Signature scheme should generate a valid header"),
        );

        Ok(())
    }
}

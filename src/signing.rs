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

/// This trait is to be implemented for types representing an outgoing
/// HTTP request. The HTTP signing extension methods are available on
/// any type implementing this trait.
pub trait ClientRequestLike {
    /// Returns the host for the request (eg. "example.com") in case the Host header has
    /// not been set explicitly.
    /// When implementing this trait, do not just read the `Host` header from the request -
    /// this method will only be called when the `Host` header is not set.
    fn host(&self) -> Option<String>;
    /// Add a header to the request. This function may be used to set the `Date` and `Digest`
    /// headers if not already present depending on the configuration. The `Authorization`
    /// header will always be set assuming the message was signed successfully.
    fn set_header(&mut self, header: HeaderName, value: HeaderValue);
    /// Returns an existing header on the request. This method *must* reflect changes made
    /// be the `set_header` method, with the possible exception of the `Authorization`
    /// header itself.
    fn header(&self, header: &Header) -> Option<HeaderValue>;
    /// Compute the digest using the provided HTTP digest algorithm. If this is not possible,
    /// then return `None`. This may require buffering the request data into memory.
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String>;
}

/// The types of error which may occur whilst signing.
#[derive(Debug)]
#[non_exhaustive]
pub enum SigningError {
    #[doc(hidden)]
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

/// The configuration used for signing HTTP requests.
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
    /// Creates a new signing configuration using the default signature algorithm, and the
    /// specified key ID and key.
    pub fn new_default(key_id: &str, key: &[u8]) -> Self {
        Self::new(
            key_id,
            DefaultSignatureAlgorithm::new_varkey(key).expect("HMAC can take key of any size"),
        )
    }

    /// Creates a new signing configuration using a custom signature algorithm, and the specified
    /// key ID.
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

    /// Returns the key ID.
    pub fn key_id(&self) -> &str {
        self.key_id.as_ref()
    }
    /// Returns the HTTP digest algorithm.
    pub fn digest(&self) -> &dyn HttpDigest {
        &*self.digest
    }
    /// Sets the HTTP digest algorithm (in-place).
    fn set_digest<DigestAlg: HttpDigest>(&mut self, digest: DigestAlg) -> &mut Self {
        self.digest = Arc::new(digest);
        self
    }
    /// Sets the HTTP digest algorithm.
    pub fn with_digest<DigestAlg: HttpDigest>(mut self, digest: DigestAlg) -> Self {
        self.set_digest(digest);
        self
    }
    /// Returns whether the digest will be automatically computed
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn compute_digest(&self) -> bool {
        self.compute_digest
    }
    /// Controls whether the digest will be automatically computed
    /// when not already present (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_compute_digest(&mut self, compute_digest: bool) -> &mut Self {
        self.compute_digest = compute_digest;
        self
    }
    /// Controls whether the digest will be automatically computed
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn with_compute_digest(mut self, compute_digest: bool) -> Self {
        self.set_compute_digest(compute_digest);
        self
    }
    /// Returns whether the current date and time will be added to the request
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn add_date(&self) -> bool {
        self.add_date
    }
    /// Controls whether the current date and time will be added to the request
    /// when not already present (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_add_date(&mut self, add_date: bool) -> &mut Self {
        self.add_date = add_date;
        self
    }
    /// Controls whether the current date and time will be added to the request
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn with_add_date(mut self, add_date: bool) -> Self {
        self.set_add_date(add_date);
        self
    }
    /// Returns whether the host will be added to the request
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn add_host(&self) -> bool {
        self.add_host
    }
    /// Controls whether the host will be added to the request
    /// when not already present (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_add_host(&mut self, add_host: bool) -> &mut Self {
        self.add_host = add_host;
        self
    }
    /// Controls whether the host will be added to the request
    /// when not already present.
    ///
    /// This is set to `true` by default.
    pub fn with_add_host(mut self, add_host: bool) -> Self {
        self.set_add_host(add_host);
        self
    }
    /// Returns the list of headers to include in the signature. Headers in this list
    /// which are not present in the request itself will be skipped when signing the request.
    ///
    /// This list contains `(request-target)`, `host`, `date` and `digest` by default.
    pub fn headers(&self) -> impl IntoIterator<Item = &Header> {
        &self.headers
    }
    /// Controls the list of headers to include in the signature (in-place). Headers in this list
    /// which are not present in the request itself will be skipped when signing the request.
    ///
    /// This list contains `(request-target)`, `host`, `date` and `digest` by default.
    pub fn set_headers(&mut self, headers: &[Header]) -> &mut Self {
        self.headers = headers.iter().cloned().collect();
        self
    }
    /// Controls the list of headers to include in the signature. Headers in this list
    /// which are not present in the request itself will be skipped when signing the request.
    ///
    /// This list contains `(request-target)`, `host`, `date` and `digest` by default.
    pub fn with_headers(mut self, headers: &[Header]) -> Self {
        self.set_headers(headers);
        self
    }
}

/// Import this trait to get access to access the `signed` and `sign` methods on all types implementing
/// `ClientRequestLike`.
pub trait SigningExt: Sized {
    /// Consumes the request and returns it signed according to the provided configuration.
    fn signed(mut self, config: &SigningConfig) -> Result<Self, SigningError> {
        self.sign(config)?;
        Ok(self)
    }

    /// Signs the request in-place according to the provided configuration.
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

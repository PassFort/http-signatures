use std::convert::TryInto;
use std::sync::Arc;
use std::time::SystemTime;

use chrono::Utc;
use http::header::{HeaderName, HeaderValue, DATE, HOST};
use itertools::Itertools;
use thiserror::Error;

use sha2::Digest;

use crate::algorithm::{HttpDigest, HttpSignatureSign};
use crate::canonicalize::{CanonicalizeConfig, CanonicalizeError, CanonicalizeExt, RequestLike};
use crate::header::{Header, PseudoHeader};
use crate::{DefaultDigestAlgorithm, DefaultSignatureAlgorithm, DATE_FORMAT};

/// This trait is to be implemented for types representing an outgoing
/// HTTP request. The HTTP signing extension methods are available on
/// any type implementing this trait.
pub trait ClientRequestLike: RequestLike {
    /// Returns the host for the request (eg. "example.com") in case the Host header has
    /// not been set explicitly.
    /// When implementing this trait, do not just read the `Host` header from the request -
    /// this method will only be called when the `Host` header is not set.
    fn host(&self) -> Option<String> {
        None
    }
    /// Add a header to the request. This function may be used to set the `Date` and `Digest`
    /// headers if not already present depending on the configuration. The `Signature`
    /// header will always be set assuming the message was signed successfully.
    fn set_header(&mut self, header: HeaderName, value: HeaderValue);
    /// Compute the digest using the provided HTTP digest algorithm. If this is not possible,
    /// then return `None`. This may require buffering the request data into memory.
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String>;
}

/// The types of error which may occur whilst signing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SigningError {
    /// A header required to be part of the signature was not present
    /// on the request, and the `skip_missing` configuration option
    /// was disabled.
    #[error("Failed to canonicalize request")]
    Canonicalize(#[source] CanonicalizeError),

    /// The signature creation date was in the future
    #[error("Signature creation date was in the future")]
    InvalidSignatureCreationDate,

    /// The signature expires date was in the past
    #[error("Signature expires date was in the past")]
    InvalidSignatureExpiresDate,
}

impl From<CanonicalizeError> for SigningError {
    fn from(other: CanonicalizeError) -> Self {
        Self::Canonicalize(other)
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum SignatureCreated {
    Omit,
    Automatic,
    Absolute(i64),
}

impl SignatureCreated {
    fn get(self, ts: i64) -> Option<i64> {
        match self {
            Self::Omit => None,
            Self::Automatic => Some(ts),
            Self::Absolute(ts) => Some(ts),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
enum SignatureExpires {
    Omit,
    Relative(i64),
    Absolute(i64),
}

impl SignatureExpires {
    fn get(self, ts: i64) -> Option<i64> {
        match self {
            Self::Omit => None,
            Self::Relative(offset) => Some(ts.saturating_add(offset)),
            Self::Absolute(ts) => Some(ts),
        }
    }
}

/// The configuration used for signing HTTP requests.
#[derive(Debug, Clone)]
pub struct SigningConfig {
    signature: Arc<dyn HttpSignatureSign>,
    digest: Arc<dyn HttpDigest>,
    key_id: String,
    headers: Vec<Header>,
    compute_digest: bool,
    add_date: bool,
    add_host: bool,
    skip_missing: bool,
    signature_created: SignatureCreated,
    signature_expires: SignatureExpires,
}

impl SigningConfig {
    /// Creates a new signing configuration using the default signature algorithm, and the
    /// specified key ID and key.
    pub fn new_default(key_id: &str, key: &[u8]) -> Self {
        Self::new(key_id, DefaultSignatureAlgorithm::new(key))
    }

    /// Creates a new signing configuration using a custom signature algorithm, and the specified
    /// key ID.
    pub fn new<SigAlg: HttpSignatureSign>(key_id: &str, signature: SigAlg) -> Self {
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
            .to_vec(),
            compute_digest: true,
            add_date: true,
            add_host: true,
            skip_missing: true,
            signature_created: SignatureCreated::Omit,
            signature_expires: SignatureExpires::Omit,
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
        self.headers = headers.to_vec();
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
    /// Returns whether the missing headers will be skipped
    /// when not present, or if signing will fail instead.
    ///
    /// This is set to `true` by default.
    pub fn skip_missing(&self) -> bool {
        self.skip_missing
    }
    /// Controls whether the missing headers will be skipped
    /// when not present, or if signing will fail instead.
    ///
    /// This is set to `true` by default.
    pub fn set_skip_missing(&mut self, skip_missing: bool) -> &mut Self {
        self.skip_missing = skip_missing;
        self
    }
    /// Controls whether the missing headers will be skipped
    /// when not present, or if signing will fail instead.
    ///
    /// This is set to `true` by default.
    pub fn with_skip_missing(mut self, skip_missing: bool) -> Self {
        self.set_skip_missing(skip_missing);
        self
    }
    /// Ensures a signature created date will be added
    /// automatically with the current time.
    ///
    /// This is off by default.
    pub fn set_signature_created_auto(&mut self) -> &mut Self {
        self.signature_created = SignatureCreated::Automatic;
        self
    }
    /// Ensures a signature created date will be added
    /// automatically with the current time.
    ///
    /// This is off by default.
    pub fn with_signature_created_auto(mut self) -> Self {
        self.signature_created = SignatureCreated::Automatic;
        self
    }
    /// Determines if a signature created date will be added
    /// automatically with the current time.
    ///
    /// This is off by default.
    pub fn signature_created_auto(&self) -> bool {
        self.signature_created == SignatureCreated::Automatic
    }
    /// Ensures a signature created date will be added
    /// with the specified unix timestamp.
    ///
    /// This is off by default.
    pub fn set_signature_created_at(&mut self, ts: i64) -> &mut Self {
        self.signature_created = SignatureCreated::Absolute(ts);
        self
    }
    /// Ensures a signature created date will be added
    /// with the specified unix timestamp.
    ///
    /// This is off by default.
    pub fn with_signature_created_at(mut self, ts: i64) -> Self {
        self.signature_created = SignatureCreated::Absolute(ts);
        self
    }
    /// Determines if a signature created date will be added
    /// with a specific unix timestamp.
    ///
    /// This is off by default.
    pub fn signature_created_at(&self) -> Option<i64> {
        if let SignatureCreated::Absolute(ts) = self.signature_created {
            Some(ts)
        } else {
            None
        }
    }
    /// Ensures a signature expires date will be added
    /// automatically relative to the current time.
    ///
    /// This is off by default.
    pub fn set_signature_expires_relative(&mut self, offset: i64) -> &mut Self {
        self.signature_expires = SignatureExpires::Relative(offset);
        self
    }
    /// Ensures a signature expires date will be added
    /// automatically relative to the current time.
    ///
    /// This is off by default.
    pub fn with_signature_expires_auto(mut self, offset: i64) -> Self {
        self.signature_expires = SignatureExpires::Relative(offset);
        self
    }
    /// Determines if a signature expires date will be added
    /// automatically relative to the current time.
    ///
    /// This is off by default.
    pub fn signature_expires_relative(&self) -> Option<i64> {
        if let SignatureExpires::Relative(offset) = self.signature_expires {
            Some(offset)
        } else {
            None
        }
    }
    /// Ensures a signature expires date will be added
    /// with the specified unix timestamp.
    ///
    /// This is off by default.
    pub fn set_signature_expires_at(&mut self, ts: i64) -> &mut Self {
        self.signature_expires = SignatureExpires::Absolute(ts);
        self
    }
    /// Ensures a signature expires date will be added
    /// with the specified unix timestamp.
    ///
    /// This is off by default.
    pub fn with_signature_expires_at(mut self, ts: i64) -> Self {
        self.signature_expires = SignatureExpires::Absolute(ts);
        self
    }
    /// Determines if a signature expires date will be added
    /// with a specific unix timestamp.
    ///
    /// This is off by default.
    pub fn signature_expires_at(&self) -> Option<i64> {
        if let SignatureExpires::Absolute(ts) = self.signature_expires {
            Some(ts)
        } else {
            None
        }
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

fn add_auto_headers<R: ClientRequestLike>(request: &mut R, config: &SigningConfig) -> Vec<Header> {
    let digest_header = HeaderName::from_static("digest");

    // Add missing date header
    if config.add_date && !request.has_header(&DATE.into()) {
        let date = Utc::now().format(DATE_FORMAT).to_string();
        request.set_header(
            DATE,
            date.try_into()
                .expect("Dates should always be valid header values"),
        );
    }
    // Add missing host header
    if config.add_host && !request.has_header(&HOST.into()) {
        if let Some(host) = request.host() {
            request.set_header(
                HOST,
                host.try_into()
                    .expect("Host should be valid in a HTTP header"),
            );
        }
    }
    // Add missing digest header
    if config.compute_digest && !request.has_header(&digest_header.clone().into()) {
        if let Some(digest_str) = request.compute_digest(&*config.digest) {
            let digest = format!("{}={}", config.digest.name(), digest_str);
            request.set_header(
                digest_header,
                digest
                    .try_into()
                    .expect("Digest should be valid in a HTTP header"),
            );
        }
    }

    // Build the content block
    if config.skip_missing {
        config
            .headers
            .iter()
            .filter(|header| request.has_header(header))
            .cloned()
            .collect()
    } else {
        config.headers.clone()
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Unix time to be positive")
        .as_secs() as i64
}

impl<R: ClientRequestLike> SigningExt for R {
    fn sign(&mut self, config: &SigningConfig) -> Result<(), SigningError> {
        // Add missing headers
        let headers = add_auto_headers(self, config);

        let joined_headers = headers.iter().map(|header| header.as_str()).join(" ");

        // Determine config for canonicalization
        let ts = unix_timestamp();
        let mut canonicalize_config = CanonicalizeConfig::new().with_headers(headers);
        if let Some(created) = config.signature_created.get(ts) {
            if created > ts {
                return Err(SigningError::InvalidSignatureCreationDate);
            }
            canonicalize_config.set_signature_created(created.into());
        }
        if let Some(expires) = config.signature_expires.get(ts) {
            if expires < ts {
                return Err(SigningError::InvalidSignatureExpiresDate);
            }
            canonicalize_config.set_signature_expires(expires.into());
        }

        // Compute canonical representation
        let content = self.canonicalize(&canonicalize_config)?;

        // Sign the content
        let signature = config.signature.http_sign(content.as_bytes());

        // Construct the signature header
        let auth_header = format!(
            "keyId=\"{}\",algorithm=\"{}\",signature=\"{}\",headers=\"{}\"",
            config.key_id, "hs2019", signature, joined_headers
        );

        // Attach the Signature header to the request
        self.set_header(
            HeaderName::from_static("signature"),
            auth_header
                .try_into()
                .expect("Signature scheme should generate a valid header"),
        );

        Ok(())
    }
}

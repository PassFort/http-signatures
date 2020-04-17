use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt::{self, Debug, Display};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use http::header::{HeaderName, HeaderValue, AUTHORIZATION, DATE};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::algorithm::{HttpDigest, HttpSignatureVerify};
use crate::canonicalize::{CanonicalizeConfig, CanonicalizeExt};
use crate::header::{Header, PseudoHeader};
use crate::{DefaultDigestAlgorithm, RequestLike, DATE_FORMAT};

/// This error indicates that we failed to verify the request. As a result
/// the request should be ignored.
#[derive(Debug)]
#[non_exhaustive]
pub struct VerifyingError<Remnant> {
    remnant: Remnant,
}

impl<Remnant> VerifyingError<Remnant> {
    /// For some request types, the verification process may be a destructive operation.
    /// This method can be used to access information that would otherwise be lost as a
    /// result of the failed verification.
    pub fn into_remnant(self) -> Remnant {
        self.remnant
    }
}

impl<Remnant: Debug> Error for VerifyingError<Remnant> {}

impl<Remnant> Display for VerifyingError<Remnant> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("VerifyingError")
    }
}

/// The verification process will use this trait to find the appropriate key and algorithm
/// to use for verifying a request.
///
/// You do not need to implement this yourself: the `SimpleKeyProvider` type provides an
/// key store that should be suitable for many situations.
pub trait KeyProvider: Debug + Sync + 'static {
    /// Given the name of an algorithm (eg. `hmac-sha256`) and the key ID, return a set
    /// of possible keys and algorithms. Returns an empty Vec if no appropriate key/algorithm
    /// combination could be found.
    fn provide_keys(&self, key_id: &str) -> Vec<Arc<dyn HttpSignatureVerify>>;
}

/// Implementation of a simple key store.
///
/// Can store multiple keys with the same Key ID but different algorithms.
/// If no algorithm is specified in the request, the first key added for
/// that Key ID will be used.
#[derive(Debug, Default, Clone)]
pub struct SimpleKeyProvider {
    keys: HashMap<String, Vec<Arc<dyn HttpSignatureVerify>>>,
}

impl SimpleKeyProvider {
    /// Initializes the key store from a list of key IDs and signature
    /// algorithms.
    pub fn new<I, S, K>(key_iter: I) -> Self
    where
        I: IntoIterator<Item = (S, K)>,
        S: Into<String>,
        K: Into<Arc<dyn HttpSignatureVerify>>,
    {
        let mut keys: HashMap<String, Vec<_>> = HashMap::new();
        for (key_id, key) in key_iter.into_iter() {
            keys.entry(key_id.into()).or_default().push(key.into());
        }
        Self { keys }
    }

    /// Adds a key to the key store
    pub fn add(&mut self, key_id: &str, key: Arc<dyn HttpSignatureVerify>) {
        self.keys.entry(key_id.into()).or_default().push(key);
    }
    /// Clears all keys from the key store
    pub fn clear(&mut self) {
        self.keys.clear();
    }
    /// Removes all keys with the specified Key ID from the key store
    pub fn remove_all(&mut self, key_id: &str) {
        self.keys.remove(key_id);
    }
}

impl KeyProvider for SimpleKeyProvider {
    fn provide_keys(&self, key_id: &str) -> Vec<Arc<dyn HttpSignatureVerify>> {
        self.keys.get(key_id).unwrap_or(&Vec::new()).to_vec()
    }
}

/// The verification process will use this trait to find the appropriate digest algorithm
/// to use when verifying the body of a request.
///
/// Unless explicitly overridden, the `DefaultDigestProvider` will be used
pub trait DigestProvider: Debug + Sync + 'static {
    /// Returns a digest algorithm for the given name, or `None` if the algorithm is not
    /// recognised by the provider.
    fn provide_digest(&self, name: &str) -> Option<Box<dyn HttpDigest>>;
}

/// Supports the `SHA-256` and `SHA-512` digest algorithms.
#[derive(Debug, Default, Copy, Clone)]
pub struct DefaultDigestProvider;

impl DigestProvider for DefaultDigestProvider {
    fn provide_digest(&self, name: &str) -> Option<Box<dyn HttpDigest>> {
        let name = name.to_ascii_uppercase();
        match name.as_str() {
            "SHA-256" => Some(Box::new(Sha256::new())),
            "SHA-512" => Some(Box::new(Sha512::new())),
            _ => None,
        }
    }
}

/// The configuration used for verifying HTTP requests.
#[derive(Debug)]
pub struct VerifyingConfig {
    key_provider: Arc<dyn KeyProvider>,
    digest_provider: Arc<dyn DigestProvider>,
    required_headers: BTreeSet<Header>,
    require_digest: bool,
    validate_digest: bool,
    validate_date: bool,
    date_leeway: Duration,
}

impl VerifyingConfig {
    /// Creates a new verifying configuration using the given key provider.
    pub fn new<KP: KeyProvider>(key_provider: KP) -> Self {
        VerifyingConfig {
            key_provider: Arc::new(key_provider),
            digest_provider: Arc::new(DefaultDigestProvider),
            required_headers: [
                Header::Pseudo(PseudoHeader::RequestTarget),
                Header::Normal(DATE),
            ]
            .iter()
            .cloned()
            .collect(),
            require_digest: true,
            validate_digest: true,
            validate_date: true,
            date_leeway: Duration::from_secs(30),
        }
    }

    /// Returns the key provider.
    pub fn key_provider(&self) -> &dyn KeyProvider {
        &*self.key_provider
    }
    /// Returns the digest provider.
    pub fn digest_provider(&self) -> &dyn DigestProvider {
        &*self.digest_provider
    }
    /// Sets the digest provider (in-place).
    fn set_digest_provider<DP: DigestProvider>(&mut self, digest_provider: DP) -> &mut Self {
        self.digest_provider = Arc::new(digest_provider);
        self
    }
    /// Sets the digest provider.
    pub fn with_digest<DP: DigestProvider>(mut self, digest_provider: DP) -> Self {
        self.set_digest_provider(digest_provider);
        self
    }
    /// Returns whether a digest header must be present and included in the signature for requests
    /// with a body.
    ///
    /// This is set to `true` by default.
    pub fn require_digest(&self) -> bool {
        self.require_digest
    }
    /// Controls whether a digest header must be present and included in the signature for requests
    /// with a body (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_require_digest(&mut self, require_digest: bool) -> &mut Self {
        self.require_digest = require_digest;
        self
    }
    /// Controls whether a digest header must be present and included in the signature for requests
    /// with a body.
    ///
    /// This is set to `true` by default.
    pub fn with_require_digest(mut self, require_digest: bool) -> Self {
        self.set_require_digest(require_digest);
        self
    }
    /// Returns whether the request body will be checked against the digest for correctness if the
    /// digest is included in the signature.
    ///
    /// This is set to `true` by default.
    pub fn validate_digest(&self) -> bool {
        self.validate_digest
    }
    /// Controls whether the request body will be checked against the digest for correctness if the
    /// digest is included in the signature (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_validate_digest(&mut self, validate_digest: bool) -> &mut Self {
        self.validate_digest = validate_digest;
        self
    }
    /// Controls whether the request body will be checked against the digest for correctness if the
    /// digest is included in the signature.
    ///
    /// This is set to `true` by default.
    pub fn with_validate_digest(mut self, validate_digest: bool) -> Self {
        self.set_validate_digest(validate_digest);
        self
    }
    /// Returns whether the date header will be compared against the current date and time if the
    /// date header is included in the signature.
    ///
    /// This is set to `true` by default.
    pub fn validate_date(&self) -> bool {
        self.validate_date
    }
    /// Controls whether the date header will be compared against the current date and time if the
    /// date header is included in the signature (in-place).
    ///
    /// This is set to `true` by default.
    pub fn set_validate_date(&mut self, validate_date: bool) -> &mut Self {
        self.validate_date = validate_date;
        self
    }
    /// Controls whether the date header will be compared against the current date and time if the
    /// date header is included in the signature.
    ///
    /// This is set to `true` by default.
    pub fn with_validate_date(mut self, validate_date: bool) -> Self {
        self.set_validate_date(validate_date);
        self
    }
    /// Returns the amount of leeway allowed in either direction when comparing dates and times
    /// from requests against the current date and time.
    ///
    /// This is set to 30 seconds by default.
    pub fn date_leeway(&self) -> Duration {
        self.date_leeway
    }
    /// Controls the amount of leeway allowed in either direction when comparing dates and times
    /// from requests against the current date and time (in-place).
    ///
    /// This is set to 30 seconds by default.
    pub fn set_date_leeway(&mut self, date_leeway: Duration) -> &mut Self {
        self.date_leeway = date_leeway;
        self
    }
    /// Controls the amount of leeway allowed in either direction when comparing dates and times
    /// from requests against the current date and time.
    ///
    /// This is set to 30 seconds by default.
    pub fn with_date_leeway(mut self, date_leeway: Duration) -> Self {
        self.set_date_leeway(date_leeway);
        self
    }
    /// Returns the list of headers that *must* be included in every request's signature. Do not
    /// include the `digest` header here or requests without a body will be denied. Instead, rely
    /// on the `validate_digest` option.
    ///
    /// This list contains `(request-target)` and `date` by default.
    pub fn required_headers(&self) -> impl IntoIterator<Item = &Header> {
        &self.required_headers
    }
    /// Controls the list of headers that *must* be included in every request's signature (in-place). Do not
    /// include the `digest` header here or requests without a body will be denied. Instead, rely
    /// on the `validate_digest` option.
    ///
    /// This list contains `(request-target)` and `date` by default.
    pub fn set_required_headers(&mut self, required_headers: &[Header]) -> &mut Self {
        self.required_headers = required_headers.iter().cloned().collect();
        self
    }
    /// Controls the list of headers that *must* be included in every request's signature. Do not
    /// include the `digest` header here or requests without a body will be denied. Instead, rely
    /// on the `validate_digest` option.
    ///
    /// This list contains `(request-target)` and `date` by default.
    pub fn with_required_headers(mut self, required_headers: &[Header]) -> Self {
        self.set_required_headers(required_headers);
        self
    }
}

/// This trait is to be implemented for types representing an incoming
/// HTTP request. The HTTP verification extension methods are available on
/// any type implementing this trait.
///
/// Typically this trait is implemented for references or mutable references to those
/// request types rather than for the request type itself.
pub trait ServerRequestLike: RequestLike {
    /// For some request types, the verification process may be a destructive operation.
    /// This associated type can be used to return information that might otherwise
    /// be lost.
    type Remnant;

    /// Complete the verification process, indicating that we want to compute a digest of the
    /// request body. This may require buffering the whole request body into memory.
    ///
    /// If a request body was present, its digest should be returned as the first element of
    /// the tuple. Otherwise `None` should be returned. The second tuple element may contain
    /// any information the implementation wants returned to the caller (for example the buffered
    /// request body, if it had to be removed from the request).
    fn complete_with_digest(self, digest: &dyn HttpDigest) -> (Option<String>, Self::Remnant);

    /// Complete the verification process without attempting to compute a digest.
    fn complete(self) -> Self::Remnant;
}

/// Contains information about a successfully validated request.
#[derive(Debug)]
pub struct VerificationDetails {
    key_id: String,
}

impl VerificationDetails {
    /// Returns the ID of the key used to validate this request's signature.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Import this trait to get access to access the `verify` method on all types implementing
/// `ServerRequestLike`.
pub trait VerifyingExt {
    /// For some request types, the verification process may be a destructive operation.
    /// This associated type can be used to return information that might otherwise
    /// be lost.
    type Remnant;

    /// Verify the request using the given verification configuration.
    fn verify(
        self,
        config: &VerifyingConfig,
    ) -> Result<(Self::Remnant, VerificationDetails), VerifyingError<Self::Remnant>>;
}

fn verify_signature_only<T: ServerRequestLike>(
    req: &T,
    config: &VerifyingConfig,
) -> Option<(BTreeMap<Header, HeaderValue>, VerificationDetails)> {
    let auth_header = req.header(&AUTHORIZATION.into()).or_else(|| {
        info!("Verification Failed: No 'Authorization' header");
        None
    })?;
    let mut auth_header = auth_header
        .to_str()
        .ok()
        .or_else(|| {
            info!("Verification Failed: Non-ascii 'Authorization' header");
            None
        })?
        .splitn(2, ' ');

    let auth_scheme = auth_header.next().or_else(|| {
        info!("Verification Failed: Malformed 'Authorization' header");
        None
    })?;
    let auth_args = auth_header.next().or_else(|| {
        info!("Verification Failed: Malformed 'Authorization' header");
        None
    })?;

    // Check that we're using signature auth
    if !auth_scheme.eq_ignore_ascii_case("Signature") {
        info!("Verification Failed: Not using Signature auth");
        return None;
    }

    // Parse the auth params
    let auth_args = auth_args
        .split(',')
        .map(|part: &str| {
            let mut kv = part.splitn(2, '=');
            let k = kv.next()?.trim();
            let v = kv.next()?.trim().trim_matches('"');
            Some((k, v))
        })
        .collect::<Option<BTreeMap<_, _>>>()
        .or_else(|| {
            info!("Verification Failed: Unable to parse 'Authorization' header");
            None
        })?;

    let key_id = *auth_args.get("keyId").or_else(|| {
        info!("Verification Failed: Missing required 'keyId' in 'Authorization' header");
        None
    })?;
    let provided_signature = auth_args.get("signature").or_else(|| {
        info!("Verification Failed: Missing required 'signature' in 'Authorization' header");
        None
    })?;
    let algorithm_name = auth_args.get("algorithm").copied();
    let verification_details = VerificationDetails {
        key_id: key_id.into(),
    };

    // Find the appropriate key
    let algorithms = config.key_provider.provide_keys(key_id);
    if algorithms.is_empty() {
        info!(
            "Verification Failed: Unknown key (keyId={:?}, algorithm={:?})",
            key_id,
            algorithm_name.unwrap_or_default()
        );
        return None;
    }

    // Determine config for canonicalization
    let mut canonicalize_config = CanonicalizeConfig::new();
    if let Some(headers) = auth_args.get("headers") {
        canonicalize_config.set_headers(
            headers
                .split(' ')
                .map(str::to_ascii_lowercase)
                .map(|header| {
                    header.parse::<Header>().ok().or_else(|| {
                        info!("Verification Failed: Invalid header name {:?}", header);
                        None
                    })
                })
                .collect::<Option<_>>()?,
        );
    }
    if let Some(created) = auth_args.get("created") {
        canonicalize_config.set_signature_created(created.parse::<HeaderValue>().ok().or_else(
            || {
                info!(
                    "Verification Failed: Invalid signature creation date {:?}",
                    created
                );
                None
            },
        )?);
    }
    if let Some(expires) = auth_args.get("expires") {
        canonicalize_config.set_signature_expires(expires.parse::<HeaderValue>().ok().or_else(
            || {
                info!(
                    "Verification Failed: Invalid signature expires date {:?}",
                    expires
                );
                None
            },
        )?);
    }

    // Canonicalize the request
    let content = req
        .canonicalize(&canonicalize_config)
        .map_err(|e| {
            info!("Canonicalization Failed: {}", e);
        })
        .ok()?;

    // Verify the signature of the content
    for algorithm in &algorithms {
        if algorithm.http_verify(content.as_bytes(), provided_signature) {
            return Some((content.headers.into_iter().collect(), verification_details));
        }
    }

    if algorithms.is_empty() {
        info!("Verification Failed: No keys found for this keyId");
    } else {
        info!("Verification Failed: Invalid signature provided");
    }
    None
}

fn verify_except_digest<T: ServerRequestLike>(
    req: &T,
    config: &VerifyingConfig,
) -> Option<(BTreeMap<Header, HeaderValue>, VerificationDetails)> {
    let (headers, verification_details) = verify_signature_only(req, config)?;

    // Check that all the required headers are set
    for header in &config.required_headers {
        if !headers.contains_key(header) {
            info!(
                "Verification Failed: Missing header '{}' required by configuration",
                header.as_str()
            );
            return None;
        }
    }

    // If we are expected to validate the date
    if config.validate_date {
        // If date was part of signature
        if let Some(date_value) = headers.get(&DATE.into()) {
            // First convert to a string
            let date_value = date_value.to_str().ok().or_else(|| {
                info!("Verification Failed: Non-ascii value for 'date' header");
                None
            })?;

            // Then parse into a datetime
            let provided_date = DateTime::<Utc>::from_utc(
                NaiveDateTime::parse_from_str(date_value, DATE_FORMAT)
                    .ok()
                    .or_else(|| {
                        info!("Verification Failed: Failed to parse 'date' header");
                        None
                    })?,
                Utc,
            );

            // Finally, compute the absolute difference between the provided
            // date and now.
            let chrono_delta = provided_date.signed_duration_since(Utc::now());
            let delta = chrono_delta
                .to_std()
                .or_else(|_| (-chrono_delta).to_std())
                .expect("Should only fail on negative values");

            if delta > config.date_leeway {
                info!(
                    "Verification Failed: Date skew of '{}' is outside allowed range",
                    chrono_delta
                );
                return None;
            }
        }
    }

    Some((headers, verification_details))
}

impl<T: ServerRequestLike> VerifyingExt for T {
    type Remnant = T::Remnant;

    fn verify(
        self,
        config: &VerifyingConfig,
    ) -> Result<(Self::Remnant, VerificationDetails), VerifyingError<Self::Remnant>> {
        let digest_header: Header = HeaderName::from_static("digest").into();

        // Check everything but the digest first, as that doesn't require consuming
        // the request.
        let (headers, verification_details) = if let Some(res) = verify_except_digest(&self, config)
        {
            res
        } else {
            return Err(VerifyingError {
                remnant: self.complete(),
            });
        };

        // If we got a digest header
        if let Some(digest_value) = headers.get(&digest_header) {
            // If we are expected to validate it
            if config.validate_digest {
                // First convert to a string
                let digest_value = match digest_value.to_str() {
                    Ok(v) => v,
                    Err(_) => {
                        info!("Verification Failed: Non-ascii value for 'digest' header");
                        return Err(VerifyingError {
                            remnant: self.complete(),
                        });
                    }
                };

                // Find the first digest which is using a supported algorithm
                if let Some((digest_alg, provided_digest)) = digest_value
                    .split(',')
                    .filter_map(|part| {
                        let mut kv = part.splitn(2, '=');
                        let k = kv.next()?.trim();
                        let v = kv.next()?.trim();

                        let digest = config.digest_provider.provide_digest(k)?;
                        Some((digest, v))
                    })
                    .next()
                {
                    // Tell the request to compute a digest as it completes
                    let (maybe_digest, remnant) = self.complete_with_digest(&*digest_alg);

                    // Check that the digest is correct in constant time
                    match maybe_digest {
                        Some(expected_digest)
                            if provided_digest
                                .as_bytes()
                                .ct_eq(expected_digest.as_bytes())
                                .into() =>
                        {
                            Ok((remnant, verification_details))
                        }
                        None => {
                            info!("Verification Failed: Unable to compute digest for comparison");
                            Err(VerifyingError { remnant })
                        }
                        _ => {
                            info!("Verification Failed: Computed digest did not match the 'digest' header");
                            Err(VerifyingError { remnant })
                        }
                    }
                } else {
                    // No supported digest algorithm.
                    info!("Verification Failed: No supported digest algorithms were used");
                    Err(VerifyingError {
                        remnant: self.complete(),
                    })
                }
            } else {
                // We are not expected to validate the digest
                Ok((self.complete(), verification_details))
            }
        } else if config.require_digest {
            // We require a digest for requests with a body, but we didn't get one. Either the request
            // has no body, or we should reject it.
            let (maybe_digest, remnant) = self.complete_with_digest(&DefaultDigestAlgorithm::new());

            // If the request did have a body (because we were able to compute a digest).
            if maybe_digest.is_some() {
                // Then reject the request
                info!("Verification Failed: 'digest' header was not included in signature, but is required by configuration");
                Err(VerifyingError { remnant })
            } else {
                // No body, so request if fine.
                Ok((remnant, verification_details))
            }
        } else {
            // We do not require a digest, valid or otherwise.
            Ok((self.complete(), verification_details))
        }
    }
}

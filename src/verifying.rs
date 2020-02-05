use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, NaiveDateTime, Utc};
use http::header::{HeaderName, HeaderValue, AUTHORIZATION, DATE};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

use crate::algorithm::{HttpDigest, HttpSignature};
use crate::header::{Header, PseudoHeader};
use crate::{DefaultDigestAlgorithm, DATE_FORMAT};

#[derive(Debug)]
#[non_exhaustive]
pub struct VerifyingError<Remnant> {
    remnant: Remnant,
}

impl<Remnant> VerifyingError<Remnant> {
    pub fn into_remnant(self) -> Remnant {
        self.remnant
    }
}

pub trait KeyProvider: Debug + Sync + 'static {
    fn provide_key(&self, name: Option<&str>, key_id: &str) -> Option<&dyn HttpSignature>;
}

#[derive(Debug, Default, Clone)]
pub struct SimpleKeyProvider {
    keys: HashMap<String, Vec<Arc<dyn HttpSignature>>>,
}

impl SimpleKeyProvider {
    pub fn new<I, S, K>(key_iter: I) -> Self
    where
        I: IntoIterator<Item = (S, K)>,
        S: Into<String>,
        K: Into<Arc<dyn HttpSignature>>,
    {
        let mut keys: HashMap<String, Vec<_>> = HashMap::new();
        for (key_id, key) in key_iter.into_iter() {
            keys.entry(key_id.into()).or_default().push(key.into());
        }
        Self { keys }
    }

    pub fn add<K: Into<Arc<dyn HttpSignature>>>(&mut self, key_id: &str, key: K) {
        self.keys.entry(key_id.into()).or_default().push(key.into());
    }
    pub fn clear(&mut self) {
        self.keys.clear();
    }
    pub fn remove_all(&mut self, key_id: &str) {
        self.keys.remove(key_id);
    }
}

impl KeyProvider for SimpleKeyProvider {
    fn provide_key(&self, name: Option<&str>, key_id: &str) -> Option<&dyn HttpSignature> {
        for key in self.keys.get(key_id)? {
            if let Some(alg_name) = name {
                if key.name().eq_ignore_ascii_case(alg_name) {
                    return Some(&**key);
                }
            } else {
                return Some(&**key);
            }
        }
        None
    }
}

pub trait DigestProvider: Debug + Sync + 'static {
    fn provide_digest(&self, name: &str) -> Option<Box<dyn HttpDigest>>;
}

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

    pub fn key_provider(&self) -> &dyn KeyProvider {
        &*self.key_provider
    }
    pub fn digest_provider(&self) -> &dyn DigestProvider {
        &*self.digest_provider
    }
    fn set_digest_provider<DP: DigestProvider>(&mut self, digest_provider: DP) -> &mut Self {
        self.digest_provider = Arc::new(digest_provider);
        self
    }
    pub fn with_digest<DP: DigestProvider>(mut self, digest_provider: DP) -> Self {
        self.set_digest_provider(digest_provider);
        self
    }
    pub fn require_digest(&self) -> bool {
        self.require_digest
    }
    pub fn set_require_digest(&mut self, require_digest: bool) -> &mut Self {
        self.require_digest = require_digest;
        self
    }
    pub fn with_require_digest(mut self, require_digest: bool) -> Self {
        self.set_require_digest(require_digest);
        self
    }
    pub fn validate_digest(&self) -> bool {
        self.validate_digest
    }
    pub fn set_validate_digest(&mut self, validate_digest: bool) -> &mut Self {
        self.validate_digest = validate_digest;
        self
    }
    pub fn with_validate_digest(mut self, validate_digest: bool) -> Self {
        self.set_validate_digest(validate_digest);
        self
    }
    pub fn validate_date(&self) -> bool {
        self.validate_date
    }
    pub fn set_validate_date(&mut self, validate_date: bool) -> &mut Self {
        self.validate_date = validate_date;
        self
    }
    pub fn with_validate_date(mut self, validate_date: bool) -> Self {
        self.set_validate_date(validate_date);
        self
    }
    pub fn date_leeway(&self) -> Duration {
        self.date_leeway
    }
    pub fn set_date_leeway(&mut self, date_leeway: Duration) -> &mut Self {
        self.date_leeway = date_leeway;
        self
    }
    pub fn with_date_leeway(mut self, date_leeway: Duration) -> Self {
        self.set_date_leeway(date_leeway);
        self
    }
    pub fn required_headers(&self) -> impl IntoIterator<Item = &Header> {
        &self.required_headers
    }
    pub fn set_required_headers(&mut self, required_headers: &[Header]) -> &mut Self {
        self.required_headers = required_headers.iter().cloned().collect();
        self
    }
    pub fn with_required_headers(mut self, required_headers: &[Header]) -> Self {
        self.set_required_headers(required_headers);
        self
    }
}

pub trait ServerRequestLike {
    type Remnant;

    fn header(&self, header: &Header) -> Option<HeaderValue>;
    fn complete_with_digest(self, digest: &dyn HttpDigest) -> (Option<String>, Self::Remnant);
    fn complete(self) -> Self::Remnant;
}

pub trait VerifyingExt {
    type Remnant;

    fn verify(
        self,
        config: &VerifyingConfig,
    ) -> Result<Self::Remnant, VerifyingError<Self::Remnant>>;
}

fn verify_signature_only<T: ServerRequestLike>(
    req: &T,
    config: &VerifyingConfig,
) -> Option<BTreeMap<Header, HeaderValue>> {
    let auth_header = req.header(&AUTHORIZATION.into())?;
    let mut auth_header = auth_header.to_str().ok()?.splitn(2, ' ');

    let auth_scheme = auth_header.next()?;
    let auth_args = auth_header.next()?;

    // Check that we're using signature auth
    if !auth_scheme.eq_ignore_ascii_case("Signature") {
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
        .collect::<Option<BTreeMap<_, _>>>()?;

    let key_id = auth_args.get("keyId")?;
    let provided_signature = auth_args.get("signature")?;
    let algorithm_name = auth_args.get("algorithm").copied();

    // We deviate from the spec here, which says the default should be '(created)'. However, this is only valid
    // for asymmetric signatures, which we don't support.
    let headers: Vec<_> = auth_args
        .get("headers")
        .copied()
        .unwrap_or("date")
        .split(' ')
        .map(str::to_ascii_lowercase)
        .collect();

    // Find the appropriate key
    let algorithm = config.key_provider.provide_key(algorithm_name, key_id)?;

    // Parse header names
    let header_vec = headers
        .iter()
        .map(|header| {
            let header_name = header.parse().ok()?;
            let value = req.header(&header_name)?;
            Some((header_name, value))
        })
        .collect::<Option<Vec<_>>>()?;

    // Build the content block
    let content_vec = header_vec
        .iter()
        .map(|(name, value)| Some(format!("{}: {}", name.as_str(), value.to_str().ok()?)))
        .collect::<Option<Vec<_>>>()?;
    let content = content_vec.join("\n");

    // Sign the content
    let expected_signature = algorithm.http_sign(content.as_bytes());

    // Perform constant time comparison
    if expected_signature
        .as_bytes()
        .ct_eq(provided_signature.as_bytes())
        .into()
    {
        Some(header_vec.into_iter().collect())
    } else {
        None
    }
}

fn verify_except_digest<T: ServerRequestLike>(
    req: &T,
    config: &VerifyingConfig,
) -> Option<BTreeMap<Header, HeaderValue>> {
    let headers = verify_signature_only(req, config)?;

    // Check that all the required headers are set
    for header in &config.required_headers {
        if !headers.contains_key(header) {
            return None;
        }
    }

    // If we are expected to validate the date
    if config.validate_date {
        // If date was part of signature
        if let Some(date_value) = headers.get(&DATE.into()) {
            // First convert to a string
            let date_value = date_value.to_str().ok()?;

            // Then parse into a datetime
            let provided_date = DateTime::<Utc>::from_utc(
                NaiveDateTime::parse_from_str(date_value, DATE_FORMAT).ok()?,
                Utc,
            );

            // Finally, compute the absolute difference between the provided
            // date and now.
            let chrono_delta = provided_date.signed_duration_since(Utc::now());
            let delta = chrono_delta
                .to_std()
                .or_else(|_| (-chrono_delta).to_std())
                .ok()?;

            if delta > config.date_leeway {
                return None;
            }
        }
    }

    Some(headers)
}

impl<T: ServerRequestLike> VerifyingExt for T {
    type Remnant = T::Remnant;

    fn verify(
        self,
        config: &VerifyingConfig,
    ) -> Result<Self::Remnant, VerifyingError<Self::Remnant>> {
        let digest_header: Header = HeaderName::from_static("digest").into();

        // Check everything but the digest first, as that doesn't require consuming
        // the request.
        let headers = if let Some(headers) = verify_except_digest(&self, config) {
            headers
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
                            Ok(remnant)
                        }
                        _ => Err(VerifyingError { remnant }),
                    }
                } else {
                    // No supported digest algorithm.
                    Err(VerifyingError {
                        remnant: self.complete(),
                    })
                }
            } else {
                // We are not expected to validate the digest
                Ok(self.complete())
            }
        } else if config.require_digest {
            // We require a digest for requests with a body, but we didn't get one. Either the request
            // has no body, or we should reject it.
            let (maybe_digest, remnant) = self.complete_with_digest(&DefaultDigestAlgorithm::new());

            // If the request did have a body (because we were able to compute a digest).
            if maybe_digest.is_some() {
                // Then reject the request
                Err(VerifyingError { remnant })
            } else {
                // No body, so request if fine.
                Ok(remnant)
            }
        } else {
            // We do not require a digest, valid or otherwise.
            Ok(self.complete())
        }
    }
}

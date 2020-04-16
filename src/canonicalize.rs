use http::HeaderValue;
use itertools::{Either, Itertools};
use thiserror::Error;

use crate::header::{Header, PseudoHeader};

/// The types of error which may occur whilst computing the canonical "signature string"
/// for a request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CanonicalizeError {
    /// One or more headers required to be part of the signature was not present
    /// on the request, and the `skip_missing` configuration option
    /// was disabled.
    #[error("Missing headers required for signature: {0:?}")]
    MissingHeaders(Vec<Header>),
}

/// Base trait for all request types
pub trait RequestLike {
    /// Returns an existing header on the request. This method *must* reflect changes made
    /// be the `ClientRequestLike::set_header` method, with the possible exception of the
    /// `Authorization` header itself.
    fn header(&self, header: &Header) -> Option<HeaderValue>;

    /// Returns true if this request contains a value for the specified header. If this
    /// returns true, following requests to `header()` for the same name must return a
    /// value.
    fn has_header(&self, header: &Header) -> bool {
        self.header(header).is_some()
    }
}

impl<T: RequestLike> RequestLike for &T {
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        (**self).header(header)
    }
}

/// Configuration for computing the canonical "signature string" of a request.
#[derive(Default)]
pub struct CanonicalizeConfig {
    headers: Option<Vec<Header>>,
    signature_created: Option<HeaderValue>,
    signature_expires: Option<HeaderValue>,
}

impl CanonicalizeConfig {
    /// Creates a new canonicalization configuration using the default values.
    pub fn new() -> Self {
        Self::default()
    }
    /// Set the headers to include in the signature
    pub fn with_headers(mut self, headers: Vec<Header>) -> Self {
        self.headers = Some(headers);
        self
    }
    /// Set the headers to include in the signature
    pub fn set_headers(&mut self, headers: Vec<Header>) -> &mut Self {
        self.headers = Some(headers);
        self
    }
    /// Get the headers to include in the signature
    pub fn headers(&self) -> Option<impl IntoIterator<Item = &Header>> {
        self.headers.as_ref()
    }
    /// Set the "signature created" pseudo-header
    pub fn with_signature_created(mut self, signature_created: HeaderValue) -> Self {
        self.signature_created = Some(signature_created);
        self
    }
    /// Set the "signature created" pseudo-header
    pub fn set_signature_created(&mut self, signature_created: HeaderValue) -> &mut Self {
        self.signature_created = Some(signature_created);
        self
    }
    /// Get the "signature created" pseudo-header
    pub fn signature_created(&self) -> Option<&HeaderValue> {
        self.signature_created.as_ref()
    }
    /// Set the "signature expires" pseudo-header
    pub fn with_signature_expires(mut self, signature_expires: HeaderValue) -> Self {
        self.signature_expires = Some(signature_expires);
        self
    }
    /// Set the "signature expires" pseudo-header
    pub fn set_signature_expires(&mut self, signature_expires: HeaderValue) -> &mut Self {
        self.signature_expires = Some(signature_expires);
        self
    }
    /// Get the "signature expires" pseudo-header
    pub fn signature_expires(&self) -> Option<&HeaderValue> {
        self.signature_expires.as_ref()
    }
}

/// Extension method for computing the canonical "signature string" of a request.
pub trait CanonicalizeExt {
    /// Compute the canonical representation of this request
    fn canonicalize(
        &self,
        config: &CanonicalizeConfig,
    ) -> Result<SignatureString, CanonicalizeError>;
}

const DEFAULT_HEADERS: &[Header] = &[Header::Pseudo(PseudoHeader::Created)];

/// Opaque struct storing a computed signature string.
pub struct SignatureString {
    content: Vec<u8>,
    pub(crate) headers: Vec<(Header, HeaderValue)>,
}

impl SignatureString {
    /// Obtain a view of this signature string as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.content
    }
}

impl From<SignatureString> for Vec<u8> {
    fn from(other: SignatureString) -> Self {
        other.content
    }
}

impl<T: RequestLike> CanonicalizeExt for T {
    fn canonicalize(
        &self,
        config: &CanonicalizeConfig,
    ) -> Result<SignatureString, CanonicalizeError> {
        // Find value of each header
        let (headers, missing_headers): (Vec<_>, Vec<_>) = config
            .headers
            .as_deref()
            .unwrap_or_else(|| DEFAULT_HEADERS)
            .iter()
            .cloned()
            .partition_map(|header| {
                if let Some(header_value) = match header {
                    Header::Pseudo(PseudoHeader::Created) => config.signature_created.clone(),
                    Header::Pseudo(PseudoHeader::Expires) => config.signature_expires.clone(),
                    _ => self.header(&header),
                } {
                    Either::Left((header, header_value))
                } else {
                    Either::Right(header)
                }
            });

        // Check for missing headers
        if !missing_headers.is_empty() {
            return Err(CanonicalizeError::MissingHeaders(missing_headers));
        }

        // Build signature string block
        let mut content = Vec::new();
        for (name, value) in &headers {
            if !content.is_empty() {
                content.push(b'\n');
            }
            content.extend(name.as_str().as_bytes());
            content.extend(b": ");
            content.extend(value.as_bytes());
        }

        Ok(SignatureString { content, headers })
    }
}

use std::cmp::Ordering;
use std::str::FromStr;

use http::header::{HeaderName, InvalidHeaderName};

/// Pseudo-headers are used to incorporate addition information into a HTTP
/// signature for which there is no corresponding HTTP header.
///
/// They are described as "special headers" in the draft specification:
/// https://tools.ietf.org/id/draft-cavage-http-signatures-12.html#canonicalization
#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
#[non_exhaustive]
pub enum PseudoHeader {
    /// The `(request-target)` pseudo-header is constructed by joining the lower-cased
    /// request method (`get`, `post`, etc.) and the request path (`/some/page?foo=1`)
    /// with a single space character.
    ///
    /// For example:
    /// `get /index.html`
    RequestTarget,
}

impl PseudoHeader {
    /// Returns the string representation of the pseudo-header.
    pub fn as_str(&self) -> &str {
        match self {
            PseudoHeader::RequestTarget => "(request-target)",
        }
    }
}

impl FromStr for PseudoHeader {
    type Err = ();
    fn from_str(s: &str) -> Result<PseudoHeader, Self::Err> {
        match s {
            "(request-target)" => Ok(PseudoHeader::RequestTarget),
            _ => Err(()),
        }
    }
}

/// A header which can be incorporated into a HTTP signature.
///
/// Headers can either be normal HTTP headers or special "pseudo-headers"
/// used for including additional information into a signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    /// This header is one of the special "pseudo-headers"
    Pseudo(PseudoHeader),
    /// This header is a normal HTTP heaeder.
    Normal(HeaderName),
}

impl Header {
    /// Returns the string representation of the header, as it will appear
    /// in the HTTP signature.
    pub fn as_str(&self) -> &str {
        match self {
            Header::Pseudo(h) => h.as_str(),
            Header::Normal(h) => h.as_str(),
        }
    }
}

impl FromStr for Header {
    type Err = InvalidHeaderName;
    fn from_str(s: &str) -> Result<Header, Self::Err> {
        PseudoHeader::from_str(s)
            .map(Into::into)
            .or_else(|_| HeaderName::from_str(s).map(Into::into))
    }
}

impl Ord for Header {
    fn cmp(&self, other: &Header) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for Header {
    fn partial_cmp(&self, other: &Header) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<HeaderName> for Header {
    fn from(other: HeaderName) -> Self {
        Header::Normal(other)
    }
}

impl From<PseudoHeader> for Header {
    fn from(other: PseudoHeader) -> Self {
        Header::Pseudo(other)
    }
}

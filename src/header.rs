use std::cmp::Ordering;

use http::header::HeaderName;

#[derive(Debug, Copy, Clone, PartialOrd, Ord, PartialEq, Eq)]
#[non_exhaustive]
pub enum PseudoHeader {
    RequestTarget,
}

impl PseudoHeader {
    pub fn as_str(&self) -> &str {
        match self {
            PseudoHeader::RequestTarget => "(request-target)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Header {
    Pseudo(PseudoHeader),
    Normal(HeaderName),
}

impl Header {
    pub fn as_str(&self) -> &str {
        match self {
            Header::Pseudo(h) => h.as_str(),
            Header::Normal(h) => h.as_str(),
        }
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

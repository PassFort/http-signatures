use std::collections::BTreeSet;
use std::convert::TryInto;
use std::error;
use std::fmt;
use std::marker::PhantomData;

use chrono::Utc;
use http::header::{HeaderName, HeaderValue, AUTHORIZATION, DATE, HOST};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type DefaultSignatureAlgorithm = Hmac<Sha256>;
type DefaultDigestAlgorithm = Sha256;

mod algorithm;
pub use algorithm::*;

mod header;
pub use header::*;

#[cfg(feature = "reqwest")]
mod reqwest_impls;
#[cfg(feature = "reqwest")]
pub use reqwest_impls::*;

#[derive(Debug)]
pub struct HttpSignatureConfig<SigAlg, DigestAlg> {
    algorithm: SigAlg,
    key_id: Option<String>,
    headers: BTreeSet<Header>,
    compute_digest: bool,
    add_date: bool,
    add_host: bool,
    phantom: PhantomData<fn() -> DigestAlg>,
}

impl HttpSignatureConfig<DefaultSignatureAlgorithm, DefaultDigestAlgorithm> {
    // Use the default signature algorithm
    pub fn new_default(key: &[u8]) -> Self {
        Self::new(
            DefaultSignatureAlgorithm::new_varkey(key).expect("HMAC can take key of any size"),
        )
    }
}

impl<SigAlg> HttpSignatureConfig<SigAlg, DefaultDigestAlgorithm> {
    pub fn new(algorithm: SigAlg) -> Self {
        HttpSignatureConfig {
            algorithm,
            key_id: None,
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
            phantom: PhantomData,
        }
    }
}

impl<SigAlg, DigestAlg> HttpSignatureConfig<SigAlg, DigestAlg> {
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_ref().map(AsRef::as_ref)
    }
    pub fn set_key_id(&mut self, key_id: Option<&str>) -> &mut Self {
        self.key_id = key_id.map(Into::into);
        self
    }
    pub fn with_key_id(mut self, key_id: Option<&str>) -> Self {
        self.set_key_id(key_id);
        self
    }
    pub fn with_digest<NewDigestAlg>(self) -> HttpSignatureConfig<SigAlg, NewDigestAlg> {
        HttpSignatureConfig {
            algorithm: self.algorithm,
            key_id: self.key_id,
            headers: self.headers,
            compute_digest: self.compute_digest,
            add_date: self.add_date,
            add_host: self.add_host,
            phantom: PhantomData,
        }
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

pub trait HttpSignatureExt: Sized {
    fn signed<SigAlg, DigestAlg>(
        mut self,
        config: &HttpSignatureConfig<SigAlg, DigestAlg>,
    ) -> Result<Self, Error>
    where
        SigAlg: HttpSignatureAlgorithm,
        DigestAlg: HttpDigestAlgorithm,
    {
        self.sign(config)?;
        Ok(self)
    }

    fn sign<SigAlg, DigestAlg>(
        &mut self,
        config: &HttpSignatureConfig<SigAlg, DigestAlg>,
    ) -> Result<(), Error>
    where
        SigAlg: HttpSignatureAlgorithm,
        DigestAlg: HttpDigestAlgorithm;
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    Unknown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Unknown => f.write_str("Unknown error"),
        }
    }
}

impl error::Error for Error {}

pub trait ClientRequestLike {
    fn host(&self) -> Option<String>;
    fn header(&self, header_name: &Header) -> Option<HeaderValue>;
    fn compute_digest<D: HttpDigestAlgorithm>(&mut self) -> Option<String>;
    fn set_header(&mut self, header: HeaderName, value: HeaderValue);
}

impl<R: ClientRequestLike> HttpSignatureExt for R {
    fn sign<SigAlg, DigestAlg>(
        &mut self,
        config: &HttpSignatureConfig<SigAlg, DigestAlg>,
    ) -> Result<(), Error>
    where
        SigAlg: HttpSignatureAlgorithm,
        DigestAlg: HttpDigestAlgorithm,
    {
        let digest_header = HeaderName::from_static("digest");

        // Add missing date header
        if config.add_date && self.header(&DATE.into()).is_none() {
            let date = Utc::now().format("%a, %d %b %Y %T GMT").to_string();
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
            if let Some(digest_str) = self.compute_digest::<DigestAlg>() {
                let digest = format!("{}={}", DigestAlg::NAME, digest_str);
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
        let signature = config.algorithm.http_sign(content.as_bytes());

        // Construct the authorization header
        let auth_header = if let Some(key_id) = config.key_id.as_ref() {
            format!(
                r#"Signature keyId="{}",algorithm="{}",signature="{}",headers="{}"#,
                key_id,
                SigAlg::NAME,
                signature,
                headers
            )
        } else {
            format!(
                r#"Signature algorithm="{}",signature="{}",headers="{}"#,
                SigAlg::NAME,
                signature,
                headers
            )
        };

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

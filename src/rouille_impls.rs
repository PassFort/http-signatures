use std::convert::TryInto;
use std::fmt::{self, Debug};
use std::io::{self, Cursor, Read};
use std::mem;

use http::header::HeaderValue;

use super::*;

/// In order to verify the signature on a rouille request, the request body must
/// be consumed by the verification process. This type is used to return the request body
/// contents on completion of a successful signature verification.
///
/// The `std::io::Read` trait is implemented for this type.
pub struct RouilleBody<'a>(RouilleBodyInner<'a>);

enum RouilleBodyInner<'a> {
    Digested(Result<Cursor<Vec<u8>>, io::Error>),
    Undigested(rouille::RequestBody<'a>),
}

impl<'a> Debug for RouilleBody<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("RouilleBody { .. }")
    }
}

impl<'a> Read for RouilleBody<'a> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use RouilleBodyInner::*;
        match self {
            RouilleBody(Digested(Ok(x))) => x.read(buf),
            RouilleBody(Digested(Err(e))) => Err(mem::replace(e, io::ErrorKind::Other.into())),
            RouilleBody(Undigested(x)) => x.read(buf),
        }
    }
}

impl RequestLike for rouille::Request {
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        match header {
            Header::Normal(header) => rouille::Request::header(self, header.as_str())
                .and_then(|v| HeaderValue::from_str(v).ok()),
            Header::Pseudo(PseudoHeader::RequestTarget) => {
                let method = self.method().to_ascii_lowercase();
                let path = self.raw_url();
                format!("{} {}", method, path).try_into().ok()
            }
            _ => None,
        }
    }
}
impl<'a> ServerRequestLike for &'a rouille::Request {
    type Remnant = Option<RouilleBody<'a>>;

    fn complete_with_digest(self, digest: &dyn HttpDigest) -> (Option<String>, Self::Remnant) {
        if let Some(mut body) = self.data() {
            let mut result = Vec::new();
            if let Err(e) = body.read_to_end(&mut result) {
                (None, Some(RouilleBody(RouilleBodyInner::Digested(Err(e)))))
            } else {
                let computed_digest = digest.http_digest(&result);
                (
                    Some(computed_digest),
                    Some(RouilleBody(RouilleBodyInner::Digested(Ok(Cursor::new(
                        result,
                    ))))),
                )
            }
        } else {
            (None, None)
        }
    }
    fn complete(self) -> Self::Remnant {
        self.data()
            .map(RouilleBodyInner::Undigested)
            .map(RouilleBody)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{offset::TimeZone, Utc};

    use super::*;

    #[test]
    fn it_works() {
        let key_provider = SimpleKeyProvider::new(vec![(
            "test_key",
            Arc::new(DefaultSignatureAlgorithm::new("abcdefgh".as_bytes()))
                as Arc<dyn HttpSignatureVerify>,
        )]);
        let config = VerifyingConfig::new(key_provider).with_validate_date(false);

        let request = rouille::Request::fake_http(
            "POST",
            "/foo/bar",
            vec![
                ("Host".into(), "test.com".into()),
                ("ContentType".into(), "application/json".into()),
                ("Date".into(), Utc.ymd(2014, 7, 8)
                    .and_hms(9, 10, 11)
                    .format("%a, %d %b %Y %T GMT")
                    .to_string()),
                ("Digest".into(), "SHA-256=2vgEVkfe4d6VW+tSWAziO7BUx7uT/rA9hn1EoxUJi2o=".into()),
                ("Authorization".into(), "Signature keyId=\"test_key\",algorithm=\"hmac-sha256\",signature=\"uH2I9FSuCGUrIEygs7hR29oz0Afkz0bZyHpz6cW/mLQ=\",headers=\"(request-target) date digest host".into()),
            ],
            br#"{ "x": 1, "y": 2}"#[..].into()
        );

        request.verify(&config).unwrap();
    }
}

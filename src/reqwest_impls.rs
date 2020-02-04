use super::*;

impl ClientRequestLike for reqwest::Request {
    fn host(&self) -> Option<String> {
        self.url().host_str().map(Into::into)
    }
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        match header {
            Header::Normal(header_name) => self.headers().get(header_name).cloned(),
            Header::Pseudo(PseudoHeader::RequestTarget) => {
                let method = self.method().as_str().to_ascii_lowercase();
                let path = self.url().path();
                format!("{} {}", method, path).try_into().ok()
            }
        }
    }
    fn compute_digest<D: HttpDigestAlgorithm>(&mut self) -> Option<String> {
        self.body()?.as_bytes().map(D::http_digest)
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}

impl ClientRequestLike for reqwest::blocking::Request {
    fn host(&self) -> Option<String> {
        self.url().host_str().map(Into::into)
    }
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        match header {
            Header::Normal(header_name) => self.headers().get(header_name).cloned(),
            Header::Pseudo(PseudoHeader::RequestTarget) => {
                let method = self.method().as_str().to_ascii_lowercase();
                let path = self.url().path();
                format!("{} {}", method, path).try_into().ok()
            }
        }
    }
    fn compute_digest<D: HttpDigestAlgorithm>(&mut self) -> Option<String> {
        None
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}

#[cfg(test)]
mod tests {
    use chrono::{offset::TimeZone, Utc};
    use http::header::CONTENT_TYPE;

    use super::*;

    #[test]
    fn it_works() {
        let config = HttpSignatureConfig::new_default("abcdefgh".as_bytes());

        let client = reqwest::Client::new();

        let without_sig = client
            .post("http://test.com/foo/bar")
            .header(CONTENT_TYPE, "application/json")
            .header(
                DATE,
                Utc.ymd(2014, 7, 8)
                    .and_hms(9, 10, 11)
                    .format("%a, %d %b %Y %T GMT")
                    .to_string(),
            )
            .body(&br#"{ "x": 1, "y": 2}"#[..])
            .build()
            .unwrap();

        let with_sig = without_sig.signed(&config).unwrap();

        assert_eq!(with_sig.headers().get(AUTHORIZATION).unwrap(), "Signature algorithm=\"hmac-sha256\",signature=\"uH2I9FSuCGUrIEygs7hR29oz0Afkz0bZyHpz6cW/mLQ=\",headers=\"(request-target) date digest host");
        assert_eq!(
            with_sig
                .headers()
                .get(HeaderName::from_static("digest"))
                .unwrap(),
            "SHA-256=2vgEVkfe4d6VW+tSWAziO7BUx7uT/rA9hn1EoxUJi2o="
        );
    }

    #[test]
    #[ignore]
    fn it_can_talk_to_reference_integration() {
        let config = HttpSignatureConfig::new_default(&base64::decode("dummykey").unwrap())
            .with_key_id(Some("dummykey"));

        let client = reqwest::blocking::Client::new();

        let req = client
            .get("http://localhost:8080/config")
            .build()
            .unwrap()
            .signed(&config)
            .unwrap();

        let result = client.execute(req).unwrap();
        println!("{:?}", result.text().unwrap());
        assert!(false);
    }
}

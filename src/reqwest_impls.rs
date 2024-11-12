use std::convert::TryInto;

use http::header::{HeaderName, HeaderValue};

use super::*;

/// Returns the correct `Host` header value for a given URL, in the form `<host>:<port>`.
fn host_from_url(url: &url::Url) -> Option<String> {
    url.host_str().map(|host| match url.port() {
        Some(port) => format!("{}:{}", host, port),
        None => host.into(),
    })
}

impl RequestLike for reqwest::Request {
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        match header {
            Header::Normal(header_name) => self.headers().get(header_name).cloned(),
            Header::Pseudo(PseudoHeader::RequestTarget) => {
                let method = self.method().as_str().to_ascii_lowercase();
                let path = self.url().path();
                format!("{} {}", method, path).try_into().ok()
            }
            _ => None,
        }
    }
}

impl ClientRequestLike for reqwest::Request {
    fn host(&self) -> Option<String> {
        host_from_url(self.url())
    }
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String> {
        self.body()?.as_bytes().map(|b| digest.http_digest(b))
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}

impl RequestLike for reqwest::blocking::Request {
    fn header(&self, header: &Header) -> Option<HeaderValue> {
        match header {
            Header::Normal(header_name) => self.headers().get(header_name).cloned(),
            Header::Pseudo(PseudoHeader::RequestTarget) => {
                let method = self.method().as_str().to_ascii_lowercase();
                let path = self.url().path();
                if let Some(query) = self.url().query() {
                    format!("{} {}?{}", method, path, query)
                } else {
                    format!("{} {}", method, path)
                }
                .try_into()
                .ok()
            }
            _ => None,
        }
    }
}

impl ClientRequestLike for reqwest::blocking::Request {
    fn host(&self) -> Option<String> {
        host_from_url(self.url())
    }
    fn compute_digest(&mut self, digest: &dyn HttpDigest) -> Option<String> {
        let bytes_to_digest = self.body_mut().as_mut()?.buffer().ok()?;
        Some(digest.http_digest(bytes_to_digest))
    }
    fn set_header(&mut self, header: HeaderName, value: HeaderValue) {
        self.headers_mut().insert(header, value);
    }
}

#[cfg(test)]
mod tests {
    use chrono::{offset::TimeZone, Utc};
    use http::header::{AUTHORIZATION, CONTENT_TYPE, DATE, HOST};

    use super::*;

    #[test]
    fn it_works() {
        let config = SigningConfig::new_default("test_key", "abcdefgh".as_bytes());

        let client = reqwest::Client::new();

        let without_sig = client
            .post("http://test.com/foo/bar")
            .header(CONTENT_TYPE, "application/json")
            .header(
                DATE,
                Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11)
                    .single()
                    .expect("valid date")
                    .format("%a, %d %b %Y %T GMT")
                    .to_string(),
            )
            .body(&br#"{ "x": 1, "y": 2}"#[..])
            .build()
            .unwrap();

        let with_sig = without_sig.signed(&config).unwrap();

        assert_eq!(with_sig.headers().get(AUTHORIZATION).unwrap(), "Signature keyId=\"test_key\",algorithm=\"hs2019\",signature=\"F8gZiriO7dtKFiP5eSZ+Oh1h61JIrAR6D5Mdh98DjqA=\",headers=\"(request-target) host date digest\"");
        assert_eq!(
            with_sig
                .headers()
                .get(HeaderName::from_static("digest"))
                .unwrap(),
            "SHA-256=2vgEVkfe4d6VW+tSWAziO7BUx7uT/rA9hn1EoxUJi2o="
        );
        assert_eq!(with_sig.headers().get(HOST).unwrap(), "test.com");
    }

    #[test]
    fn it_works_blocking() {
        let config = SigningConfig::new_default("test_key", "abcdefgh".as_bytes());

        let client = reqwest::blocking::Client::new();

        let without_sig = client
            .post("http://test.com/foo/bar")
            .header(CONTENT_TYPE, "application/json")
            .header(
                DATE,
                Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11)
                    .single()
                    .expect("valid date")
                    .format("%a, %d %b %Y %T GMT")
                    .to_string(),
            )
            .body(&br#"{ "x": 1, "y": 2}"#[..])
            .build()
            .unwrap();

        let with_sig = without_sig.signed(&config).unwrap();

        assert_eq!(with_sig.headers().get(AUTHORIZATION).unwrap(), "Signature keyId=\"test_key\",algorithm=\"hs2019\",signature=\"F8gZiriO7dtKFiP5eSZ+Oh1h61JIrAR6D5Mdh98DjqA=\",headers=\"(request-target) host date digest\"");
        assert_eq!(
            with_sig
                .headers()
                .get(HeaderName::from_static("digest"))
                .unwrap(),
            "SHA-256=2vgEVkfe4d6VW+tSWAziO7BUx7uT/rA9hn1EoxUJi2o="
        );
        assert_eq!(with_sig.headers().get(HOST).unwrap(), "test.com");
    }

    #[test]
    fn sets_host_header_with_port_correctly() {
        let config = SigningConfig::new_default("test_key", "abcdefgh".as_bytes());
        let client = reqwest::Client::new();

        let without_sig = client
            .post("http://localhost:8080/foo/bar")
            .header(CONTENT_TYPE, "application/json")
            .header(
                DATE,
                Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11)
                    .single()
                    .expect("valid date")
                    .format("%a, %d %b %Y %T GMT")
                    .to_string(),
            )
            .body(&br#"{ "x": 1, "y": 2}"#[..])
            .build()
            .unwrap();

        let with_sig = without_sig.signed(&config).unwrap();
        assert_eq!(with_sig.headers().get(HOST).unwrap(), "localhost:8080");
    }

    #[test]
    fn sets_host_header_with_port_correctly_blocking() {
        let config = SigningConfig::new_default("test_key", "abcdefgh".as_bytes());
        let client = reqwest::blocking::Client::new();

        let without_sig = client
            .post("http://localhost:8080/foo/bar")
            .header(CONTENT_TYPE, "application/json")
            .header(
                DATE,
                Utc.with_ymd_and_hms(2014, 7, 8, 9, 10, 11)
                    .single()
                    .expect("valid date")
                    .format("%a, %d %b %Y %T GMT")
                    .to_string(),
            )
            .body(&br#"{ "x": 1, "y": 2}"#[..])
            .build()
            .unwrap();

        let with_sig = without_sig.signed(&config).unwrap();
        assert_eq!(with_sig.headers().get(HOST).unwrap(), "localhost:8080");
    }
    #[test]
    #[ignore]
    fn it_can_talk_to_reference_integration() {
        let config = SigningConfig::new_default("dummykey", &base64::decode("dummykey").unwrap());

        let client = reqwest::blocking::Client::new();

        let req = client
            .get("http://localhost:8080/config")
            .build()
            .unwrap()
            .signed(&config)
            .unwrap();

        let result = client.execute(req).unwrap();
        println!("{:?}", result.text().unwrap());
    }
}

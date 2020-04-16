use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use http_sig::mock_request::MockRequest;
use http_sig::{
    CanonicalizeConfig, CanonicalizeExt, Header, RsaSha256Sign, RsaSha256Verify, SigningConfig,
    SigningExt, SimpleKeyProvider, VerifyingConfig, VerifyingExt,
};
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
enum Mode {
    Canonicalize,
    Sign,
    Verify,
}

#[derive(Debug, StructOpt)]
#[structopt(about = "A validator for use with the HTTP-signatures test suite.")]
struct Opt {
    /// A list of header names, optionally quoted
    #[structopt(subcommand)]
    mode: Mode,

    /// A list of header names, optionally quoted
    #[allow(clippy::option_option)]
    #[structopt(short = "d", long, global = true, min_values = 0)]
    headers: Option<Option<String>>,

    /// A Key Id string.
    #[structopt(short, long = "keyId", global = true)]
    key_id: Option<String>,

    /// A private key file name filename.
    #[structopt(short, long, parse(from_os_str), global = true)]
    private_key: Option<PathBuf>,

    /// The type of the keys.
    #[structopt(short = "t", long, global = true)]
    key_type: Option<String>,

    /// A public key file name filename.
    #[structopt(short = "u", long, parse(from_os_str), global = true)]
    public_key: Option<PathBuf>,

    /// One of: rsa-sha1, hmac-sha1, rsa-sha256, hmac-sha256, hs2019.
    #[structopt(short, long, global = true)]
    algorithm: Option<String>,

    /// The created param for the signature.
    #[structopt(short, long, global = true)]
    created: Option<i64>,

    /// The expires param for the signature.
    #[structopt(short, long, global = true)]
    expires: Option<i64>,
}

impl Opt {
    fn parse_headers(&self) -> Result<Option<Vec<Header>>, Box<dyn Error>> {
        Ok(if let Some(headers) = &self.headers {
            Some(if let Some(headers) = headers {
                let headers: Vec<Header> = headers
                    .split_ascii_whitespace()
                    .map(|s| s.parse::<Header>().with_context(|| format!("{:?}", s)))
                    .collect::<Result<_, _>>()?;
                headers
            } else {
                Vec::new()
            })
        } else {
            None
        })
    }
    fn canonicalize_config(&self) -> Result<CanonicalizeConfig, Box<dyn Error>> {
        let mut config = CanonicalizeConfig::default();
        if let Some(created) = self.created {
            config.set_signature_created(created.into());
        }
        if let Some(expires) = self.expires {
            config.set_signature_expires(expires.into());
        }
        if let Some(headers) = self.parse_headers()? {
            config.set_headers(headers);
        }

        Ok(config)
    }
    fn signing_config(&self) -> Result<SigningConfig, Box<dyn Error>> {
        let key_id = self.key_id.clone().unwrap_or_default();
        let key_data = if let Some(key) = self.private_key.as_ref() {
            Some(fs::read(key)?)
        } else {
            None
        };

        match self.algorithm.as_deref() {
            Some("rsa-sha256") | Some("hs2019") | None => {}
            Some(other) => return Err(anyhow!("Unknown algorithm: {}", other).into()),
        }

        let mut config = match (self.key_type.as_deref(), key_data) {
            (Some("rsa"), Some(pkey)) | (Some("RSA"), Some(pkey)) => {
                SigningConfig::new(&key_id, RsaSha256Sign::new_pem(&pkey)?)
            }
            (Some(_), None) => return Err(anyhow!("No key provided").into()),
            (Some(other), Some(_)) => return Err(anyhow!("Unknown key type: {}", other).into()),
            (None, _) => SigningConfig::new_default(&key_id, b""),
        };

        if let Some(headers) = self.parse_headers()? {
            config.set_headers(&headers);
        }

        if let Some(created) = self.created {
            config.set_signature_created_at(created);
        }

        if let Some(expires) = self.expires {
            config.set_signature_expires_at(expires);
        }

        // Disable various convenience options that would mess up the test suite
        config.set_add_date(false);
        config.set_compute_digest(false);
        config.set_add_host(false);
        config.set_skip_missing(false);

        Ok(config)
    }
    fn verification_config(&self) -> Result<VerifyingConfig, Box<dyn Error>> {
        let key_id = self.key_id.clone().unwrap_or_default();
        let key_data = if let Some(key) = self.public_key.as_ref() {
            Some(fs::read(key)?)
        } else {
            None
        };

        let mut key_provider = SimpleKeyProvider::default();

        match self.algorithm.as_deref() {
            Some("hs2019") | None => {}
            Some(other) => return Err(anyhow!("Unknown algorithm: {}", other).into()),
        }

        match (self.key_type.as_deref(), key_data) {
            (Some("rsa"), Some(pkey)) | (Some("RSA"), Some(pkey)) => {
                key_provider.add(&key_id, Arc::new(RsaSha256Verify::new_pem(&pkey)?));
            }
            (Some(_), None) => return Err(anyhow!("No key provided").into()),
            (Some(other), Some(_)) => return Err(anyhow!("Unknown key type: {}", other).into()),
            (None, _) => {}
        }

        let mut config = VerifyingConfig::new(key_provider);

        // Disable various convenience options that would mess up the test suite
        config.set_require_digest(false);
        config.set_validate_date(false);
        config.set_required_headers(&[]);

        Ok(config)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let opt = Opt::from_args();

    let mut req = MockRequest::from_reader(&mut io::stdin().lock())?;

    log::info!("{:?}", req);

    match opt.mode {
        Mode::Canonicalize => {
            let res = req.canonicalize(&opt.canonicalize_config()?)?;
            io::stdout().lock().write_all(res.as_bytes())?;
        }
        Mode::Sign => {
            req.sign(&opt.signing_config()?)?;
            req.write(&mut io::stdout().lock())?;
        }
        Mode::Verify => {
            req.verify(&opt.verification_config()?)?;
        }
    }

    Ok(())
}

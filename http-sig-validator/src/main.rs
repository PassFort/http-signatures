use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use http_sig::mock_request::MockRequest;
use http_sig::{
    Header, RsaSha256Sign, RsaSha256Verify, SigningConfig, SigningExt, SimpleKeyProvider,
    VerifyingConfig, VerifyingExt,
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
    #[structopt(short = "d", long, global = true)]
    headers: Option<String>,

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
    fn signing_config(&self) -> Result<SigningConfig, Box<dyn Error>> {
        let key_id = self.key_id.clone().unwrap_or_default();
        let key_data = if let Some(key) = self.private_key.as_ref() {
            Some(fs::read(key)?)
        } else {
            None
        };

        #[allow(clippy::single_match)]
        let mut config = match (self.algorithm.as_deref(), key_data) {
            (Some("rsa-sha256"), Some(pkey)) => {
                SigningConfig::new(&key_id, RsaSha256Sign::new_pem(&pkey)?)
            }
            _ => SigningConfig::new_default(&key_id, b""),
        };

        if let Some(headers) = &self.headers {
            let headers: Vec<Header> = headers
                .split_ascii_whitespace()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()?;
            config.set_headers(&headers);
        }

        // Disable various convenience options that would mess up the test suite
        config.set_add_date(false);
        config.set_compute_digest(false);
        config.set_add_host(false);

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

        #[allow(clippy::single_match)]
        match (self.algorithm.as_deref(), key_data) {
            (Some("rsa-sha256"), Some(pkey)) => {
                key_provider.add(&key_id, Arc::new(RsaSha256Verify::new_pem(&pkey)?));
            }
            _ => {}
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

    match opt.mode {
        Mode::Canonicalize => {
            let res = req.canonicalize(&opt.signing_config()?)?;
            print!("{}", res);
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

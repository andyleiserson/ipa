use clap::Args;
use rand::{thread_rng, CryptoRng, Rng};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, ExtendedKeyUsagePurpose,
    IsCa, KeyUsagePurpose, SanType, PKCS_ECDSA_P256_SHA256,
};
use x25519_dalek::StaticSecret;
use std::{
    error::Error,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
};
use time::{Duration, OffsetDateTime};

#[derive(Debug, Args)]
#[clap(
    name = "keygen",
    about = "Generate keys used by an MPC helper",
    next_help_heading = "Key Generation Options"
)]
pub struct KeygenArgs {
    /// DNS name to use for the TLS certificate
    #[arg(short, long)]
    pub(crate) name: String,

    /// Writes the generated TLS certificate to the file
    #[arg(long, visible_alias("cert"), visible_alias("tls-certificate"))]
    pub(crate) tls_cert: PathBuf,

    /// Writes the generated TLS private key to the file
    #[arg(long, visible_alias("key"))]
    pub(crate) tls_key: PathBuf,

    /// Writes the generated report private key to the file
    #[arg(long)]
    pub(crate) report_key: PathBuf,
}

fn create_new<P: AsRef<Path>>(path: P) -> io::Result<File> {
    File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

fn keygen_tls<R: Rng + CryptoRng>(args: &KeygenArgs, rng: &mut R) -> Result<(), Box<dyn Error>> {
    let mut params = CertificateParams::default();
    params.alg = &PKCS_ECDSA_P256_SHA256;

    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
        KeyUsagePurpose::KeyCertSign,
    ];
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
    params.not_after = params.not_before + Duration::days(91);
    params.serial_number = Some(rng.gen_range(0..=i64::MAX.try_into().unwrap()));

    let mut name = DistinguishedName::new();
    name.push(rcgen::DnType::CommonName, args.name.clone());
    params.distinguished_name = name;

    params.subject_alt_names = vec![SanType::DnsName(args.name.clone())];

    let gen = Certificate::from_params(params)?;

    create_new(&args.tls_cert)?.write_all(gen.serialize_pem().unwrap().as_bytes())?;
    create_new(&args.tls_key)?.write_all(gen.serialize_private_key_pem().as_bytes())?;

    Ok(())
}

fn keygen_report<R: Rng + CryptoRng>(args: &KeygenArgs, rng: &mut R) -> Result<(), Box<dyn Error>> {
    let report_key = StaticSecret::new(rng);
    create_new(&args.report_key)
        .unwrap()
        .write_all(&report_key.to_bytes())
        .unwrap();

    Ok(())
}

/// Generate keys necessary for running a helper service.
///
/// # Errors
/// If a problem is encountered during key generation.
///
/// # Panics
/// If something that shouldn't happen goes wrong during key generation.
pub fn keygen(args: KeygenArgs) -> Result<(), Box<dyn Error>> {
    let mut rng = thread_rng();
    keygen_tls(&args, &mut rng)?;
    keygen_report(&args, &mut rng)?;
    Ok(())
}

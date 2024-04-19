use crate::{
    get_content, get_reader, process_text_decrypt, process_text_encrypt, process_text_key_generate,
    process_text_sign, process_text_verify, CmdExector,
};

use super::{verify_file, verify_path};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use enum_dispatch::enum_dispatch;
use std::{fmt, path::PathBuf, str::FromStr};
use tokio::fs;

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum TextSubCommand {
    #[command(about = "Sign a text with a private/session key and return a signature")]
    Sign(TextSignOpts),
    #[command(about = "Verify a signature with a public/session key")]
    Verify(TextVerifyOpts),
    #[command(about = "Generate a random blake3 key or ed25519 key pair")]
    Generate(KeyGenerateOpts),
    #[command(about = "Encrypt a text with a key and return the ciphertext")]
    Encrypt(TextEncryptOpts),
    #[command(about = "Decrypt a text with a key and return the plaintext")]
    Decrypt(TextDecryptOpts),
}

#[derive(Debug, Parser)]
pub struct TextSignOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long, default_value = "blake3", value_parser = parse_text_sign_format)]
    pub format: Algorithm,
}

#[derive(Debug, Parser)]
pub struct TextVerifyOpts {
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    #[arg(short, long, value_parser = verify_file)]
    pub key: String,
    #[arg(long)]
    pub sig: String,
    #[arg(long, default_value = "blake3", value_parser = parse_text_sign_format)]
    pub format: Algorithm,
}

#[derive(Debug, Parser)]
pub struct KeyGenerateOpts {
    #[arg(long, default_value = "blake3", value_parser = parse_text_sign_format)]
    pub format: Algorithm,
    #[arg(short, long, value_parser = verify_path)]
    pub output_path: PathBuf,
}

#[derive(Debug, Parser)]
pub struct TextEncryptOpts {
    /// The plaintext to encrypt.
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    /// The key to encrypt with.
    #[arg(short, long)]
    pub key: String,
}

#[derive(Debug, Parser)]
pub struct TextDecryptOpts {
    /// The ciphertext to decrypt.
    #[arg(short, long, value_parser = verify_file, default_value = "-")]
    pub input: String,
    /// The key to decrypt with.
    #[arg(short, long)]
    pub key: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Algorithm {
    Blake3,
    Ed25519,
    ChaCha20Poly1305,
}

fn parse_text_sign_format(format: &str) -> Result<Algorithm, anyhow::Error> {
    format.parse()
}

impl FromStr for Algorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "blake3" => Ok(Algorithm::Blake3),
            "ed25519" => Ok(Algorithm::Ed25519),
            "chacha20poly1305" => Ok(Algorithm::ChaCha20Poly1305),
            _ => Err(anyhow::anyhow!("Invalid format")),
        }
    }
}

impl From<Algorithm> for &'static str {
    fn from(format: Algorithm) -> Self {
        match format {
            Algorithm::Blake3 => "blake3",
            Algorithm::Ed25519 => "ed25519",
            Algorithm::ChaCha20Poly1305 => "chacha20poly1305",
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Into::<&str>::into(*self))
    }
}

impl CmdExector for TextSignOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = get_content(&self.key)?;
        let sig = process_text_sign(&mut reader, &key, self.format)?;
        // base64 output
        let encoded = URL_SAFE_NO_PAD.encode(sig);
        println!("{}", encoded);
        Ok(())
    }
}

impl CmdExector for TextVerifyOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let mut reader = get_reader(&self.input)?;
        let key = get_content(&self.key)?;
        let decoded = URL_SAFE_NO_PAD.decode(&self.sig)?;
        let verified = process_text_verify(&mut reader, &key, &decoded, self.format)?;
        if verified {
            println!("✓ Signature verified");
        } else {
            println!("⚠ Signature not verified");
        }
        Ok(())
    }
}

impl CmdExector for KeyGenerateOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let key = process_text_key_generate(self.format)?;
        for (k, v) in key {
            fs::write(self.output_path.join(k), v).await?;
        }
        Ok(())
    }
}

impl CmdExector for TextEncryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let TextEncryptOpts { input, key } = self;
        let mut reader = get_reader(&input)?;
        let key = get_content(&key)?;
        let encrypted = process_text_encrypt(&mut reader, key.as_slice())?;
        println!("{encrypted}");
        Ok(())
    }
}

impl CmdExector for TextDecryptOpts {
    async fn execute(self) -> anyhow::Result<()> {
        let TextDecryptOpts { input, key } = self;
        let mut reader = get_reader(&input)?;
        let key = get_content(&key)?;
        let decrypted = process_text_decrypt(&mut reader, key.as_slice())?;
        println!("{decrypted}");
        Ok(())
    }
}

use crate::{process_genpass, Algorithm};
use anyhow::Result;
use base64::Engine;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{aead::generic_array::GenericArray, AeadCore, ChaCha20Poly1305, KeyInit};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use std::{collections::HashMap, io::Read};

pub trait TextSigner {
    // signer could sign any input data
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>>;
}

pub trait TextVerifier {
    // verifier could verify any input data
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool>;
}

/// A trait for encrypting and decrypting text data.
///
/// This trait provides an abstraction over different encryption algorithms
/// for securing text data. It is suitable for scenarios where text data needs
/// to be securely transmitted or stored.
pub trait TextEncryptor {
    /// Encrypts the data read from the provided reader.
    ///
    /// This method takes a mutable reference to an object that implements `Read` to
    /// read the plaintext data. It returns a `Result` containing a tuple of `Vec<u8>` and
    /// an `Option<Vec<u8>>`. The first element of the tuple is the ciphertext, while the
    /// second element is an optional nonce generated during the encryption process.
    ///
    /// # Parameters
    /// - `reader`: a mutable reference to any type that implements `Read` from which
    ///   plaintext data will be read.
    ///
    /// # Returns
    /// A `Result` that, on success, contains a tuple where the first element is the encrypted
    /// data as a vector of bytes (`Vec<u8>`) and the second element is an optional vector of bytes
    /// representing the nonce (`Option<Vec<u8>>`), if any was generated during encryption.
    ///
    /// # Errors
    /// Returns an error if the encryption fails due to reasons such as invalid key, corrupted data,
    /// etc.
    fn encrypt(&self, reader: impl Read) -> Result<(Vec<u8>, Option<Vec<u8>>)>;

    /// Decrypts the data read from the provided reader using the specified nonce.
    ///
    /// This method takes a mutable reference to an object that implements `Read` to
    /// read the encrypted data, along with a nonce that was possibly used during the
    /// encryption. The nonce is provided via an `impl Into<Option<Vec<u8>>>`, allowing
    /// flexible input types. The function returns a `Result` containing the decrypted
    /// data as `Vec<u8>`.
    ///
    /// # Parameters
    /// - `reader`: a mutable reference to any type that implements `Read`, from which
    ///   encrypted data will be read.
    /// - `nonce`: an implementation of `Into<Option<Vec<u8>>>` providing the nonce that
    ///   was used in the encryption process. This can be passed as `Some(vec_of_nonce_bytes)`
    ///   if a nonce was used, or `None` if no nonce is applicable.
    ///
    /// # Returns
    /// A `Result<Vec<u8>>`, where a successful result contains the decrypted data as
    /// a vector of bytes (`Vec<u8>`).
    ///
    /// # Errors
    /// Returns an error if the decryption fails due to reasons such as invalid nonce,
    /// corrupted data, incorrect decryption key, or others.
    fn decrypt(&self, reader: impl Read, nonce: impl Into<Option<Vec<u8>>>) -> Result<Vec<u8>>;
}

pub struct Blake3 {
    key: [u8; 32],
}

pub struct Ed25519Signer {
    key: SigningKey,
}

pub struct Ed25519Verifier {
    key: VerifyingKey,
}

pub struct Chacha20Poly1305Encryptor {
    key: chacha20poly1305::Key,
}

impl TextSigner for Blake3 {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes().to_vec())
    }
}

impl TextVerifier for Blake3 {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ret = blake3::keyed_hash(&self.key, &buf);
        Ok(ret.as_bytes() == sig)
    }
}

impl TextSigner for Ed25519Signer {
    fn sign(&self, reader: &mut dyn Read) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let signature = self.key.sign(&buf);
        Ok(signature.to_bytes().to_vec())
    }
}

impl TextVerifier for Ed25519Verifier {
    fn verify(&self, reader: &mut dyn Read, sig: &[u8]) -> Result<bool> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let sig = (&sig[..64]).try_into()?;
        let signature = Signature::from_bytes(sig);
        Ok(self.key.verify(&buf, &signature).is_ok())
    }
}

impl Blake3 {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        // convert &[u8] to &[u8; 32]
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("blake3.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl Ed25519Signer {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key = SigningKey::from_bytes(key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let mut csprng = OsRng;
        let sk: SigningKey = SigningKey::generate(&mut csprng);
        let pk: VerifyingKey = (&sk).into();
        let mut map = HashMap::new();
        map.insert("ed25519.sk", sk.to_bytes().to_vec());
        map.insert("ed25519.pk", pk.to_bytes().to_vec());

        Ok(map)
    }
}

impl Ed25519Verifier {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        let key = VerifyingKey::from_bytes(key)?;
        Ok(Self { key })
    }
}

impl Chacha20Poly1305Encryptor {
    pub fn try_new(key: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let key = (&key[..32]).try_into()?;
        Ok(Self::new(key))
    }

    pub fn new(key: &[u8; 32]) -> Self {
        let key: GenericArray<u8, _> = chacha20poly1305::Key::from(*key);
        Self { key }
    }

    fn generate() -> Result<HashMap<&'static str, Vec<u8>>> {
        let key = process_genpass(32, true, true, true, true)?;
        let mut map = HashMap::new();
        map.insert("chacha20poly1305.txt", key.as_bytes().to_vec());
        Ok(map)
    }
}

impl TextEncryptor for Chacha20Poly1305Encryptor {
    fn encrypt(&self, mut reader: impl Read) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let ccp = ChaCha20Poly1305::new(&self.key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = ccp.encrypt(&nonce, buf.as_slice())?;
        let nonce = <[u8; 12]>::from(nonce);
        Ok((cipher, Some(nonce.to_vec())))
    }

    fn decrypt(&self, mut reader: impl Read, nonce: impl Into<Option<Vec<u8>>>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf)?;
        let Some(nonce) = nonce.into() else {
            anyhow::bail!("Nonce is needed to decrypt using chacha20poly1305 algorithm.");
        };

        let ccp = ChaCha20Poly1305::new(&self.key);
        let nonce = chacha20poly1305::Nonce::from_slice(&nonce[..12]);
        let plain = ccp.decrypt(nonce, buf.as_slice())?;
        Ok(plain)
    }
}

pub fn process_text_sign(
    reader: &mut dyn Read,
    key: &[u8], // (ptr, length)
    format: Algorithm,
) -> Result<Vec<u8>> {
    let signer: Box<dyn TextSigner> = match format {
        Algorithm::Blake3 => Box::new(Blake3::try_new(key)?),
        Algorithm::Ed25519 => Box::new(Ed25519Signer::try_new(key)?),
        f => anyhow::bail!("Unsupported sign format: {f}"),
    };

    signer.sign(reader)
}

pub fn process_text_verify(
    reader: &mut dyn Read,
    key: &[u8],
    sig: &[u8],
    format: Algorithm,
) -> Result<bool> {
    let verifier: Box<dyn TextVerifier> = match format {
        Algorithm::Blake3 => Box::new(Blake3::try_new(key)?),
        Algorithm::Ed25519 => Box::new(Ed25519Verifier::try_new(key)?),
        f => anyhow::bail!("Unsupported sign format: {f}"),
    };
    verifier.verify(reader, sig)
}

pub fn process_text_key_generate(format: Algorithm) -> Result<HashMap<&'static str, Vec<u8>>> {
    match format {
        Algorithm::Blake3 => Blake3::generate(),
        Algorithm::Ed25519 => Ed25519Signer::generate(),
        Algorithm::ChaCha20Poly1305 => Chacha20Poly1305Encryptor::generate(),
    }
}

pub fn process_text_encrypt(reader: &mut dyn Read, key: &[u8]) -> Result<String> {
    let vec = process_binary_encrypt(reader, key)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(vec))
}

pub fn process_text_decrypt(reader: &mut dyn Read, key: &[u8]) -> Result<String> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(buf)?;
    let decrypted = process_binary_decrypt(&mut decoded.as_slice(), key)?;
    Ok(String::from_utf8(decrypted)?)
}

pub fn process_binary_encrypt(reader: &mut dyn Read, key: &[u8]) -> Result<Vec<u8>> {
    let encryptor = Chacha20Poly1305Encryptor::try_new(key)?;
    let (mut cipher_text, nonce) = encryptor.encrypt(reader)?;
    if let Some(mut nonce) = nonce {
        nonce.append(&mut cipher_text);
        cipher_text = nonce;
    }
    Ok(cipher_text)
}

pub fn process_binary_decrypt(reader: &mut dyn Read, key: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    reader.read_exact(&mut nonce)?;
    let encryptor = Chacha20Poly1305Encryptor::try_new(key)?;
    let plain = encryptor.decrypt(reader, nonce.to_vec())?;
    Ok(plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

    const KEY: &[u8] = include_bytes!("../../fixtures/blake3.txt");

    #[test]
    fn test_process_text_sign() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let mut reader1 = "hello".as_bytes();
        let format = Algorithm::Blake3;
        let sig = process_text_sign(&mut reader, KEY, format)?;
        let ret = process_text_verify(&mut reader1, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_text_verify() -> Result<()> {
        let mut reader = "hello".as_bytes();
        let format = Algorithm::Blake3;
        let sig = "33Ypo4rveYpWmJKAiGnnse-wHQhMVujjmcVkV4Tl43k";
        let sig = URL_SAFE_NO_PAD.decode(sig)?;
        let ret = process_text_verify(&mut reader, KEY, &sig, format)?;
        assert!(ret);
        Ok(())
    }

    #[test]
    fn test_process_encrypt_and_decrypt() -> Result<()> {
        let key = process_genpass(32, true, true, true, true)?;
        let encrypted = process_text_encrypt(&mut "hello, world".as_bytes(), key.as_bytes())?;
        println!("encrypted: {}", encrypted);
        let decrypted = process_text_decrypt(&mut encrypted.as_bytes(), key.as_bytes())?;
        println!("decrypted: {}", decrypted);
        Ok(())
    }
}

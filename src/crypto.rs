//! Command framing and encryption for the legacy IDrive protocol.
//! These legacy algorithms are required by the existing service protocol.

use crate::{Error, Result};
use aes::{
    Aes256,
    cipher::{BlockDecrypt, BlockEncrypt, KeyInit, generic_array::GenericArray},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use md4::Md4;
use md5::{Digest, Md5};
use zeroize::Zeroizing;

pub const MARKER: &str = "eb6ab2a3";
pub const MAX_COMMAND_BYTES: usize = 8192;

pub struct CommandCipher(Aes256);

impl CommandCipher {
    pub fn greeting() -> Self {
        Self::derive(b"740428cc4e4f430", b"740428cc4e4f430")
    }

    /// MD5-derived salt followed by OpenSSL EVP_BytesToKey's two-round MD5 KDF.
    pub fn derive(keyword: &[u8], challenge: &[u8]) -> Self {
        let salt_hash = Zeroizing::new(Md5::digest(keyword).to_vec());
        let salt = &salt_hash[..8];
        let mut material = Zeroizing::new(Vec::with_capacity(32));
        let mut previous = Zeroizing::new(Vec::<u8>::new());
        while material.len() < 32 {
            let mut h = Md5::new();
            h.update(&*previous);
            h.update(challenge);
            h.update(salt);
            let first = Zeroizing::new(h.finalize().to_vec());
            previous = Zeroizing::new(Md5::digest(&*first).to_vec());
            material.extend_from_slice(&previous);
        }
        Self(Aes256::new(GenericArray::from_slice(&material[..32])))
    }

    pub fn encrypt_bytes(&self, data: &[u8]) -> Vec<u8> {
        let mut out = vec![0; data.len().div_ceil(16) * 16];
        out[..data.len()].copy_from_slice(data);
        self.crypt_blocks(&mut out, false);
        out
    }

    pub fn decrypt_bytes(&self, data: &[u8]) -> Result<Vec<u8>> {
        if !data.len().is_multiple_of(16) {
            return Err(Error::Frame("ciphertext is not block aligned"));
        }
        let mut out = data.to_vec();
        self.crypt_blocks(&mut out, true);
        Ok(out)
    }

    fn crypt_blocks(&self, bytes: &mut [u8], decrypt: bool) {
        // Process eight blocks together to expose the cipher backend's instruction parallelism.
        for chunk in bytes.chunks_mut(128) {
            let count = chunk.len() / 16;
            let mut blocks = [GenericArray::default(); 8];
            for (block, source) in blocks.iter_mut().zip(chunk.chunks_exact(16)) {
                block.copy_from_slice(source);
            }
            if decrypt {
                self.0.decrypt_blocks(&mut blocks[..count]);
            } else {
                self.0.encrypt_blocks(&mut blocks[..count]);
            }
            for (target, block) in chunk.chunks_exact_mut(16).zip(blocks.iter()) {
                target.copy_from_slice(block);
            }
        }
    }

    pub fn encode(&self, text: &str) -> Result<String> {
        if text.len() > MAX_COMMAND_BYTES || text.as_bytes().contains(&0) {
            return Err(Error::Frame("invalid command length or embedded NUL"));
        }
        let encrypted = self.encrypt_bytes(text.as_bytes());
        let mut framed = format!("{}:0-", encrypted.len()).into_bytes();
        framed.extend_from_slice(&encrypted);
        Ok(STANDARD_NO_PAD.encode(framed).replace('/', ")"))
    }

    pub fn decode(&self, encoded: &str) -> Result<String> {
        if encoded.len() > (MAX_COMMAND_BYTES + 32) * 2 {
            return Err(Error::Frame("encoded command too large"));
        }
        let frame = STANDARD_NO_PAD
            .decode(encoded.trim_end_matches('=').replace(')', "/"))
            .map_err(|_| Error::Frame("invalid base64"))?;
        let separator = frame
            .iter()
            .position(|b| *b == b'-')
            .ok_or(Error::Frame("missing command header"))?;
        let header = std::str::from_utf8(&frame[..separator])
            .map_err(|_| Error::Frame("invalid command header"))?;
        let (length, compression) = header
            .split_once(':')
            .ok_or(Error::Frame("missing compression flag"))?;
        let length: usize = length
            .parse()
            .map_err(|_| Error::Frame("invalid ciphertext length"))?;
        if compression != "0" || length > MAX_COMMAND_BYTES || frame.len() - separator - 1 != length
        {
            return Err(Error::Frame("invalid command bounds or compression"));
        }
        let plain = Zeroizing::new(self.decrypt_bytes(&frame[separator + 1..])?);
        let end = plain.iter().position(|b| *b == 0).unwrap_or(plain.len());
        String::from_utf8(plain[..end].to_vec()).map_err(|_| Error::Frame("command is not UTF-8"))
    }
}

/// Rsync-derived challenge response: MD4 of a zero seed followed by both strings.
pub fn challenge_hash(first: &[u8], second: &[u8]) -> Zeroizing<String> {
    let mut h = Md4::new();
    h.update([0; 4]);
    h.update(first);
    h.update(second);
    Zeroizing::new(STANDARD_NO_PAD.encode(h.finalize()))
}

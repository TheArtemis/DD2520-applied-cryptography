use crate::set1::xor::xor_bytes;
use aes::aes_128_ecb_encrypt;

/// Fixed nonce of zero (for challenges / tests). Do not reuse in production.
pub const NONCE_ZERO: [u8; 8] = [0u8; 8];

/// CTR mode: encrypt(nonce || counter) gives keystream; XOR with data.
/// Counter is 64-bit little-endian. Same function for encrypt and decrypt.
fn ctr_keystream_xor(input: &[u8], key: &[u8; 16], nonce: &[u8; 8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len());
    let mut counter: u64 = 0;
    let mut pos = 0;
    while pos < input.len() {
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(nonce);
        block[8..16].copy_from_slice(&counter.to_le_bytes());
        let keystream = aes_128_ecb_encrypt(&block, key);
        let take = (input.len() - pos).min(16);
        let xored = xor_bytes(&input[pos..pos + take], &keystream[..take]);
        output.extend_from_slice(&xored);
        pos += take;
        counter += 1;
    }
    output
}

pub fn ctr_encrypt(plaintext: &[u8], key: &[u8; 16], nonce: &[u8; 8]) -> Vec<u8> {
    ctr_keystream_xor(plaintext, key, nonce)
}

pub fn ctr_decrypt(ciphertext: &[u8], key: &[u8; 16], nonce: &[u8; 8]) -> Vec<u8> {
    ctr_keystream_xor(ciphertext, key, nonce)
}


// Same-keystream attack: when multiple messages are XORed with the same stream (e.g. fixed-nonce CTR),
// recover the keystream (and thus plaintexts) using per-column frequency scoring.

/// English letter frequency score (rough). Space and letters get positive score; control chars negative.
pub fn score_byte_english(b: u8) -> i32 {
    match b {
        b' ' => 12,
        b'e' | b'E' => 10,
        b't' | b'T' => 9,
        b'a' | b'A' => 8,
        b'o' | b'O' => 8,
        b'i' | b'I' | b'n' | b'N' => 7,
        b's' | b'S' | b'h' | b'H' | b'r' | b'R' => 6,
        b'd' | b'D' | b'l' | b'L' => 5,
        b'c' | b'C' | b'u' | b'U' | b'm' | b'M' | b'w' | b'W' => 4,
        b'f' | b'F' | b'g' | b'G' | b'y' | b'Y' | b'p' | b'P' => 3,
        b'b' | b'B' | b'v' | b'V' | b'k' | b'K' => 2,
        b'j' | b'J' | b'x' | b'X' | b'q' | b'Q' | b'z' | b'Z' => 1,
        b'.' | b',' | b'\'' | b'?' | b'!' | b'-' | b'\n' => 2,
        32..=126 => 0, // printable
        _ => -10,
    }
}

/// For a column of ciphertext bytes (same position, multiple messages), try each keystream byte
/// 0..=255; return the one that decrypts the column to the highest score under `score`.
pub fn recover_keystream_byte(column: &[u8], score: fn(u8) -> i32) -> u8 {
    let mut best_byte = 0u8;
    let mut best_score = i32::MIN;
    for k in 0u8..=255 {
        let s: i32 = column.iter().map(|&c| score(c ^ k)).sum();
        if s > best_score {
            best_score = s;
            best_byte = k;
        }
    }
    best_byte
}

/// Recover keystream up to `max_len` by attacking each column. Uses `score_byte_english` by default.
pub fn recover_keystream(ciphertexts: &[Vec<u8>], max_len: usize) -> Vec<u8> {
    recover_keystream_with_scorer(ciphertexts, max_len, score_byte_english)
}

/// Recover keystream up to `max_len` using a custom byte scorer.
pub fn recover_keystream_with_scorer(
    ciphertexts: &[Vec<u8>],
    max_len: usize,
    score: fn(u8) -> i32,
) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(max_len);
    for j in 0..max_len {
        let column: Vec<u8> = ciphertexts
            .iter()
            .filter_map(|c| c.get(j).copied())
            .collect();
        if column.is_empty() {
            break;
        }
        keystream.push(recover_keystream_byte(&column, score));
    }
    keystream
}

/// Decrypt multiple ciphertexts using a single keystream (XOR each position).
pub fn decrypt_with_keystream(ciphertexts: &[Vec<u8>], keystream: &[u8]) -> Vec<Vec<u8>> {
    ciphertexts
        .iter()
        .map(|ct| {
            ct.iter()
                .zip(keystream.iter())
                .map(|(c, k)| c ^ k)
                .collect::<Vec<_>>()
        })
        .collect()
}

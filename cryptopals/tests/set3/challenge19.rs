use cryptopals::{
    set1::encoding::base64_decode,
    set3::ctr::{ctr_encrypt, NONCE_ZERO},
    set3::stream_attack::{decrypt_with_keystream, recover_keystream},
};
use rand::{rngs::StdRng, Rng, SeedableRng};

#[test]
fn test_ctr_fixed_nonce_attack() {
    let data = include_str!("data/challenge19.txt");
    let lines: Vec<&str> = data.lines().map(str::trim).filter(|s| !s.is_empty()).collect();
    assert_eq!(lines.len(), 40, "expected 40 lines");

    let plaintexts: Vec<Vec<u8>> = lines.iter().map(|s| base64_decode(s)).collect();
    let max_len = plaintexts.iter().map(|p| p.len()).max().unwrap();

    println!(
        "Loaded {} plaintexts (max length = {})",
        plaintexts.len(),
        max_len
    );
    for (i, pt) in plaintexts.iter().take(3).enumerate() {
        println!("Plaintext {}: {}", i, String::from_utf8_lossy(pt));
    }

    // Fixed nonce 0; random key (fixed seed for reproducible test)
    let mut rng = StdRng::seed_from_u64(19);
    let key: [u8; 16] = rng.gen();

    // Encrypt each line independently (successive encryptions, not one stream)
    let ciphertexts: Vec<Vec<u8>> = plaintexts
        .iter()
        .map(|pt| ctr_encrypt(pt, &key, &NONCE_ZERO))
        .collect();

    let ct_lengths: Vec<usize> = ciphertexts.iter().map(|c| c.len()).collect();
    println!("Ciphertext lengths: {:?}", ct_lengths);

    // Attack: recover keystream from ciphertexts only
    let keystream = recover_keystream(&ciphertexts, max_len);
    let preview_len = keystream.len().min(32);
    println!(
        "Recovered keystream (first {} bytes): {:02x?}",
        preview_len,
        &keystream[..preview_len]
    );

    let recovered = decrypt_with_keystream(&ciphertexts, &keystream);

    // Verify: recovered plaintexts match originals up to a few byte errors per line (frequency
    // attack can misguess in columns with few samples or tie on score).
    for (i, (orig, rec)) in plaintexts.iter().zip(recovered.iter()).enumerate() {
        assert_eq!(orig.len(), rec.len(), "line {} length mismatch", i);
        let errors = orig.iter().zip(rec.iter()).filter(|(a, b)| a != b).count();
        println!(
            "Line {}: {} byte errors; recovered: {}",
            i,
            errors,
            String::from_utf8_lossy(rec)
        );
        assert!(
            errors <= 5,
            "line {}: {} byte errors (orig {:?}, rec {:?})",
            i,
            errors,
            String::from_utf8_lossy(orig),
            String::from_utf8_lossy(rec)
        );
    }
}

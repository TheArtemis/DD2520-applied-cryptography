use crate::state::State;
use crate::sbox::{AES_SBOX, AES_INV_SBOX};
use crate::gf256::{gf256_mul, gf256_mul2, gf256_mul3};

pub struct AES128 {
    key: [u8; 16],
}

impl AES128 {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    } 

    // Since it's aes 128, there are 10 rounds of encryption/decryption
    pub fn cipher(&self, state: &mut State) {
        let key_schedule = self.key_expansion(self.key);
        
        self.add_round_key(state, &key_schedule[0]);
        
        // First 9 rounds
        for i in 1..10 {
            self.sub_bytes(state);
            self.shift_rows(state);
            self.mix_columns(state);
            self.add_round_key(state, &key_schedule[i]);
        }
        
        // Last round
        self.sub_bytes(state);
        self.shift_rows(state);
        self.add_round_key(state, &key_schedule[10]);
    }

    /// Inverse cipher (decryption). Decrypts the state in place.
    pub fn inv_cipher(&self, state: &mut State) {
        let key_schedule = self.key_expansion(self.key);

        self.add_round_key(state, &key_schedule[10]);

        // First 9 rounds
        for i in (1..10).rev() {
            self.inv_shift_rows(state);
            self.inv_sub_bytes(state);
            self.add_round_key(state, &key_schedule[i]);
            self.inv_mix_columns(state);
        }

        // Last round
        self.inv_shift_rows(state);
        self.inv_sub_bytes(state);
        self.add_round_key(state, &key_schedule[0]);
    }

    // XORs the state with a round-specific subkey derived from the main key via expansion, integrating key material per round
    fn add_round_key(&self, state: &mut State, round_key: &State) {
        *state ^= *round_key;
    }

    // Substitutes each byte using a non-linear S-box lookup table to introduce confusion, ensuring no byte maps to itself or its complement.
    fn sub_bytes(&self, state: &mut State) {
        for row in 0..4 {
            for col in 0..4 {
                state[(row, col)] = AES_SBOX[state[(row, col)] as usize];
            }
        }
    }

    // Substitutes each byte using the inverse S-box lookup table to reverse the confusion introduced by sub_bytes, ensuring each byte maps back to its original value
    fn inv_sub_bytes(&self, state: &mut State) {
        for row in 0..4 {
            for col in 0..4 {
                state[(row, col)] = AES_INV_SBOX[state[(row, col)] as usize];
            }
        }
    }

    // Cyclically shifts rows left (0, 1, 2, 3 positions for rows 1-4) to provide diffusion across columns, preventing independent column encryption
    fn shift_rows(&self, state: &mut State) {
        // row 0: no shift
        // row 1: left shift by 1
        let temp = state[(1, 0)];
        state[(1, 0)] = state[(1, 1)];
        state[(1, 1)] = state[(1, 2)];
        state[(1, 2)] = state[(1, 3)];
        state[(1, 3)] = temp;
        
        // row 2: left shift by 2
        let temp0 = state[(2, 0)];
        let temp1 = state[(2, 1)];
        state[(2, 0)] = state[(2, 2)];
        state[(2, 1)] = state[(2, 3)];
        state[(2, 2)] = temp0;
        state[(2, 3)] = temp1;
        
        // row 3: left shift by 3 (or right shift by 1)
        let temp = state[(3, 3)];
        state[(3, 3)] = state[(3, 2)];
        state[(3, 2)] = state[(3, 1)];
        state[(3, 1)] = state[(3, 0)];
        state[(3, 0)] = temp;
    }

    // performs the inverse shift rows operation on all rows of the state, reversing the diffusion introduced by shift rows to ensure consistent decryption
    fn inv_shift_rows(&self, state: &mut State) {
        // row 0: no shift
        // row 1: right shift by 1 (inverse of left by 1)
        let temp = state[(1, 3)];
        state[(1, 3)] = state[(1, 2)];
        state[(1, 2)] = state[(1, 1)];
        state[(1, 1)] = state[(1, 0)];
        state[(1, 0)] = temp;

        // row 2: right shift by 2 (same as left by 2, symmetric)
        let temp0 = state[(2, 0)];
        let temp1 = state[(2, 1)];
        state[(2, 0)] = state[(2, 2)];
        state[(2, 1)] = state[(2, 3)];
        state[(2, 2)] = temp0;
        state[(2, 3)] = temp1;

        // row 3: right shift by 3 (inverse of left by 3 = left by 1)
        let temp = state[(3, 0)];
        state[(3, 0)] = state[(3, 1)];
        state[(3, 1)] = state[(3, 2)];
        state[(3, 2)] = state[(3, 3)];
        state[(3, 3)] = temp;
    }

    // performs the MixColumns operation on all columns of the state, mixing the bytes to provide diffusion across columns
    fn mix_columns(&self, state: &mut State) {
        for col in 0..4 {
            let mut column = state.get_col(col);
            self.mix_column(&mut column);
            state.set_col(col, column);
        }
    }

    // performs the MixColumns operation on a single column of the state, mixing the bytes to provide diffusion across columns
    fn mix_column(&self, vec: &mut [u8]) {  
        
        // matrix representation:
        /* 
        | 02 03 01 01 |   
        | 01 02 03 01 |   
        | 01 01 02 03 |   
        | 03 01 01 02 |        
        */

        let [a, b, c, d] = [vec[0], vec[1], vec[2], vec[3]];        

        vec[0] = gf256_mul2(a) ^ gf256_mul3(b) ^ c ^ d;
        vec[1] = a ^ gf256_mul2(b) ^ gf256_mul3(c) ^ d;
        vec[2] = a ^ b ^ gf256_mul2(c) ^ gf256_mul3(d);
        vec[3] = gf256_mul3(a) ^ b ^ c ^ gf256_mul2(d);
    }

    fn inv_mix_columns(&self, state: &mut State) {
        for col in 0..4 {
            let mut column = state.get_col(col);
            self.inv_mix_column(&mut column);
            state.set_col(col, column);
        }
    }

    // performs the inverse MixColumns operation on a single column of the state, reversing the diffusion introduced by MixColumns to ensure consistent decryption
    fn inv_mix_column(&self, vec: &mut [u8]) {
        // Inverse MixColumns matrix in GF(2^8):
        // | 0e 0b 0d 09 |
        // | 09 0e 0b 0d |
        // | 0d 09 0e 0b |
        // | 0b 0d 09 0e |
        let [a, b, c, d] = [vec[0], vec[1], vec[2], vec[3]];

        vec[0] = gf256_mul(a, 0x0e) ^ gf256_mul(b, 0x0b) ^ gf256_mul(c, 0x0d) ^ gf256_mul(d, 0x09);
        vec[1] = gf256_mul(a, 0x09) ^ gf256_mul(b, 0x0e) ^ gf256_mul(c, 0x0b) ^ gf256_mul(d, 0x0d);
        vec[2] = gf256_mul(a, 0x0d) ^ gf256_mul(b, 0x09) ^ gf256_mul(c, 0x0e) ^ gf256_mul(d, 0x0b);
        vec[3] = gf256_mul(a, 0x0b) ^ gf256_mul(b, 0x0d) ^ gf256_mul(c, 0x09) ^ gf256_mul(d, 0x0e);
    }

    // generates multiple round keys from the initial cipher key for use in each encryption/decryption round. It  ensures each round has a unique subkey, (diffusion) and preventing simple key reuse attacks
    fn key_expansion(&self, key: [u8; 16]) -> Vec<State> {
        // split key into 4 words (w[0..3])
        let mut words: [[u8; 4]; 44] = [[0; 4]; 44];
        
        // initialize first 4 words from key
        for i in 0..4 {
            words[i] = [
                key[i * 4],
                key[i * 4 + 1],
                key[i * 4 + 2],
                key[i * 4 + 3],
            ];
        }
        
        // generate remaining 40 words (w[4..43])
        for i in 4..44 {
            let mut temp = words[i - 1];
            
            if i % 4 == 0 {
                temp = self.rot_word(temp);
                temp = self.sub_word(temp);
                let rcon = self.rcon(i / 4);
                for j in 0..4 {
                    temp[j] ^= rcon[j];
                }
            }
            
            // xor with word 4 positions back
            for j in 0..4 {
                words[i][j] = words[i - 4][j] ^ temp[j];
            }
        }
        
        // group every 4 words into a State (11 round keys total)
        let mut keys = Vec::new();
        for i in 0..11 {
            let mut state_data = [0u8; 16];
            for j in 0..4 {
                let word = words[i * 4 + j];
                state_data[j * 4] = word[0];
                state_data[j * 4 + 1] = word[1];
                state_data[j * 4 + 2] = word[2];
                state_data[j * 4 + 3] = word[3];
            }
            keys.push(State::new(state_data));
        }
        
        keys
    }

    // rotates the bytes in a word left by one position, effectively shifting the bytes circularly to the left
    fn rot_word(&self, word: [u8; 4]) -> [u8; 4] {
        let [a, b, c, d] = word;
        [b, c, d, a]
    }

    // substitutes each byte in the word using the AES S-box to introduce confusion, ensuring no byte maps to itself or its complement
    fn sub_word(&self, word: [u8; 4]) -> [u8; 4] {
        let [a, b, c, d] = word;
        [AES_SBOX[a as usize], AES_SBOX[b as usize], AES_SBOX[c as usize], AES_SBOX[d as usize]]
    }

    // generates a round constant for the given round number, used to mix key material into the round key
    fn rcon(&self, round: usize) -> [u8; 4] {        
        const RCON_TABLE: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
        
        if round == 0 {
            [0x00, 0x00, 0x00, 0x00]
        } else if round <= 10 {
            [RCON_TABLE[round - 1], 0x00, 0x00, 0x00]
        } else {
            // for round > 10, compute using xtime (2^(round-1))
            let mut rcon_val = 0x01u8;
            for _ in 1..round {
                rcon_val = crate::gf256::xtime(rcon_val);
            }
            [rcon_val, 0x00, 0x00, 0x00]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let key: [u8; 16] = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c];
        let plaintext: [u8; 16] = [0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34];

        let aes = AES128::new(key);
        let mut state = State::new(plaintext);

        aes.cipher(&mut state);
        let _ciphertext = *state.as_bytes();

        aes.inv_cipher(&mut state);
        let decrypted = *state.as_bytes();

        assert_eq!(plaintext, decrypted, "decrypt(cipher(plaintext)) should equal plaintext");
    }
}

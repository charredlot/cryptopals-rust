use std::cmp;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str;

use charfreq::EnglishCharScore;
use hex::{bytes_to_hex, hex_to_bytes};

pub fn fixed_xor(buf: &[u8], key: &[u8]) -> Vec<u8> {
    let l = cmp::min(buf.len(), key.len());
    let mut vec: Vec<u8> = Vec::with_capacity(l);
    for (&b, &k) in buf.iter().zip(key) {
        vec.push(b ^ k);
    }
    vec
}

pub fn slice_xor_inplace(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d = *d ^ *s;
    }
}

pub fn slice_xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut res = Vec::new();
    for (l, r) in left.iter().zip(right) {
        res.push(*l ^ *r);
    }
    res
}

/// Returns key, score
pub fn guess_byte_xor_cipher(buf: &[u8]) -> (u8, u64) {
    let mut score = EnglishCharScore::new();
    for i in 0..256 {
        let key = i as u8;

        for &b in buf {
            score.add_byte(b ^ key);
        }
        score.update_best(key);
    }
    let (low_score, low_key) = score.get_best();
    (low_key.unwrap(), low_score)
}

/// Returns best_decrypted_line, best_line_number
fn detect_byte_xor_cipher(filename: &str) -> (Vec<u8>, usize) {
    let f = match File::open(filename) {
        Ok(file) => file,
        Err(e) => { panic!("{}", e); }
    };

    let mut best_score: u64 = u64::max_value();
    let mut best_lineno: usize = 0;
    let mut best_result: Vec<u8> = Vec::new();

    let buffered = BufReader::new(&f);
    for (i, line) in buffered.lines().enumerate() {
        let l = match line {
            Ok(line_str) => line_str,
            Err(e) => { panic!("{}", e); }
        };

        let line_bytes = hex_to_bytes(&l);
        let (key, score) = guess_byte_xor_cipher(&line_bytes);
        if score >= best_score {
            // XXX: same score?
            continue;
        }

        let decrypted_bytes = repeating_key_xor(&line_bytes, &[key; 1]);
        match str::from_utf8(&decrypted_bytes) {
            Ok(decrypted) => {
                println!("  line {} {}: {}", i, score, decrypted);
            },
            // some strings won't be valid utf8
            Err(_) => continue,
        };

        best_score = score;
        best_lineno = i;
        best_result = decrypted_bytes;
    }
    (best_result, best_lineno)
}

pub fn repeating_key_xor(s: &[u8], key: &[u8]) -> Vec<u8> {
    let mut vec: Vec<u8> = Vec::with_capacity(s.len());
    for (&b0, &b1) in s.iter().zip(key.iter().cycle()) {
        vec.push(b0 ^ b1);
    }
    vec
}

fn fixed_xor_test() {
    let buf = hex_to_bytes("1c0111001f010100061a024b53535009181c");
    let key = hex_to_bytes("686974207468652062756c6c277320657965");
    let answer = "746865206b696420646f6e277420706c6179";

    let result = fixed_xor(buf.as_slice(), key.as_slice());

    let s = bytes_to_hex(result.as_slice());
    if s == answer {
        println!("Finished fixed_xor_test");
    } else {
        println!("ERROR in fixed_xor_test:");
        println!("  expected {}", answer);
        println!("  got      {}", s);
    }
}

fn byte_xor_cipher_test(ciphertext: &str, plaintext: &str) {
    let cipher_bytes = hex_to_bytes(ciphertext);
    let (key, _) = guess_byte_xor_cipher(&cipher_bytes);

    let decrypted_bytes = repeating_key_xor(&cipher_bytes, &[key; 1]);
    // this might panic?
    let decrypted = str::from_utf8(&decrypted_bytes).unwrap();
    if decrypted == plaintext {
        println!("Finished byte_xor_cipher_test for {}", ciphertext);
    } else {
        println!("ERROR in byte_xor_cipher_test:");
        println!("  expected {}", plaintext);
        println!("  got      {}", decrypted);
    }
}

fn detect_byte_xor_cipher_test() {
    let expected_result: &str = "Now that the party is jumping\n";
    let expected_lineno: usize = 170;
    let (best_result_vec, best_lineno) = detect_byte_xor_cipher("data/1.4.txt");

    let best_result = str::from_utf8(&best_result_vec).unwrap();
    if best_result == expected_result && best_lineno == expected_lineno {
        println!("Finished detect_byte_xor_cipher_test");
    } else {
        println!("ERROR in detect_byte_xor_cipher_test:");
        println!("  expected line {}: {}", expected_lineno, expected_result);
        println!("  got      line {}: {}", best_lineno, best_result);
    }
}

fn repeating_key_xor_test() {
    let s = "Burning 'em, if you ain't quick and nimble\n\
             I go crazy when I hear a cymbal";
    let key = "ICE";
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272\
                    a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";


    let bytes = repeating_key_xor(s.as_bytes(), key.as_bytes());
    let result = bytes_to_hex(bytes.as_slice());

    if result == expected {
        println!("Finished repeating_key_xor_test");
    } else {
        println!("ERROR repeating_key_xor_test:");
        println!("  expected {}", expected);
        println!("  got      {}", result);
    }
}

pub fn xor_test() {
    fixed_xor_test();
    byte_xor_cipher_test("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
                         "Cooking MC's like a pound of bacon");
    detect_byte_xor_cipher_test();
    repeating_key_xor_test();
}

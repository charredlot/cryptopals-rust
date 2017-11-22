extern crate gmp;

use self::gmp::mpz::Mpz;
use dsa::{new_keypair, PublicKey, Params};
use hex::bytes_to_hex;
use sha1;

fn sign_test() {
    let msg = "beep boop".as_bytes();
    let (pub_key, priv_key) = new_keypair();
    let signature = priv_key.sha1_sign(&msg);
    assert!(pub_key.sha1_verify(&msg, &signature));
}

fn nonce_to_key_test() {
    let msg =
        concat!("For those that envy a MC",
                " it can be hazardous to your health\n",
                "So be friendly, a matter of life and death,",
                " just like a etch-a-sketch\n");
    let y = Mpz::from_str_radix(
            concat!("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4",
                    "abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004",
                    "e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed",
                    "1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b",
                    "bb283e6633451e535c45513b2d33c99ea17"), 16).unwrap();
    let pub_key = PublicKey{
        y: y,
        params: Params::default(),
    };
}

pub fn dsa_test() {
    sign_test();
    nonce_to_key_test();
}

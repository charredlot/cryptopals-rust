extern crate gmp;

use self::gmp::mpz::Mpz;
use dsa::{new_keypair, PublicKey, Params, Signature};
use hex::bytes_to_hex;
use sha1;
use util::mpz_bytes;

fn sign_test() {
    let msg = "beep boop".as_bytes();
    let (pub_key, priv_key) = new_keypair();
    let signature = priv_key.sha1_sign(&msg);
    assert!(pub_key.sha1_verify(&msg, &signature));
}

fn nonce_to_key_test0() {
    let msg = "beep boop".as_bytes();
    let (pub_key, priv_key) = new_keypair();
    let signature = priv_key.sha1_sign(&msg);

    let k = &signature.k;
    let priv_key_guess = signature.sha1_k_to_key(&pub_key.params, msg, k);
    assert_eq!(priv_key, priv_key_guess,
               "sha1_k_to_key failed with k {:?}", k);
}

fn nonce_to_key_test1() {
    let msg =
        concat!("For those that envy a MC",
                " it can be hazardous to your health\n",
                "So be friendly, a matter of life and death,",
                " just like a etch-a-sketch\n").as_bytes();
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
    let r = Mpz::from_str_radix(
               "548099063082341131477253921760299949438196259240",
               10).unwrap();
    let s = Mpz::from_str_radix(
               "857042759984254168557880549501802188789837994940",
               10).unwrap();

    for i in 0..0x10000 {
        let signature = Signature{
            r: r.clone(),
            s: s.clone(),
            k: Mpz::from(i),
        };
        let guess =
            signature.sha1_k_to_key(&pub_key.params, msg, &signature.k);

        let guess_y = (&pub_key.params.g).powm(&guess.x, &pub_key.params.p);
        if guess_y == pub_key.y {
            println!("Found candidate DSA private key {:?} with k {:?}",
                     guess, signature.k);

            // TODO: can this be false?
            let guess_signature = guess.sha1_sign_with_k(msg, &signature.k);
            assert_eq!(guess_signature, signature);
            let hash_y = sha1::digest(
                            bytes_to_hex(
                                &mpz_bytes(&guess.x)).as_bytes());
            assert_eq!("0954edd5e0afe5542a4adf012611a91912a3ec16",
                       bytes_to_hex(&hash_y));
            return;
        }
    }
    panic!("didn't find private key from k");
}

pub fn dsa_test() {
    println!("Starting DSA tests");
    sign_test();
    nonce_to_key_test0();
    nonce_to_key_test1();
    println!("Finished DSA tests");
}

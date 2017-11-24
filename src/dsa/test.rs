extern crate gmp;

use std::fs::File;
use std::io::BufReader;
use std::io::prelude::*;

use self::gmp::mpz::Mpz;
use dsa::{new_keypair, PublicKey, PrivateKey, Params, Signature};
use hex::{bytes_to_hex, hex_to_bytes};
use sha1;
use util::{mpz_bytes, bytes_to_mpz};

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

fn repeated_nonce_test() {
    let y_str = concat!("2d026f4bf30195ede3a088da85e398ef869611d0f68f07",
                        "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8",
                        "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519",
                        "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430",
                        "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3",
                        "2971c3de5084cce04a2e147821");
    let y = Mpz::from_str_radix(y_str, 16).unwrap();

    let f = File::open("data/6.44.txt").unwrap();
    let buffered = BufReader::new(&f);

    #[derive(Debug)]
    enum Parse {
        Msg,
        S,
        R,
        M,
    }

    #[derive(Debug)]
    struct SignedMsg {
        msg: String,
        signature: Signature,
        hash: Mpz,
    }

    impl SignedMsg {
        fn new() -> SignedMsg {
            SignedMsg{
                msg: String::from(""),
                signature: Signature{
                    r: Mpz::zero(),
                    s: Mpz::zero(),
                    k: Mpz::zero(),
                },
                hash: Mpz::zero(),
            }
        }
    }

    fn strip_prefix(prefix: &'static str, mut s: String) -> String {
        assert!(s.starts_with(prefix));
        s.drain(..prefix.len());
        s
    }

    let mut curr = SignedMsg::new();
    let mut msgs: Vec<SignedMsg> = Vec::new();
    let mut state = Parse::Msg;
    for rline in buffered.lines() {
        let line = rline.unwrap();
        match state {
            Parse::Msg => {
                curr.msg = strip_prefix("msg: ", line);
                state = Parse::S;
            },
            Parse::S => {
                let res = strip_prefix("s: ", line);
                curr.signature.s = Mpz::from_str_radix(&res, 10).unwrap();
                state = Parse::R;
            },
            Parse::R => {
                let res = strip_prefix("r: ", line);
                curr.signature.r = Mpz::from_str_radix(&res, 10).unwrap();
                state = Parse::M;
            },
            Parse::M => {
                let res = strip_prefix("m: ", line);
                let hash = hex_to_bytes(&res);
                assert_eq!(hash, sha1::digest(curr.msg.as_bytes()));

                curr.hash = bytes_to_mpz(&hash);
                msgs.push(curr);
                // need to do this here so borrow checker knows
                curr = SignedMsg::new();
                state = Parse::Msg;
            },
        }
    }

    // s1 = k^-1 (H1 + xr) mod q
    //
    // x is the private key, so it's the same for all msgs
    // k is the same nonce for this test, q is the same param
    // r = (g^k mod p) mod q, so r is the same since it only depends on k
    // and the parameters g, p, q
    //
    // s1 * k - H1 = x * r mod q
    // s2 * k - H2 = x * r mod q
    // => (s1 - s2) * k = H1 - H2 mod q
    // => k = (H1 - H2) / (s1 - s2) mod q
    let params = Params::default();
    let q = &params.q;
    let priv_key = {
        let mut candidate_key: Option<PrivateKey> = None;
        'outer: for (i, msg) in msgs.iter().enumerate() {
            let guess_signature = msg.signature.clone();
            for (j, other_msg) in msgs.iter().enumerate() {
                if i == j {
                    // TODO: maybe some better way to do this?
                    continue;
                }

                // r is derived from the g, p, q params and k, so if it's the
                // same k it's the same r
                if msg.signature.r != other_msg.signature.r {
                    continue;
                }

                let k = {
                    let top = (&msg.hash - &other_msg.hash).modulus(&q);
                    let bottom = &msg.signature.s - &other_msg.signature.s;
                    (top * bottom.invert(&q).unwrap()).modulus(&q)
                };

                let guess_key =
                    guess_signature.sha1_k_to_key(&params,
                                                  msg.msg.as_bytes(),
                                                  &k);
                let guess_y = (&params.g).powm(&guess_key.x, &params.p);
                if guess_y == y {
                    candidate_key = Some(guess_key);
                    break 'outer;
                }
            }
        }
        match candidate_key {
            Some(key) => key,
            None => panic!("couldn't find repeated nonce (k)"),
        }
    };
    assert_eq!("ca8f6f7c66fa362d40760d135b763eb8527d3d52",
               bytes_to_hex(
                   &sha1::digest(
                       bytes_to_hex(&mpz_bytes(&priv_key.x)).as_bytes())));
}

fn bad_parameter_test() {
    // g = 0 => r = g ^ k mod q mod p = 0
    // also, signature will always validate since it's
    // v = g^u1 * y^u2 mod p mod q = 0 = r
    // also, we check for r == 0 so we can't sign with g == 0

    let (mut pub_key, _) = new_keypair();

    // set g = (p + 1) mod p = 1 mod p
    pub_key.params = {
        let mut params = Params::default();
        params.g = &params.p + &Mpz::one();
        params
    };

    // verify is:
    // r === (g^u1 * g^u2 mod p) mod q
    // g = 1 means we can ignore the g^u1 term
    // r = y^(r / s) mod p mod q
    //
    // if we set r = y^z
    // y^z = y^(y^z / s)
    // z = y^z / s
    // s = y^z * z^-1
    let z = Mpz::from_str_radix("97", 10).unwrap();
    let yz = pub_key.y.powm(&z, &pub_key.params.p)
                      .modulus(&pub_key.params.q);
    let signature = Signature{
        r: yz.clone(),
        s: (yz * z.invert(&pub_key.params.q).unwrap())
            .modulus(&pub_key.params.q),
        k: Mpz::zero(),
    };
    assert!(pub_key.sha1_verify("Hello, world".as_bytes(), &signature));
    assert!(pub_key.sha1_verify("Goodbye, world".as_bytes(), &signature));
}

pub fn dsa_test() {
    println!("Starting DSA tests");
    sign_test();
    nonce_to_key_test0();
    nonce_to_key_test1();
    repeated_nonce_test();
    bad_parameter_test();
    println!("Finished DSA tests");
}

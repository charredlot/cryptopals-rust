pub mod test;

extern crate gmp;

use self::gmp::mpz::Mpz;
use sha1;
use util::{randomish_mpz_lt, bytes_to_mpz};

pub const PARAM_P: &'static str =
    concat!("800000000000000089e1855218a0e7dac38136ffafa72eda7",
            "859f2171e25e65eac698c1702578b07dc2a1076da241c76c6",
            "2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe",
            "ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2",
            "b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87",
            "1a584471bb1");
pub const PARAM_Q: &'static str = "f4f47f05794b256174bba6e9b396a7707e563c5b";
pub const PARAM_G: &'static str =
    concat!("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119",
            "458fef538b8fa4046c8db53039db620c094c9fa077ef389b5",
            "322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047",
            "0f5b64c36b625a097f1651fe775323556fe00b3608c887892",
            "878480e99041be601a62166ca6894bdd41a7054ec89f756ba",
            "9fc95302291");

#[derive(Debug, Clone)]
pub struct Params {
    pub q: Mpz,
    pub g: Mpz,
    pub p: Mpz,
}

#[derive(Debug)]
pub struct PublicKey {
    // pub for debugging
    pub y: Mpz,
    pub params: Params,
}

#[derive(Debug)]
pub struct PrivateKey {
    // pub for debugging
    pub x: Mpz,
    pub y: Mpz,
    pub params: Params,
}

#[derive(Debug)]
pub struct Signature {
    pub r: Mpz,
    pub s: Mpz,
}

impl Params {
    pub fn default() -> Params {
        Params{
            q: Mpz::from_str_radix(&PARAM_Q, 16).unwrap(),
            g: Mpz::from_str_radix(&PARAM_G, 16).unwrap(),
            p: Mpz::from_str_radix(&PARAM_P, 16).unwrap(),
        }
    }
}

impl PrivateKey {
    pub fn sha1_sign(&self, msg: &[u8]) -> Signature {
        let q = &self.params.q;
        let g = &self.params.g;
        let p = &self.params.p;
        let zero = Mpz::zero();

        let k = loop {
            let candidate = randomish_mpz_lt(&q);
            if candidate > Mpz::one() {
                break candidate;
            }
        };

        let r = (g.powm(&k, p)).modulus(q);
        if r == zero {
            // try again, r can't be zero
            return self.sha1_sign(msg);
        }

        let s = {
            // q is prime, so this should never panic?
            let inv_k = k.invert(q).unwrap();
            let h = bytes_to_mpz(&sha1::digest(msg)) + (&self.x * &r);
            (inv_k * h.modulus(&q)).modulus(&q)
        };
        if s == zero {
            // s can't be zero
            return self.sha1_sign(msg);
        }

        Signature{r: r, s: s}
    }
}

impl PublicKey {
    pub fn sha1_verify(&self, msg: &[u8], signature: &Signature) -> bool {
        let q = &self.params.q;
        let g = &self.params.g;
        let p = &self.params.p;
        let zero = Mpz::zero();

        let r = &signature.r;
        let s = &signature.s;

        if r == &zero || r >= q || s == &zero || s >= q {
            return false;
        }

        // q should be prime
        let w = s.invert(q).unwrap();
        let u1 = (&bytes_to_mpz(&sha1::digest(msg)) * &w).modulus(q);
        let u2 = (r * &w).modulus(q);
        let v = {
            (g.powm(&u1, p) * (&self.y).powm(&u2, p)).modulus(p).modulus(q)
        };

        v == signature.r
    }
}

pub fn new_keypair() -> (PublicKey, PrivateKey) {
    let params = Params::default();

    let x = randomish_mpz_lt(&params.q);
    let y = (&params.g).powm(&x, &params.p);

    (PublicKey{y: y.clone(), params: params.clone()},
     PrivateKey{x: x, y: y, params: params})
}

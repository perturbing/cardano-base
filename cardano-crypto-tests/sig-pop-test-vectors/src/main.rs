#![warn(missing_docs)]
#![doc = include_str!("../README.md")]
#![allow(non_snake_case)]

use blst::{blst_p1, blst_scalar, blst_sk_to_pk_in_g1};
use blst::min_sig::SecretKey as BlstSk;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::fs::File;
use std::io::prelude::*;



fn generate_sk_and_pk<R: RngCore>(mut rng: R) -> std::io::Result<()>  {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);

    let sk = BlstSk::key_gen(&ikm, &[])
        .expect("Error occurs when the length of ikm < 32. This will not happen here.");

    
    let pk = sk.sk_to_pk();

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let aug = b"Random value for test aug. ";
    let msg = b"blst is such a blast";

    let sig = sk.sign(msg, dst, aug);

    // Should we keep the verify signature here?
    let _verif = sig.verify(false, msg, dst, aug, &pk, false);

    // Proof of Possession
    const POP: &[u8] = &[80, 111, 80];
    let k1 = sk.sign(POP, &[], &[]);
    let k2 = unsafe {
        let sk_scalar = std::mem::transmute::<&BlstSk, &blst_scalar>(&sk);
        let mut out = blst_p1::default();
        blst_sk_to_pk_in_g1(&mut out, sk_scalar);
        out
    };
    let _pop = (k1, k2);

    // Verify PoP
    // let _ = pk.validate().unwrap();

    // Write values to file to create test vectors
    // I believe we need to save the following values:
    // - ikm
    // - sk
    // - pk
    // - sig
    // - k1
    // - k2
    // - What else?


    Ok(())

}


fn write_hex_to_file(file_name: &str, hex_strings: &[String]) -> std::io::Result<()> {
    let mut file = File::create(file_name)?;

    for string in hex_strings {
        file.write_all(string.as_ref())?;
        file.write_all(b"\n")?;
    }
    Ok(())
}

fn main() {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
    generate_sk_and_pk(&mut rng).expect("Failed to create large dst test vectors!");
}
